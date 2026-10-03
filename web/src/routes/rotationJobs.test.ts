import { beforeEach, describe, expect, it, vi } from 'vitest'
import { catchUpRotation, createRotationGuard, removeAndRotate } from './rotationJobs'
import { rotationNeededAfter, runRemoveMember, type RemoveResult } from './runRemoveMember'
import { runRotation, type RotationDeps, type RotationOutcome } from './runRotation'
import type { RemoveDeps } from './runRemoveMember'

vi.mock('./runRemoveMember', async (orig) => ({
  ...(await orig<typeof import('./runRemoveMember')>()),
  runRemoveMember: vi.fn(),
}))
vi.mock('./runRotation', async (orig) => ({
  ...(await orig<typeof import('./runRotation')>()),
  runRotation: vi.fn(),
}))

const remove = vi.mocked(runRemoveMember)
const rotate = vi.mocked(runRotation)

const GROUP = 'g1'
const SUBJECT = 'u-subject'
const removeDeps = {} as RemoveDeps
const rotationDeps = {} as RotationDeps
const DONE: RotationOutcome = { status: 'completed', rewrapped: 2 }

const deferred = <T>() => {
  let resolve!: (v: T) => void
  const promise = new Promise<T>((r) => {
    resolve = r
  })
  return { promise, resolve }
}

beforeEach(() => {
  remove.mockReset()
  rotate.mockReset()
})

describe('createRotationGuard', () => {
  it('lets one holder in at a time and reports changes', () => {
    const seen: boolean[] = []
    const guard = createRotationGuard((h) => seen.push(h))
    const release = guard.tryAcquire()
    expect(release).not.toBeNull()
    expect(guard.held).toBe(true)
    expect(guard.tryAcquire()).toBeNull()
    release?.()
    expect(guard.held).toBe(false)
    expect(guard.tryAcquire()).not.toBeNull()
    expect(seen).toEqual([true, false, true])
  })

  it('ignores a repeated or stale release, which must not free a newer holder', () => {
    const guard = createRotationGuard()
    const first = guard.tryAcquire()
    first?.()
    const second = guard.tryAcquire()
    first?.() // stale
    expect(guard.held).toBe(true)
    second?.()
    second?.() // repeated
    expect(guard.held).toBe(false)
  })
})

describe('catchUpRotation', () => {
  it('runs and releases the guard', async () => {
    rotate.mockResolvedValue(DONE)
    const guard = createRotationGuard()
    expect(await catchUpRotation(guard, rotationDeps, GROUP)).toEqual({
      busy: false,
      outcome: DONE,
    })
    expect(rotate).toHaveBeenCalledWith(rotationDeps, GROUP)
    expect(guard.held).toBe(false)
  })

  it('does nothing while another job holds the guard', async () => {
    const guard = createRotationGuard()
    guard.tryAcquire()
    expect(await catchUpRotation(guard, rotationDeps, GROUP)).toEqual({ busy: true })
    expect(rotate).not.toHaveBeenCalled()
  })

  it('releases the guard when the job throws', async () => {
    rotate.mockRejectedValue(new Error('boom'))
    const guard = createRotationGuard()
    await expect(catchUpRotation(guard, rotationDeps, GROUP)).rejects.toThrow('boom')
    expect(guard.held).toBe(false)
  })
})

describe('removeAndRotate', () => {
  const go = (guard = createRotationGuard(), rotatingGroup = true) =>
    removeAndRotate(
      { guard, remove: removeDeps, rotation: rotationDeps },
      GROUP,
      SUBJECT,
      'member',
      rotatingGroup,
    )

  it('refuses, touching nothing, while another rotation job runs', async () => {
    const guard = createRotationGuard()
    guard.tryAcquire()
    expect(await go(guard)).toEqual({ busy: true })
    expect(remove).not.toHaveBeenCalled()
    expect(rotate).not.toHaveBeenCalled()
  })

  it('runs the rotation after a Rotating removal, excluding the removed user, holding the guard throughout', async () => {
    const guard = createRotationGuard()
    const heldDuring: boolean[] = []
    remove.mockImplementation(() => {
      heldDuring.push(guard.held)
      return Promise.resolve({ ok: true, rotating: true })
    })
    rotate.mockImplementation(() => {
      heldDuring.push(guard.held)
      return Promise.resolve(DONE)
    })
    const res = await go(guard)
    expect(res).toMatchObject({ busy: false, removal: { ok: true }, rotation: DONE })
    expect(rotate).toHaveBeenCalledWith(rotationDeps, GROUP, { exclude: new Set([SUBJECT]) })
    expect(heldDuring).toEqual([true, true])
    expect(guard.held).toBe(false)
  })

  it('does not run a rotation after an Open-group removal', async () => {
    remove.mockResolvedValue({ ok: true, rotating: false })
    const res = await go(createRotationGuard(), false)
    expect(res).toMatchObject({ busy: false, removal: { ok: true } })
    expect(res).not.toHaveProperty('rotation')
    expect(rotate).not.toHaveBeenCalled()
  })

  it('runs the rotation after an ambiguous removal in a Rotating group, excluding the subject', async () => {
    remove.mockResolvedValue({ ok: false, kind: 'ambiguous' })
    rotate.mockResolvedValue({ status: 'none' })
    await go()
    expect(rotate).toHaveBeenCalledWith(rotationDeps, GROUP, { exclude: new Set([SUBJECT]) })
  })

  it('does not run one after an ambiguous removal in an Open group', async () => {
    remove.mockResolvedValue({ ok: false, kind: 'ambiguous' })
    await go(createRotationGuard(), false)
    expect(rotate).not.toHaveBeenCalled()
  })

  it('finishes the running rotation, with nobody excluded, when a removal is refused for one', async () => {
    remove.mockResolvedValue({ ok: false, kind: 'rotationInProgress' })
    rotate.mockResolvedValue(DONE)
    await go()
    expect(rotate).toHaveBeenCalledWith(rotationDeps, GROUP, { exclude: new Set() })
  })

  it('runs nothing when the removal changed nothing', async () => {
    for (const kind of ['stale', 'forbidden', 'notFound', 'coldKeys', 'authRequired'] as const) {
      remove.mockResolvedValue({ ok: false, kind })
      await go()
    }
    expect(rotate).not.toHaveBeenCalled()
  })

  it('releases the guard when the rotation throws', async () => {
    remove.mockResolvedValue({ ok: true, rotating: true })
    rotate.mockRejectedValue(new Error('boom'))
    const guard = createRotationGuard()
    await expect(go(guard)).rejects.toThrow('boom')
    expect(guard.held).toBe(false)
  })

  it('keeps a catch-up job out for the whole removal, which is what stops it resuming without the exclude set', async () => {
    const guard = createRotationGuard()
    const pending = deferred<RemoveResult>()
    remove.mockReturnValue(pending.promise)
    rotate.mockResolvedValue(DONE)

    const removal = go(guard)
    // The DELETE is in flight: a catch-up that started now would race it.
    expect(await catchUpRotation(guard, rotationDeps, GROUP)).toEqual({ busy: true })
    expect(rotate).not.toHaveBeenCalled()

    pending.resolve({ ok: true, rotating: true })
    await removal
    expect(rotate).toHaveBeenCalledTimes(1) // only the removal's own job, with its exclude set
    // And once it is over, a catch-up may run again.
    expect(await catchUpRotation(guard, rotationDeps, GROUP)).toMatchObject({ busy: false })
  })
})

describe('rotationNeededAfter', () => {
  const need = (outcome: RemoveResult, rotating: boolean) =>
    rotationNeededAfter(outcome, rotating, SUBJECT)

  it('needs a run after a Rotating removal and excludes the subject', () => {
    expect(need({ ok: true, rotating: true }, true)).toEqual({
      run: true,
      exclude: new Set([SUBJECT]),
    })
    expect(need({ ok: true, rotating: false }, false)).toEqual({ run: false })
  })

  it('needs a run for ambiguous only in a Rotating group, and for rotationInProgress always', () => {
    expect(need({ ok: false, kind: 'ambiguous' }, true)).toEqual({
      run: true,
      exclude: new Set([SUBJECT]),
    })
    expect(need({ ok: false, kind: 'ambiguous' }, false)).toEqual({ run: false })
    expect(need({ ok: false, kind: 'rotationInProgress' }, false)).toEqual({
      run: true,
      exclude: new Set(),
    })
  })
})
