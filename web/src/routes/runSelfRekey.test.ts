import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail } from '@/lib/api/groups'
import type { HandoffEntry } from '@/lib/api/keyRotation'
import type { RotationOutcome } from './runRotation'
import { runSelfRekey, type SelfRekeyDeps } from './runSelfRekey'

const rotation = vi.hoisted(() => ({ runRotation: vi.fn() }))
vi.mock('./runRotation', () => rotation)

const ME = 'a0000000-0000-4000-8000-000000000001'
const GROUP = 'g0000000-0000-4000-8000-000000000009'

const ROW: HandoffEntry = {
  groupId: GROUP,
  generation: 2,
  newWrappingPublicKey: 'new-key',
  wrappedGroupKey: { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' },
}

const MINTED = {
  generation: 3,
  link: { nonce: 'ln', ciphertext: 'lc' },
  removerWrappedKey: { ephemeralPub: 'we', nonce: 'wn', ciphertext: 'wc' },
  startSignature: 'sig',
}

function detail(over: Partial<GroupDetail> = {}): GroupDetail {
  return {
    role: 'admin',
    visibility: 'private',
    revocationMode: 'rotating',
    generation: 2,
    ...over,
  } as GroupDetail
}

const DONE: RotationOutcome = { status: 'completed', rewrapped: 2 }

function setup(group: GroupDetail | Error = detail()) {
  const calls = {
    mint: vi.fn(() => Promise.resolve(MINTED)),
    selfRekey: vi.fn((): Promise<void> => Promise.resolve()),
    deleteHandoff: vi.fn((): Promise<void> => Promise.resolve()),
  }
  const deps = {
    selfUserId: ME,
    getGroup: vi.fn(() =>
      group instanceof Error ? Promise.reject(group) : Promise.resolve(group),
    ),
    startSelfRekeyCrypto: calls.mint,
    selfRekey: calls.selfRekey,
    deleteHandoff: calls.deleteHandoff,
  } as unknown as SelfRekeyDeps
  return { deps, ...calls }
}

beforeEach(() => {
  rotation.runRotation.mockReset()
  rotation.runRotation.mockResolvedValue(DONE)
})

describe('runSelfRekey', () => {
  it('opens the row, starts the re-key with what was minted, then runs the job', async () => {
    const t = setup()
    const out = await runSelfRekey(t.deps, ROW)
    expect(out).toEqual({ status: 'rekeyed', rotation: DONE })
    expect(t.mint).toHaveBeenCalledWith({
      userId: ME,
      groupId: GROUP,
      handoffGeneration: 2,
      handoffWrappedKey: ROW.wrappedGroupKey,
    })
    expect(t.selfRekey).toHaveBeenCalledWith(GROUP, {
      generation: 3,
      link: MINTED.link,
      wrappedKey: MINTED.removerWrappedKey,
      startSignature: 'sig',
    })
    expect(rotation.runRotation).toHaveBeenCalledWith(t.deps, GROUP)
    expect(t.deleteHandoff).not.toHaveBeenCalled()
  })

  it('deletes the row only when the server says it is stale, and runs no job', async () => {
    const t = setup()
    t.selfRekey.mockRejectedValue(new ApiError(409, 'stale', 'handoff_stale'))
    expect(await runSelfRekey(t.deps, ROW)).toEqual({ status: 'stale' })
    expect(t.deleteHandoff).toHaveBeenCalledWith(GROUP)
    expect(rotation.runRotation).not.toHaveBeenCalled()
  })

  it('reports a failed delete of a stale row instead of claiming it is cleared', async () => {
    const t = setup()
    t.selfRekey.mockRejectedValue(new ApiError(409, 'stale', 'handoff_stale'))
    t.deleteHandoff.mockRejectedValue(new Error('offline'))
    const out = await runSelfRekey(t.deps, ROW)
    expect(out).toMatchObject({ status: 'incomplete' })
    expect(JSON.stringify(out)).toContain('offline')
  })

  it('carries on with the job when a rotation is already running', async () => {
    const t = setup()
    t.selfRekey.mockRejectedValue(new ApiError(409, 'busy', 'rotation_in_progress'))
    expect(await runSelfRekey(t.deps, ROW)).toEqual({ status: 'rekeyed', rotation: DONE })
    expect(t.deleteHandoff).not.toHaveBeenCalled()
  })

  it.each([
    ['a refusal it cannot interpret', new ApiError(409, 'x', 'key_epoch_stale')],
    ['a network failure', new Error('offline')],
  ])('keeps the row on %s', async (_name, err) => {
    const t = setup()
    t.selfRekey.mockRejectedValue(err)
    expect(await runSelfRekey(t.deps, ROW)).toMatchObject({ status: 'incomplete' })
    expect(t.deleteHandoff).not.toHaveBeenCalled()
    expect(rotation.runRotation).not.toHaveBeenCalled()
  })

  it('keeps the row, and sends nothing, when it will not open', async () => {
    const t = setup()
    t.mint.mockRejectedValue(new Error('crypto: bad tag'))
    const out = await runSelfRekey(t.deps, ROW)
    expect(out).toMatchObject({ status: 'incomplete' })
    expect(JSON.stringify(out)).toContain('bad tag')
    expect(t.selfRekey).not.toHaveBeenCalled()
    expect(t.deleteHandoff).not.toHaveBeenCalled()
  })

  it('resumes a running rotation without starting another', async () => {
    const t = setup(detail({ rotation: { generation: 3, startedAt: 't', startedBy: ME } }))
    expect(await runSelfRekey(t.deps, ROW)).toEqual({ status: 'rekeyed', rotation: DONE })
    expect(t.mint).not.toHaveBeenCalled()
    expect(t.selfRekey).not.toHaveBeenCalled()
  })

  it("deletes a row the caller's own entry has already moved past", async () => {
    const t = setup(detail({ generation: 5 }))
    expect(await runSelfRekey(t.deps, ROW)).toEqual({ status: 'stale' })
    expect(t.deleteHandoff).toHaveBeenCalledWith(GROUP)
    expect(t.mint).not.toHaveBeenCalled()
  })

  it.each([
    ['no longer an admin', detail({ role: 'member' })],
    ['gone from the group', new ApiError(404, 'not found')],
  ])('leaves the row alone when the caller is %s', async (_name, group) => {
    const t = setup(group)
    expect(await runSelfRekey(t.deps, ROW)).toEqual({ status: 'not-admin' })
    expect(t.deleteHandoff).not.toHaveBeenCalled()
    expect(t.mint).not.toHaveBeenCalled()
  })

  it('leaves an Open group to its self-wrap, keeping the row', async () => {
    const t = setup(detail({ revocationMode: 'open' }))
    expect(await runSelfRekey(t.deps, ROW)).toEqual({ status: 'open' })
    expect(t.deleteHandoff).not.toHaveBeenCalled()
    expect(t.mint).not.toHaveBeenCalled()
  })

  it('treats an unreadable group as incomplete, never as stale', async () => {
    const t = setup(new Error('offline'))
    expect(await runSelfRekey(t.deps, ROW)).toMatchObject({ status: 'incomplete' })
    expect(t.deleteHandoff).not.toHaveBeenCalled()
  })
})
