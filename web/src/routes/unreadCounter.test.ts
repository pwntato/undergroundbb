import { describe, expect, it, vi } from 'vitest'
import type { UnreadTotal } from '@/lib/api/notifications'
import { createUnreadCounter, UNREAD_MIN_GAP_MS } from './unreadCounter'

const t = (unread: number): UnreadTotal => ({ unread, unreadMore: false })

function deferred<T>() {
  let resolve!: (v: T) => void
  let reject!: (e: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

function setup(over: { settled?: () => Promise<void> } = {}) {
  let clock = 1_000_000
  const applied: Array<UnreadTotal | null> = []
  const fetches: Array<ReturnType<typeof deferred<UnreadTotal>>> = []
  const fetchTotal = vi.fn().mockImplementation(() => {
    const d = deferred<UnreadTotal>()
    fetches.push(d)
    return d.promise
  })
  const counter = createUnreadCounter({
    now: () => clock,
    settled: over.settled ?? (() => Promise.resolve()),
    fetchTotal,
    apply: (x) => applied.push(x),
  })
  return {
    counter,
    applied,
    fetches,
    fetchTotal,
    advance: (ms: number) => {
      clock += ms
    },
  }
}

const tick = () => new Promise((r) => setTimeout(r, 0))

describe('createUnreadCounter', () => {
  it('shows what the first refresh fetched', async () => {
    const s = setup()
    const p = s.counter.refresh(false)
    await tick()
    s.fetches[0]!.resolve(t(3))
    await p
    expect(s.applied).toEqual([t(3)])
  })

  it('skips an unforced refresh within 30 seconds of the last attempt, in flight or done', async () => {
    const s = setup()
    const first = s.counter.refresh(false)
    await tick()
    await s.counter.refresh(false) // first still in flight
    expect(s.fetchTotal).toHaveBeenCalledTimes(1)
    s.fetches[0]!.resolve(t(1))
    await first
    s.advance(UNREAD_MIN_GAP_MS - 1)
    await s.counter.refresh(false)
    expect(s.fetchTotal).toHaveBeenCalledTimes(1)
    s.advance(1)
    const later = s.counter.refresh(false)
    await tick()
    expect(s.fetchTotal).toHaveBeenCalledTimes(2)
    s.fetches[1]!.resolve(t(2))
    await later
  })

  it('a skipped refresh does not cancel the one in flight (navigating mid-count)', async () => {
    const s = setup()
    const first = s.counter.refresh(true)
    await tick()
    await s.counter.refresh(false) // skipped: the attempt just started
    s.fetches[0]!.resolve(t(0))
    await first
    expect(s.applied).toEqual([t(0)])
  })

  it('a forced refresh runs inside the window', async () => {
    const s = setup()
    const a = s.counter.refresh(false)
    await tick()
    s.fetches[0]!.resolve(t(5))
    await a
    const b = s.counter.refresh(true)
    await tick()
    expect(s.fetchTotal).toHaveBeenCalledTimes(2)
    s.fetches[1]!.resolve(t(0))
    await b
    expect(s.applied).toEqual([t(5), t(0)])
  })

  it('drops an older answer that lands after a newer one', async () => {
    const s = setup()
    const older = s.counter.refresh(false)
    await tick()
    const newer = s.counter.refresh(true)
    await tick()
    s.fetches[1]!.resolve(t(0))
    await newer
    s.fetches[0]!.resolve(t(30)) // sent before the mark, lands last
    await older
    expect(s.applied).toEqual([t(0)])
  })

  it('shows no badge when the count failed, and does not retry until the window passes', async () => {
    const s = setup()
    const p = s.counter.refresh(false)
    await tick()
    s.fetches[0]!.reject(new Error('x'))
    await p
    expect(s.applied).toEqual([null])
    await s.counter.refresh(false)
    expect(s.fetchTotal).toHaveBeenCalledTimes(1)
  })

  it('waits for a mark-read in flight before it fetches', async () => {
    const gate = deferred<void>()
    const s = setup({ settled: () => gate.promise })
    const p = s.counter.refresh(true)
    await tick()
    expect(s.fetchTotal).not.toHaveBeenCalled()
    gate.resolve()
    await tick()
    expect(s.fetchTotal).toHaveBeenCalledTimes(1)
    s.fetches[0]!.resolve(t(0))
    await p
  })

  it('shows nothing after dispose, and starts nothing', async () => {
    const s = setup()
    const p = s.counter.refresh(false)
    await tick()
    s.counter.dispose()
    s.fetches[0]!.resolve(t(9))
    await p
    await s.counter.refresh(true)
    expect(s.applied).toEqual([])
    expect(s.fetchTotal).toHaveBeenCalledTimes(1)
  })
})
