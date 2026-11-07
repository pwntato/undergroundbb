import { describe, expect, it, vi } from 'vitest'
import type { UnreadTotal } from '@/lib/api/notifications'
import { refreshWhenShown, startHeaderCounting } from './headerCounting'
import { marksSettled, onMarksSettled, trackMarkRead } from './markReadTracker'

const t = (unread: number): UnreadTotal => ({ unread, unreadMore: false })
const flush = async () => {
  for (let i = 0; i < 10; i++) await Promise.resolve()
}

function setup() {
  const applied: Array<UnreadTotal | null> = []
  let n = 0
  const fetchTotal = vi.fn().mockImplementation(() => Promise.resolve(t(++n)))
  let clock = 1_000_000
  const started = startHeaderCounting({
    now: () => clock,
    settled: marksSettled,
    fetchTotal,
    onMarksSettled,
    apply: (x) => applied.push(x),
  })
  return { started, applied, fetchTotal, advance: (ms: number) => (clock += ms) }
}

describe('startHeaderCounting', () => {
  it('counts again, forced, each time a mark-read finishes on any screen', async () => {
    const s = setup()
    await s.started.counter.refresh(false)
    expect(s.fetchTotal).toHaveBeenCalledTimes(1)
    // Within the 30 s gap, so only a forced refresh can have run.
    await trackMarkRead(Promise.resolve())
    await flush()
    expect(s.fetchTotal).toHaveBeenCalledTimes(2)
    expect(s.applied).toEqual([t(1), t(2)])
    s.started.stop()
  })

  it('after stop() nothing more is fetched or shown', async () => {
    const s = setup()
    s.started.stop()
    await trackMarkRead(Promise.resolve())
    await flush()
    expect(s.fetchTotal).not.toHaveBeenCalled()
    await s.started.counter.refresh(true)
    expect(s.applied).toEqual([])
  })

  it('stopping one counter leaves another one counting', async () => {
    const a = setup()
    a.started.stop()
    const b = setup()
    await trackMarkRead(Promise.resolve())
    await flush()
    expect(a.fetchTotal).not.toHaveBeenCalled()
    expect(b.fetchTotal).toHaveBeenCalledTimes(1)
    b.started.stop()
  })
})

describe('startHeaderCounting listener', () => {
  it('stop() calls the unsubscribe it was given, once (no leaked listener)', () => {
    const unsubscribe = vi.fn()
    const listen = vi.fn().mockReturnValue(unsubscribe)
    const started = startHeaderCounting({
      now: () => 0,
      settled: () => Promise.resolve(),
      fetchTotal: () => Promise.resolve(t(1)),
      onMarksSettled: listen,
      apply: () => undefined,
    })
    expect(listen).toHaveBeenCalledTimes(1)
    expect(unsubscribe).not.toHaveBeenCalled()
    started.stop()
    expect(unsubscribe).toHaveBeenCalledTimes(1)
  })
})

describe('refreshWhenShown', () => {
  it('asks for an unforced refresh only while the header shows', () => {
    const refresh = vi.fn().mockResolvedValue(undefined)
    const counter = { refresh, dispose: vi.fn() }
    refreshWhenShown(false, counter)
    expect(refresh).not.toHaveBeenCalled()
    refreshWhenShown(true, counter)
    expect(refresh).toHaveBeenCalledExactlyOnceWith(false)
  })

  it('does nothing before a counter exists', () => {
    expect(() => refreshWhenShown(true, null)).not.toThrow()
  })
})
