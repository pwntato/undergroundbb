import { describe, expect, it, vi } from 'vitest'
import { marksSettled, onMarksSettled } from './markReadTracker'
import { markFailedAfter, runMarkRead, runTrackedMarkRead } from './runMarkRead'

const idsOf = (n: number) => Array.from({ length: n }, (_, i) => `id${String(i)}`)

describe('runMarkRead', () => {
  it('sends nothing for no ids', async () => {
    const calls: (readonly string[])[] = []
    const r = await runMarkRead([], (b) => {
      calls.push(b)
      return Promise.resolve()
    })
    expect(calls).toEqual([])
    expect(r).toEqual({ marked: [], failed: false })
  })

  it('splits 60 ids into batches of 25, 25 and 10 and reports all marked', async () => {
    const sizes: number[] = []
    const r = await runMarkRead(idsOf(60), (b) => {
      sizes.push(b.length)
      return Promise.resolve()
    })
    expect(sizes).toEqual([25, 25, 10])
    expect(r.marked).toEqual(idsOf(60))
    expect(r.failed).toBe(false)
  })

  it('stops at the first failed batch and reports only what was confirmed', async () => {
    let call = 0
    const r = await runMarkRead(idsOf(60), () => {
      call++
      return call === 2 ? Promise.reject(new Error('boom')) : Promise.resolve()
    })
    expect(call).toBe(2)
    expect(r.marked).toEqual(idsOf(25))
    expect(r.failed).toBe(true)
  })
})

describe('markFailedAfter', () => {
  it('lets a button-started mark replace the alert with its own result', () => {
    expect(markFailedAfter(true, false, true)).toBe(false)
    expect(markFailedAfter(false, true, true)).toBe(true)
    expect(markFailedAfter(true, true, true)).toBe(true)
  })

  it('never lets a row opened in the list hide an earlier failure', () => {
    expect(markFailedAfter(true, false, false)).toBe(true)
    expect(markFailedAfter(false, true, false)).toBe(true)
    expect(markFailedAfter(false, false, false)).toBe(false)
  })
})

describe('runTrackedMarkRead', () => {
  it('is in flight for the tracker while it runs and tells listeners when it finishes', async () => {
    let release!: () => void
    const gate = new Promise<void>((r) => {
      release = r
    })
    const mark = vi.fn().mockImplementation(() => gate)
    const done = vi.fn()
    const off = onMarksSettled(done)
    const run = runTrackedMarkRead(['a', 'b'], mark)
    let settled = false
    void marksSettled().then(() => {
      settled = true
    })
    await Promise.resolve()
    expect(mark).toHaveBeenCalledWith(['a', 'b'])
    expect(settled).toBe(false)
    expect(done).not.toHaveBeenCalled()
    release()
    expect(await run).toEqual({ marked: ['a', 'b'], failed: false })
    await Promise.resolve()
    expect(settled).toBe(true)
    expect(done).toHaveBeenCalledTimes(1)
    off()
  })

  it('still releases the tracker when a request fails', async () => {
    const done = vi.fn()
    const off = onMarksSettled(done)
    const result = await runTrackedMarkRead(['a'], () => Promise.reject(new Error('x')))
    expect(result).toEqual({ marked: [], failed: true })
    expect(done).toHaveBeenCalledTimes(1)
    off()
  })
})
