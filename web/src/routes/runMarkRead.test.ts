import { describe, expect, it } from 'vitest'
import { markFailedAfter, runMarkRead } from './runMarkRead'

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
