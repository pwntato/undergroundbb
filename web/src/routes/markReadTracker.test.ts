import { describe, expect, it, vi } from 'vitest'
import { marksSettled, onMarksSettled, trackMarkRead } from './markReadTracker'

function deferred() {
  let resolve!: () => void
  let reject!: (e: unknown) => void
  const promise = new Promise<void>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

describe('markReadTracker', () => {
  it('is settled at once when nothing is in flight', async () => {
    await expect(marksSettled()).resolves.toBeUndefined()
  })

  it('holds marksSettled until every tracked run has finished', async () => {
    const a = deferred()
    const b = deferred()
    const ta = trackMarkRead(a.promise)
    const tb = trackMarkRead(b.promise)
    let settled = false
    void marksSettled().then(() => {
      settled = true
    })
    a.resolve()
    await ta
    await Promise.resolve()
    expect(settled).toBe(false)
    b.resolve()
    await tb
    await Promise.resolve()
    expect(settled).toBe(true)
  })

  it('settles when a run fails, and passes the failure on', async () => {
    const a = deferred()
    const t = trackMarkRead(a.promise)
    const settled = marksSettled()
    a.reject(new Error('boom'))
    await expect(t).rejects.toThrow('boom')
    await expect(settled).resolves.toBeUndefined()
  })

  it('tells subscribers once, when the last run finishes, and stops after unsubscribe', async () => {
    const cb = vi.fn()
    const off = onMarksSettled(cb)
    const a = deferred()
    const b = deferred()
    const ta = trackMarkRead(a.promise)
    const tb = trackMarkRead(b.promise)
    a.resolve()
    await ta
    expect(cb).not.toHaveBeenCalled()
    b.resolve()
    await tb
    expect(cb).toHaveBeenCalledTimes(1)
    off()
    const c = deferred()
    const tc = trackMarkRead(c.promise)
    c.resolve()
    await tc
    expect(cb).toHaveBeenCalledTimes(1)
  })
})
