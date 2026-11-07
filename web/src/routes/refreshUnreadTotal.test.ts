import { describe, expect, it, vi } from 'vitest'
import { refreshUnreadTotal, UNREAD_MIN_GAP_MS } from './refreshUnreadTotal'

const total = { unread: 3, unreadMore: false }

function deps(over: Partial<Parameters<typeof refreshUnreadTotal>[0]> = {}) {
  return {
    force: false,
    lastAt: undefined,
    now: () => 1_000_000,
    settled: () => Promise.resolve(),
    fetchTotal: vi.fn().mockResolvedValue(total),
    ...over,
  }
}

describe('refreshUnreadTotal', () => {
  it('fetches when it never has', async () => {
    const d = deps()
    expect(await refreshUnreadTotal(d)).toEqual({ status: 'ok', value: total })
    expect(d.fetchTotal).toHaveBeenCalledTimes(1)
  })

  it('skips a recent count, but not an old one', async () => {
    const recent = deps({ lastAt: 1_000_000 - UNREAD_MIN_GAP_MS + 1 })
    expect(await refreshUnreadTotal(recent)).toEqual({ status: 'skipped' })
    expect(recent.fetchTotal).not.toHaveBeenCalled()
    const old = deps({ lastAt: 1_000_000 - UNREAD_MIN_GAP_MS })
    expect((await refreshUnreadTotal(old)).status).toBe('ok')
  })

  it('force fetches even when the count is recent', async () => {
    const d = deps({ force: true, lastAt: 1_000_000 })
    expect((await refreshUnreadTotal(d)).status).toBe('ok')
  })

  it('waits for a mark-read in flight before it fetches', async () => {
    const order: string[] = []
    let release!: () => void
    const d = deps({
      settled: () =>
        new Promise<void>((r) => {
          release = () => {
            order.push('settled')
            r()
          }
        }),
      fetchTotal: vi.fn().mockImplementation(() => {
        order.push('fetch')
        return Promise.resolve(total)
      }),
    })
    const p = refreshUnreadTotal(d)
    await Promise.resolve()
    expect(order).toEqual([])
    release()
    await p
    expect(order).toEqual(['settled', 'fetch'])
  })

  it('reports a failed fetch instead of throwing', async () => {
    const d = deps({ fetchTotal: vi.fn().mockRejectedValue(new Error('x')) })
    expect(await refreshUnreadTotal(d)).toEqual({ status: 'failed' })
  })
})
