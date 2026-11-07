import { describe, expect, it, vi } from 'vitest'
import { listGroupsWithUnread } from './listGroupsWithUnread'

describe('listGroupsWithUnread', () => {
  it('asks for counts, and only after the marks in flight have settled', async () => {
    const order: string[] = []
    let release!: () => void
    const listGroups = vi.fn().mockImplementation((opts: unknown) => {
      order.push(`list ${JSON.stringify(opts)}`)
      return Promise.resolve({ groups: [] })
    })
    const p = listGroupsWithUnread({
      settled: () =>
        new Promise<void>((r) => {
          release = () => {
            order.push('settled')
            r()
          }
        }),
      listGroups,
    })
    await Promise.resolve()
    expect(listGroups).not.toHaveBeenCalled()
    release()
    expect(await p).toEqual({ groups: [] })
    expect(order).toEqual(['settled', 'list {"unread":true}'])
  })

  it('stops waiting after the cap when a mark never finishes', async () => {
    vi.useFakeTimers()
    try {
      const listGroups = vi.fn().mockResolvedValue({ groups: [] })
      const p = listGroupsWithUnread({
        settled: () => new Promise<void>(() => {}),
        listGroups,
        maxWaitMs: 3000,
      })
      await vi.advanceTimersByTimeAsync(2999)
      expect(listGroups).not.toHaveBeenCalled()
      await vi.advanceTimersByTimeAsync(1)
      await p
      expect(listGroups).toHaveBeenCalledTimes(1)
    } finally {
      vi.useRealTimers()
    }
  })
})
