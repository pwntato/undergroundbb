import { describe, expect, it, vi } from 'vitest'
import { runLogout } from './runLogout'

describe('runLogout', () => {
  it('clears the local session after the server call succeeds', async () => {
    const order: string[] = []
    const outcome = await runLogout({
      logoutRequest: () => {
        order.push('request')
        return Promise.resolve()
      },
      clearLocalSession: () => order.push('clear'),
    })
    expect(outcome).toEqual({ ok: true })
    expect(order).toEqual(['request', 'clear'])
  })

  it('keeps the local session when the server call fails', async () => {
    const clearLocalSession = vi.fn()
    const outcome = await runLogout({
      logoutRequest: () => Promise.reject(new Error('network')),
      clearLocalSession,
    })
    expect(outcome.ok).toBe(false)
    expect(clearLocalSession).not.toHaveBeenCalled()
  })
})
