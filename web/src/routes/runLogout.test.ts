import { describe, expect, it, vi } from 'vitest'
import { onLogoutClick, runLogout } from './runLogout'

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

describe('onLogoutClick', () => {
  function setup(logoutRequest: () => Promise<void>) {
    const events: string[] = []
    const run = onLogoutClick({
      logoutRequest: () => {
        events.push('request')
        return logoutRequest()
      },
      clearLocalSession: () => events.push('clear'),
      setLoggingOut: (v) => events.push(`busy:${String(v)}`),
      setLogoutError: (m) => events.push(`error:${String(m)}`),
      navigate: (to, o) => events.push(`navigate:${to}:${String(o.replace)}`),
    })
    return { events, run }
  }

  it('clears the old error, is busy for the request, then leaves for the home page, replacing the entry', async () => {
    const { events, run } = setup(() => Promise.resolve())
    await run
    expect(events).toEqual([
      'error:null',
      'busy:true',
      'request',
      'clear',
      'busy:false',
      'navigate:/:true',
    ])
  })

  it('on failure shows the message, stays put, and keeps the local session', async () => {
    const { events, run } = setup(() => Promise.reject(new Error('network')))
    await run
    expect(events).toEqual([
      'error:null',
      'busy:true',
      'request',
      'busy:false',
      'error:Could not log out. Check your connection and try again.',
    ])
  })

  it('is still busy while the request has not answered', async () => {
    let answer!: () => void
    const { events, run } = setup(
      () =>
        new Promise<void>((resolve) => {
          answer = resolve
        }),
    )
    expect(events).toEqual(['error:null', 'busy:true', 'request'])
    answer()
    await run
    expect(events.at(-1)).toBe('navigate:/:true')
  })
})
