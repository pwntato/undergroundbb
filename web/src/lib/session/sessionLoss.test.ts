import { describe, expect, it, vi } from 'vitest'
import { installSessionLossWatcher, isSessionLoss, watchSessionLoss } from './sessionLoss'

const ORIGIN = 'http://localhost:5173'

describe('isSessionLoss', () => {
  it('is true for a 401 from a protected API route', () => {
    for (const path of [
      '/api/groups',
      '/api/invites',
      // next to the excluded /api/account/recovery-code, and still session routes
      '/api/account/credentials',
      '/api/account/password',
      '/api/account',
      '/api/users:batch',
    ]) {
      expect(isSessionLoss(path, 401, ORIGIN), path).toBe(true)
    }
  })

  it('accepts a URL object and a Request-shaped input', () => {
    expect(isSessionLoss(new URL('/api/groups', ORIGIN), 401, ORIGIN)).toBe(true)
    expect(isSessionLoss(new Request(`${ORIGIN}/api/groups`), 401, ORIGIN)).toBe(true)
  })

  it('ignores the routes whose 401 is not a lost session', () => {
    for (const path of [
      // login (internal/handlers/login.go)
      '/api/auth/verify',
      '/api/auth/challenge',
      '/api/auth/session',
      // wrong recovery code (internal/handlers/recovery.go), reachable from the
      // unguarded /recovery screen while logged in
      '/api/account/recovery-code/release',
      '/api/account/recovery-code',
    ]) {
      expect(isSessionLoss(path, 401, ORIGIN), path).toBe(false)
    }
  })

  it('ignores every status but 401', () => {
    for (const status of [200, 403, 404, 409, 410, 500, 503]) {
      expect(isSessionLoss('/api/groups', status, ORIGIN), String(status)).toBe(false)
    }
  })

  it('ignores other origins and non-API paths', () => {
    expect(isSessionLoss('https://example.com/api/groups', 401, ORIGIN)).toBe(false)
    expect(isSessionLoss('/assets/app.js', 401, ORIGIN)).toBe(false)
    expect(isSessionLoss('/apiary', 401, ORIGIN)).toBe(false)
  })
})

describe('watchSessionLoss', () => {
  function stubFetch(status: number) {
    return vi.fn(async () => new Response(null, { status }))
  }

  it('calls onLost on a 401 and still returns the response untouched', async () => {
    const onLost = vi.fn()
    const f = watchSessionLoss(stubFetch(401), ORIGIN, onLost)
    const res = await f('/api/groups')
    expect(res.status).toBe(401)
    expect(onLost).toHaveBeenCalledTimes(1)
  })

  it('does not call onLost for a 500 (a store failure is not a logout) or an auth 401', async () => {
    const onLost = vi.fn()
    await watchSessionLoss(stubFetch(500), ORIGIN, onLost)('/api/groups')
    await watchSessionLoss(stubFetch(401), ORIGIN, onLost)('/api/auth/verify')
    await watchSessionLoss(stubFetch(401), ORIGIN, onLost)('/api/account/recovery-code/release')
    expect(onLost).not.toHaveBeenCalled()
  })

  it('passes the request through unchanged', async () => {
    const inner = stubFetch(200)
    await watchSessionLoss(inner, ORIGIN, () => undefined)('/api/groups', { method: 'POST' })
    expect(inner).toHaveBeenCalledWith('/api/groups', { method: 'POST' })
  })

  it('lets a network error propagate without calling onLost', async () => {
    const onLost = vi.fn()
    const f = watchSessionLoss(
      vi.fn(async () => {
        throw new TypeError('network down')
      }),
      ORIGIN,
      onLost,
    )
    await expect(f('/api/groups')).rejects.toThrow('network down')
    expect(onLost).not.toHaveBeenCalled()
  })
})

describe('installSessionLossWatcher', () => {
  it('swaps in a watching fetch and the undo restores the original', async () => {
    const original = vi.fn(async () => new Response(null, { status: 401 }))
    const target = { fetch: original as unknown as typeof fetch }
    const onLost = vi.fn()

    const undo = installSessionLossWatcher(target, ORIGIN, onLost)
    expect(target.fetch).not.toBe(original)
    await target.fetch('/api/groups')
    expect(onLost).toHaveBeenCalledTimes(1)

    undo()
    expect(target.fetch).toBe(original)
  })
})
