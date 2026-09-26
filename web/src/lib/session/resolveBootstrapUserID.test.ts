// Pins issue #32's actual decision logic -- what SessionProvider's bootstrap
// adopts for each shape GET /api/auth/session (via getSession) can produce --
// independent of React, per this file's own header comment.

import { describe, expect, it } from 'vitest'
import { resolveBootstrapUserID } from './resolveBootstrapUserID'

describe('resolveBootstrapUserID (issue #32)', () => {
  it('adopts the userId from an authenticated response', async () => {
    const userId = await resolveBootstrapUserID(() =>
      Promise.resolve({ authenticated: true, userId: 'user-1' }),
    )
    expect(userId).toBe('user-1')
  })

  it('resolves to null for an unauthenticated response', async () => {
    const userId = await resolveBootstrapUserID(() => Promise.resolve({ authenticated: false }))
    expect(userId).toBeNull()
  })

  it('resolves to null, not authenticated, even if an unauthenticated response carries a userId', async () => {
    // Not a real server shape (session.go's own sessionResponse omits
    // userId whenever Authenticated is false), but the field is optional at
    // the wire level, so a malformed or unexpected response with both set
    // must still be treated as logged-out -- authenticated is the field
    // that decides this, not userId's mere presence.
    const userId = await resolveBootstrapUserID(() =>
      Promise.resolve({ authenticated: false, userId: 'user-1' }),
    )
    expect(userId).toBeNull()
  })

  it('resolves to null on a rejected getSession (network error, 5xx)', async () => {
    const userId = await resolveBootstrapUserID(() => Promise.reject(new Error('network error')))
    expect(userId).toBeNull()
  })
})
