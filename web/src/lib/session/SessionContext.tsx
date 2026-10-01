// Tracks this tab's session state for routing decisions (e.g. redirecting an
// already-logged-in visitor away from /login, or an unauthenticated one away
// from a protected route via RequireAuth). This is NOT authentication's
// source of truth -- the session cookie is HttpOnly and every API call is
// authenticated (or not) by the server on each request regardless of what
// this context says. It exists only so the UI doesn't have to guess before
// the server tells it.
//
// Issue #32: on mount, this fetches GET /api/auth/session once and adopts
// whatever it reports, rather than always starting as logged-out. status
// stays 'loading' until that resolves so a consumer (RequireAuth in
// particular) can wait for the real answer instead of redirecting an
// authenticated visitor to /login for the one tick before the cookie check
// comes back. A failed fetch (network error, 5xx) is treated the same as
// "not authenticated": there is nothing else defensible to assume, and every
// route this gates already tolerates being wrong in that direction (worst
// case, an authenticated visitor sees a login prompt and re-establishes the
// session that already exists).

import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { getSession } from '@/lib/api/auth'
import { clearLiveKeys, getOwnSigningKey } from '@/lib/crypto/worker-client'
import { cacheOwnSigningKey, clearCachedOwnSigningKey } from './ownSigningKey'
import { clearGroupNameCache } from '@/lib/groups/groupNameCache'
import { SessionContext, type SessionState } from './session-context'
import { resolveBootstrapUserID } from './resolveBootstrapUserID'

export function SessionProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<SessionState['status']>('loading')
  const [userId, setUserId] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    void (async () => {
      const id = await resolveBootstrapUserID(getSession)
      if (!cancelled) {
        setUserId(id)
        setStatus('ready')
      }
    })()
    return () => {
      cancelled = true
    }
    // Deliberately empty deps: this bootstrap runs exactly once per app
    // mount, not once per tab's actual session lifetime -- login()/logout()
    // update userId directly rather than re-triggering this effect, the
    // same distinction the previous version of this file's own comment drew
    // between "believes it has a session" and re-checking the server.
  }, [])

  const value = useMemo<SessionState>(
    () => ({
      status,
      userId,
      login: (id: string) => {
        // Both callers (login, signup) run this only after completeLogin has
        // populated the worker's liveKeys. Cache the PUBLIC signing key so a
        // page reload, which drops liveKeys, does not leave the roster check
        // unable to read the caller's own key (#171). Symmetric with logout.
        void getOwnSigningKey(id).then(
          (k) => cacheOwnSigningKey(id, k),
          () => undefined,
        )
        setUserId(id)
      },
      logout: () => {
        // Issue #34: also clears the crypto worker's cached liveKeys, so a
        // worker instance reused across a logout/login in the same tab
        // never signs anything under the account that just logged out. No
        // logout endpoint/UI exists yet (ChangePasswordScreen.tsx's own
        // session.logout() calls are for an expired-session redirect, not a
        // user-initiated logout) -- this still needs to run there too, once
        // one does, for the same reason.
        clearLiveKeys()
        // Issue #35: also clears this tab's cached decrypted group names --
        // same reasoning as clearLiveKeys, a reused worker instance/tab must
        // never show a previous account's group names, and userId is still
        // in scope here (the value this cache was keyed under) even though
        // it's about to be cleared below.
        if (userId !== null) {
          clearGroupNameCache(userId)
          clearCachedOwnSigningKey(userId)
        }
        setUserId(null)
      },
    }),
    [status, userId],
  )
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}
