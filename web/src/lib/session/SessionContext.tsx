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
        setUserId(id)
      },
      logout: () => {
        setUserId(null)
      },
    }),
    [status, userId],
  )
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}
