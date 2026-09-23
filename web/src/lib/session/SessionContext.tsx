// Tracks whether this tab believes it has an active session, purely as UI
// state for routing decisions (e.g. redirecting an already-logged-in visitor
// away from /login). This is NOT the source of truth for authentication --
// the session cookie is HttpOnly and every API call is authenticated (or
// not) by the server on each request regardless of what this context says.
// A page reload always starts logged-out here even with a live cookie; nothing
// currently needs this to survive a reload, since every screen it gates
// (login, signup) is itself safe to show to an already-authenticated visitor.

import { useMemo, useState, type ReactNode } from 'react'
import { SessionContext, type SessionState } from './session-context'

export function SessionProvider({ children }: { children: ReactNode }) {
  const [userId, setUserId] = useState<string | null>(null)
  const value = useMemo<SessionState>(
    () => ({
      userId,
      login: (id: string) => {
        setUserId(id)
      },
      logout: () => {
        setUserId(null)
      },
    }),
    [userId],
  )
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}
