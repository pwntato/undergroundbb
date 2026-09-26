// Issue #32's other direction from RequireAuth: keeps an already-logged-in
// visitor from landing back on /login or /signup, e.g. a bookmark or a
// back-navigation after logging in elsewhere in the same tab. Same
// loading-wait rationale as RequireAuth -- see SessionContext's own comment.

import type { ReactNode } from 'react'
import { Navigate } from 'react-router'
import { useSession } from './useSession'

export function RedirectIfAuthenticated({ children }: { children: ReactNode }) {
  const session = useSession()

  if (session.status === 'loading') {
    return null
  }
  if (session.userId !== null) {
    return <Navigate to="/" replace />
  }
  return children
}
