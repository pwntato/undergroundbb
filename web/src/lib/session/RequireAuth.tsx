// Issue #32: route guard for a protected screen that has nothing of its own
// to fetch first. This is NOT the only way to guard a route in this
// codebase -- ChangePasswordScreen deliberately does its own bootstrap
// instead (see that file's own header comment): it already needs GET
// /api/account/credentials to unwrap PROFILE, and that call's own 401 is a
// more reliable auth check than SessionContext, since SessionContext can be
// stale the instant this component's session cookie expires mid-visit while
// SessionContext still says authenticated. Use RequireAuth for a route that
// has no such call to piggyback on; use ChangePasswordScreen's pattern (a
// real authenticated request whose 401 redirects) when the screen needs one
// anyway.
//
// Waits out status: 'loading' rather than redirecting immediately -- see
// SessionContext's own comment on why: redirecting before the real answer
// comes back would bounce an authenticated visitor to /login for one tick on
// every load.

import type { ReactNode } from 'react'
import { Navigate } from 'react-router'
import { useSession } from './useSession'

export function RequireAuth({ children }: { children: ReactNode }) {
  const session = useSession()

  if (session.status === 'loading') {
    return null
  }
  if (session.userId === null) {
    return <Navigate to="/login" replace />
  }
  return children
}
