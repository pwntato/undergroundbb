// The one piece of chrome the signed-in screens share (#69): a link to the notification list, on
// every screen except the ones in appHeaderPaths.ts, which hold a one-time recovery code a link out
// would lose. Absolutely placed so it does not push the centred screens down. The group list shows
// per-group unread counts (#145); a header badge and dropdown are not built.

import { Link, useLocation } from 'react-router'
import { useSession } from '@/lib/session/useSession'
import { headerShownOn } from './appHeaderPaths'

export function AppHeaderLink() {
  return (
    <Link to="/notifications" className="text-sm text-primary underline-offset-4 hover:underline">
      Notifications
    </Link>
  )
}

export function AppHeader() {
  const session = useSession()
  const { pathname } = useLocation()
  if (session.status === 'loading' || !session.userId || !headerShownOn(pathname)) return null
  return (
    <header className="absolute right-4 top-3">
      <AppHeaderLink />
    </header>
  )
}
