// The one piece of chrome every signed-in screen shares (#69): a link to the notification list.
// Absolutely placed so it does not push the centred screens down. The unread badge and a dropdown
// come with #145, once there is a count to show.

import { Link } from 'react-router'
import { useSession } from '@/lib/session/useSession'

export function AppHeaderLink() {
  return (
    <Link to="/notifications" className="text-sm text-primary underline-offset-4 hover:underline">
      Notifications
    </Link>
  )
}

export function AppHeader() {
  const session = useSession()
  if (session.status === 'loading' || !session.userId) return null
  return (
    <header className="absolute right-4 top-3">
      <AppHeaderLink />
    </header>
  )
}
