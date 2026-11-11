// The landing route. Signed out: the signup/login prompt. Signed in: the HomePanel pane (#47),
// fed by the group list the app shell already loaded (groupsContext.ts); the sidebar and the
// account links live in the shell, not here.

import { Link } from 'react-router'
import { Button } from '@/components/ui/button'
import { useSession } from '@/lib/session/useSession'
import { useGroups } from './groupsContext'
import { HomePanel } from './HomePanel'

export function Home() {
  const session = useSession()
  const { load, usernames, requestReauth } = useGroups()

  // Renders nothing rather than the logged-out view while the #32 bootstrap
  // is still checking -- otherwise an authenticated visitor reloading this
  // page would see the signup/login prompt flash before session.userId
  // arrives, even though they're already signed in.
  if (session.status === 'loading') {
    return null
  }

  if (!session.userId) {
    return (
      <div className="flex flex-col items-center gap-4 text-center">
        <h1 className="text-2xl font-bold text-primary">UndergroundBB</h1>
        <p className="text-sm text-muted-foreground">Frontend scaffold. Nothing to see yet.</p>
        <div className="flex gap-2">
          <Button asChild>
            <Link to="/signup">Sign up</Link>
          </Button>
          <Button asChild variant="outline">
            <Link to="/login">Log in</Link>
          </Button>
        </div>
      </div>
    )
  }

  return <HomePanel load={load} usernames={usernames} onReauthenticate={requestReauth} />
}
