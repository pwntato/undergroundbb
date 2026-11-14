// The landing route. Signed out: the signup/login prompt. Signed in: the HomePanel pane (#47),
// fed by the group list the app shell already loaded (groupsContext.ts); the sidebar and the
// account links live in the shell, not here.

import { Link } from 'react-router'
import { Button } from '@/components/ui/button'
import { useSession } from '@/lib/session/useSession'
import { useGroups } from './groupsContext'
import { HomePanel } from './HomePanel'
import { REPO_LINK_REL, REPO_URL } from './repoLink'

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
        <p className="max-w-md text-sm text-muted-foreground">
          A private message board for groups you trust. Everything you write in a group is encrypted
          in your browser, and the server never sees your password or can read your posts.
        </p>
        <div className="flex gap-2">
          <Button asChild>
            <Link to="/signup">Sign up</Link>
          </Button>
          <Button asChild variant="outline">
            <Link to="/login">Log in</Link>
          </Button>
        </div>
        <a
          href={REPO_URL}
          target="_blank"
          rel={REPO_LINK_REL}
          className="inline-flex min-h-[1.5rem] items-center text-sm text-muted-foreground underline underline-offset-4 hover:text-primary"
        >
          Source code on GitHub
        </a>
      </div>
    )
  }

  return <HomePanel load={load} usernames={usernames} onReauthenticate={requestReauth} />
}
