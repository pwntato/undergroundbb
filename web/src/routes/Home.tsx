// Placeholder authenticated landing -- #33 is only the signup/login
// screens; the actual home/board view is separate, later work.

import { Link } from 'react-router'
import { Button } from '@/components/ui/button'
import { useSession } from '@/lib/session/useSession'

export function Home() {
  const session = useSession()

  if (!session.userId) {
    return (
      <div className="flex flex-col items-center gap-4 text-center">
        <h1 className="font-mono text-2xl font-bold tracking-tight text-primary">UndergroundBB</h1>
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

  return (
    <div className="flex flex-col items-center gap-4 text-center">
      <h1 className="font-mono text-2xl font-bold tracking-tight text-primary">UndergroundBB</h1>
      <p className="text-sm text-muted-foreground">You&apos;re logged in. Nothing to see yet.</p>
      <Button asChild variant="outline">
        <Link to="/account/password">Change password</Link>
      </Button>
    </div>
  )
}
