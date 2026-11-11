// The signed-in landing pane (#47), hook-free so it renders in a test. The sidebar already lists
// the groups, so this pane says what to DO: a new user with no groups gets the three ways in, and a
// user with groups gets "new posts in these" or "all caught up", then the per-group actions.

import { Link } from 'react-router'
import { Button } from '@/components/ui/button'
import { GroupList, type LoadState } from './GroupList'
import { groupLabel } from './groupLabel'
import { unreadLabel } from './unreadLabel'

const TEXT_LINK =
  'inline-flex min-h-[1.5rem] items-center text-sm text-primary underline underline-offset-4'

function FirstSteps() {
  return (
    <section
      aria-labelledby="first-steps"
      className="flex w-full flex-col gap-3 rounded-md border p-4 text-left"
    >
      <h2 id="first-steps" className="text-lg font-semibold">
        Welcome. Let&apos;s get you into a group.
      </h2>
      <p className="text-sm text-muted-foreground">
        You&apos;re not in any groups yet, so there is nothing to read. Pick one:
      </p>
      <ul className="flex flex-col gap-3">
        <li className="flex flex-col items-start gap-1">
          <span className="text-sm">Start your own and invite people to it.</span>
          <Button asChild>
            <Link to="/groups/new">Create a group</Link>
          </Button>
        </li>
        <li className="flex flex-col items-start gap-1">
          <span className="text-sm">Browse the groups anyone can ask to join.</span>
          <Button asChild variant="outline">
            <Link to="/directory">Find groups</Link>
          </Button>
        </li>
        <li className="flex flex-col items-start gap-1">
          <span className="text-sm">
            Got an invite link? Open it in this browser. Invites you have accepted wait for you
            here.
          </span>
          <Link to="/invites" className={TEXT_LINK}>
            Check your invites
          </Link>
        </li>
      </ul>
    </section>
  )
}

export function HomePanel({
  load,
  usernames,
  onReauthenticate,
}: {
  readonly load: LoadState
  readonly usernames: ReadonlyMap<string, string>
  readonly onReauthenticate: () => void
}) {
  const groups = load.status === 'ready' ? load.groups : []
  const unread = groups.filter((g) => unreadLabel(g.unread, g.unreadMore) !== null)
  return (
    <div className="flex w-full max-w-md flex-col items-center gap-4 text-center">
      <h1 className="text-2xl font-bold text-primary">UndergroundBB</h1>

      {load.status === 'ready' && groups.length === 0 ? (
        <FirstSteps />
      ) : (
        <>
          {load.status === 'ready' && (
            <p className="text-sm text-muted-foreground">
              {unread.length === 0
                ? "You're all caught up. Nothing new to read."
                : `New to read in ${unread.map((g) => groupLabel(g, usernames)).join(', ')}.`}
            </p>
          )}
          <GroupList load={load} usernames={usernames} onReauthenticate={onReauthenticate} />
        </>
      )}
    </div>
  )
}
