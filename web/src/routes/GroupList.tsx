// The purely presentational half of Home's group list -- pulled out of
// Home.tsx specifically so it can be tested with renderToStaticMarkup
// (no effects, no context, no fetch), matching
// SignupProgressStep.test.tsx's own established pattern for a
// prop-driven component in this codebase's no-jsdom test suite. Home.tsx
// owns fetching (useSession, runListGroups) and passes this component a
// plain LoadState; this file owns nothing but rendering it.

import { Link } from 'react-router'
import type { DisplayGroup } from './runListGroups'
import { groupLabel } from './groupLabel'

export type LoadState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly groups: readonly DisplayGroup[] }
  | { readonly status: 'error' }

export function GroupList({ load }: { readonly load: LoadState }) {
  return (
    <>
      {load.status === 'loading' && (
        <p className="text-sm text-muted-foreground">Loading your groups…</p>
      )}

      {load.status === 'error' && (
        <p className="text-sm text-destructive">
          Couldn&apos;t load your groups. Try reloading the page.
        </p>
      )}

      {load.status === 'ready' && load.groups.length === 0 && (
        <p className="text-sm text-muted-foreground">You&apos;re not in any groups yet.</p>
      )}

      {load.status === 'ready' && load.groups.length > 0 && (
        <ul className="flex w-full flex-col gap-2 text-left">
          {load.groups.map((group) => (
            <li
              key={group.groupId}
              className="flex items-center justify-between rounded-md border px-3 py-2"
            >
              <span className="font-medium">{groupLabel(group)}</span>
              <span className="flex items-center gap-2">
                {/* Issue #38: only an Admin or Ambassador may create an
                    invite (the server's own 403 is the real check --
                    this is just not offering the link to a plain Member,
                    who would only see it fail). */}
                <Link
                  to={`/groups/${group.groupId}/members`}
                  className="text-xs text-primary underline-offset-4 hover:underline"
                >
                  Members
                </Link>
                <Link
                  to={`/groups/${group.groupId}/settings`}
                  className="text-xs text-primary underline-offset-4 hover:underline"
                >
                  Settings
                </Link>
                {(group.role === 'admin' || group.role === 'ambassador') && (
                  <Link
                    to={`/groups/${group.groupId}/invite`}
                    className="text-xs text-primary underline-offset-4 hover:underline"
                  >
                    Invite
                  </Link>
                )}
                <span className="text-xs text-muted-foreground">{group.role}</span>
              </span>
            </li>
          ))}
        </ul>
      )}

      {load.status === 'ready' && load.groups.some((g) => g.nameStatus === 'coldKeys') && (
        <p className="text-xs text-muted-foreground">Log in again to see private group names.</p>
      )}
    </>
  )
}
