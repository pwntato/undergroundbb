// The purely presentational half of Home's group list -- pulled out of
// Home.tsx specifically so it can be tested with renderToStaticMarkup
// (no effects, no context, no fetch), matching
// SignupProgressStep.test.tsx's own established pattern for a
// prop-driven component in this codebase's no-jsdom test suite. Home.tsx
// owns fetching (useSession, runListGroups) and passes this component a
// plain LoadState; this file owns nothing but rendering it.

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
              <span className="text-xs text-muted-foreground">{group.role}</span>
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
