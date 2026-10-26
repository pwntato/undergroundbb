// The handoff rows a committed key rotation left behind (#62, docs/DESIGN.md,
// "The self re-key must survive a closed tab"). A row naming the account's
// CURRENT wrapping key is a self re-key that has not run yet: the server
// refuses another rotation (409 handoff_pending) until it has, so the screen
// says so up front instead of after the user typed a password.
//
// This only reads. It never deletes: a row naming the current key can be the
// only copy of a group's key a sole admin can still reach, and "not in the
// list" comes from an eventually consistent index, so it is not proof the
// caller left. Rows for groups the caller no longer owes one for block nothing
// (the server only counts groups they administer or, with no rotation, belong
// to), and the sweep after the next
// rotation removes them. A row whose generation moved is found out by the
// start being refused (slice 4), which deletes it then.

import type { GroupListEntry } from '@/lib/api/groups'
import type { HandoffEntry } from '@/lib/api/keyRotation'

export interface PendingHandoffDeps {
  readonly listHandoffs: () => Promise<readonly HandoffEntry[]>
}

/**
 * The group ids with a self re-key waiting: rows naming the current key for a
 * group the caller (as far as the list says) administers or, in a group with
 * no rotation, belongs to.
 */
export async function pendingSelfRekeys(
  deps: PendingHandoffDeps,
  groups: readonly GroupListEntry[],
  currentWrappingPublicKey: string,
): Promise<string[]> {
  const rows = await deps.listHandoffs()
  const owed = new Set(
    groups.filter((g) => g.role === 'admin' || g.noRotation).map((g) => g.groupId),
  )
  const pending: string[] = []
  for (const row of rows) {
    if (owed.has(row.groupId) && row.newWrappingPublicKey === currentWrappingPublicKey) {
      pending.push(row.groupId)
    }
  }
  return pending
}
