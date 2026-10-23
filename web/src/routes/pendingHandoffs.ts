// The handoff rows a committed key rotation left behind (#62, docs/DESIGN.md,
// "The self re-key must survive a closed tab"). A row naming the account's
// CURRENT wrapping key is a self re-key that has not run yet: the server
// refuses another rotation (409 handoff_pending) until it has, so the screen
// says so up front instead of after the user typed a password.
//
// This only reads and tidies. A row is deleted here only when it can never be
// used: the group is gone from the caller's list or they no longer administer
// it. A row whose generation moved is not decided here (the list does not say
// what the group's newest generation is); the start finds that out by being
// refused, and deletes it then.

import type { GroupListEntry } from '@/lib/api/groups'
import type { HandoffEntry } from '@/lib/api/keyRotation'

export interface PendingHandoffDeps {
  readonly listHandoffs: () => Promise<readonly HandoffEntry[]>
  readonly deleteHandoff: (groupId: string) => Promise<void>
}

/**
 * The group ids with a self re-key waiting, after deleting the rows nothing can
 * use. A failed delete is not an error: the row stays, and the next visit tries
 * again.
 */
export async function pendingSelfRekeys(
  deps: PendingHandoffDeps,
  groups: readonly GroupListEntry[],
  currentWrappingPublicKey: string,
): Promise<string[]> {
  const rows = await deps.listHandoffs()
  const adminOf = new Set(groups.filter((g) => g.role === 'admin').map((g) => g.groupId))
  const pending: string[] = []
  for (const row of rows) {
    if (!adminOf.has(row.groupId)) {
      await deps.deleteHandoff(row.groupId).catch(() => undefined)
      continue
    }
    if (row.newWrappingPublicKey === currentWrappingPublicKey) {
      pending.push(row.groupId)
    }
  }
  return pending
}
