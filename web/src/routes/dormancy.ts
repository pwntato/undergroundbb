// Which members of a group are dormant (#62): their keys were rotated after
// their entry point was wrapped, so the entry is still wrapped to the key they
// replaced and they cannot read new content until an admin or ambassador
// approves the new keys. Dormancy is derived, not stored: the roster serves each
// member's wrapEpoch, their projection serves keyEpoch, and a member is dormant
// exactly when wrapEpoch is behind keyEpoch (docs/DESIGN.md, "Dormancy is
// derived, not stored"). Both numbers are server-held and unsigned, so this is a
// prompt for a human decision and never an authorization: the approving
// endpoints enforce their own rules.

import type { GroupDetail, MemberEntry } from '@/lib/api/groups'
import type { UserProjection } from '@/lib/api/users'
import { servedFingerprint } from './runMemberVerification'

/**
 * Where the dormant member's entry sits relative to the caller's. 'behind':
 * a generation was minted since they rotated, so a plain wrap of the current
 * key approves them. 'current': the old keys still hold the current key, so
 * approving needs a new key for everyone (the server decides; this only sets
 * the expectation). 'open': an Open group has no re-key, so either way a plain
 * wrap at the approver's generation approves them.
 */
export type DormantEntry = 'behind' | 'current' | 'open'

export interface DormantMember {
  readonly userId: string
  readonly role: MemberEntry['role']
  readonly keyEpoch: number
  readonly wrapEpoch: number
  /** The fingerprint of the keys the server serves for them now; null if unreadable. */
  readonly fingerprint: string | null
  readonly entry: DormantEntry
}

export type Dormancy =
  | { readonly state: 'unavailable' }
  | { readonly state: 'ready'; readonly dormant: readonly DormantMember[] }

export interface LoadDormancyDeps {
  readonly getUsers: (
    ids: readonly string[],
    onError?: (err: unknown) => void,
  ) => Promise<ReadonlyMap<string, UserProjection>>
  readonly selfUserId: string
}

/**
 * The dormant members among `members`, in roster order. Self is left out (a
 * rotated admin brings their own entry current from the Rotate keys page), as
 * is any member whose projection is missing or is a deleted account.
 */
export function findDormant(
  members: readonly MemberEntry[],
  users: ReadonlyMap<string, UserProjection>,
  selfUserId: string,
  myGeneration: GroupDetail['generation'],
  revocationMode: GroupDetail['revocationMode'],
): DormantMember[] {
  const out: DormantMember[] = []
  for (const m of members) {
    if (m.userId === selfUserId) continue
    const user = users.get(m.userId)
    if (user === undefined || user.deleted === true) continue
    // A roster that does not say (an older server) is unknown, not dormant.
    if (m.wrapEpoch === undefined || m.wrapEpoch >= user.keyEpoch) continue
    out.push({
      userId: m.userId,
      role: m.role,
      keyEpoch: user.keyEpoch,
      wrapEpoch: m.wrapEpoch,
      fingerprint: servedFingerprint(user),
      entry:
        revocationMode === 'open' ? 'open' : m.generation < myGeneration ? 'behind' : 'current',
    })
  }
  return out
}

/**
 * Reads every member's projection and derives who is dormant. A failed read is
 * 'unavailable' rather than "nobody is dormant": silence here would look like a
 * clean group.
 */
export async function loadDormancy(
  deps: LoadDormancyDeps,
  members: readonly MemberEntry[],
  myGeneration: GroupDetail['generation'],
  revocationMode: GroupDetail['revocationMode'],
): Promise<Dormancy> {
  const others = members.filter((m) => m.userId !== deps.selfUserId).map((m) => m.userId)
  if (others.length === 0) return { state: 'ready', dormant: [] }
  let failed = false
  const users = await deps.getUsers(others, () => {
    failed = true
  })
  if (failed) return { state: 'unavailable' }
  return {
    state: 'ready',
    dormant: findDormant(members, users, deps.selfUserId, myGeneration, revocationMode),
  }
}
