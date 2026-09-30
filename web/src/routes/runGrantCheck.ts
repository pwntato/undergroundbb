// The async body behind the roster's grant-chain mark -- issue #55, slice 3.
// Reads the signed grant history and the key histories of everyone who
// signed, runs lib/crypto/grant-chain's verifier, and reports a per-member
// status. Plain function over injected deps, like runGroupMembers.ts.
//
// What the result means: "verified" from the verifier is proof against a
// dishonest server only if the anchor was pinned AND every key history was
// checked against signed PIN# rows. PIN# is not built, so key histories here
// are exactly what the server served, and the UI must not call a consistent
// chain "verified" (see GroupMembersPanel). What this DOES catch: an anchor
// that changed since this browser first saw it, and any role the signed
// history does not back.

import type { ListGrantsResponse } from '@/lib/api/groups'
import type { UserProjection } from '@/lib/api/users'
import {
  checkMemberRole,
  verifyGrantChain,
  type GrantRecord,
  type RoleStatus,
  type UserKeyHistory,
} from '@/lib/crypto/grant-chain'
import type { StoredAnchorPin } from '@/lib/groups/anchorPin'

/**
 * How the anchor relates to this browser's pin:
 *  - pinned: matches the pin taken earlier
 *  - first-seen: no earlier pin; verified root, pin taken just now
 *  - unpinned: the root verified but no pin could be taken (storage
 *    unavailable or refused the write)
 *  - changed: differs from the pin (or the server served two anchors)
 *  - root-unverified: the root grant did not verify (or was not served), so
 *    nothing in the chain has a valid start. Takes precedence over the pin
 *    states except 'changed'. Can be forgery or an honest lookup failure
 *    (e.g. the creator's key history could not be read).
 */
export type AnchorState = 'pinned' | 'first-seen' | 'unpinned' | 'changed' | 'root-unverified'

export type GrantCheck =
  | { readonly state: 'unavailable' }
  | {
      readonly state: 'checked'
      readonly anchor: AnchorState
      readonly statuses: ReadonlyMap<string, RoleStatus>
    }

/**
 * A check together with the exact roster it ran against. The screen shows
 * the check only while its view is still the current one, so marks from a
 * previous roster (after a role change) or another group never sit against
 * this one while the new check runs.
 */
export interface ViewCheck<V> {
  readonly view: V
  readonly result: GrantCheck
}

/** The check to display for `current`, or null if it belongs to another view. */
export function checkForView<V>(stored: ViewCheck<V> | null, current: V): GrantCheck | null {
  return stored !== null && stored.view === current ? stored.result : null
}

export interface GrantCheckDeps {
  readonly listGrants: (groupId: string, cursor?: string) => Promise<ListGrantsResponse>
  readonly getUser: (userId: string) => Promise<UserProjection>
  readonly readPin: (groupId: string) => StoredAnchorPin | null
  readonly writePin: (groupId: string, pin: StoredAnchorPin) => boolean
}

// A history this deep means the server is not honoring nextCursor; stop.
const MAX_GRANT_PAGES = 100
const MAX_CONCURRENT_READS = 8

/** Checks every member's role against the signed history. Never throws. */
export async function checkGrants(
  deps: GrantCheckDeps,
  groupId: string,
  members: readonly { readonly userId: string; readonly role: string }[],
): Promise<GrantCheck> {
  try {
    const { anchor, grants, anchorsAgree } = await readAllGrants(deps, groupId)
    const keyHistories = await readKeyHistories(deps, [
      anchor.creatorUserId,
      ...grants.map((g) => g.grantorUserId),
    ])

    const stored = deps.readPin(groupId)
    const result = verifyGrantChain({
      groupId,
      anchor,
      ...(stored !== null && { pinnedAnchor: stored }),
      grants,
      keyHistories,
    })

    const rootVerdict = result.verdicts.get(anchor.rootGrantSortKey)
    let anchorState: AnchorState
    if (!anchorsAgree || (stored !== null && !result.anchorPinned)) {
      anchorState = 'changed'
    } else if (rootVerdict?.valid !== true) {
      // Checked before the pin states: a pinned anchor with a root that no
      // longer verifies is still a chain with no valid start.
      anchorState = 'root-unverified'
    } else if (stored !== null) {
      anchorState = 'pinned'
    } else {
      // Trust on first use, and only for an anchor whose root verified.
      const saved = deps.writePin(groupId, {
        creatorUserId: anchor.creatorUserId,
        creatorSigningPublicKey: anchor.creatorSigningPublicKey,
      })
      anchorState = saved ? 'first-seen' : 'unpinned'
    }

    // checkMemberRole calls a grantless member "verified" without looking at
    // the root, so a chain with no valid start is overridden for everyone.
    const blanket: RoleStatus | null =
      anchorState === 'changed'
        ? { status: 'unverified', reason: 'the group anchor changed since you first saw it' }
        : anchorState === 'root-unverified'
          ? {
              status: 'unverified',
              reason: `the group's root grant could not be checked${
                rootVerdict?.reason !== undefined ? ` (${rootVerdict.reason})` : ' (not served)'
              }`,
            }
          : null
    const statuses = new Map<string, RoleStatus>()
    for (const m of members) {
      statuses.set(m.userId, blanket ?? checkMemberRole(result, m.userId, m.role))
    }
    return { state: 'checked', anchor: anchorState, statuses }
  } catch {
    return { state: 'unavailable' }
  }
}

async function readAllGrants(
  deps: GrantCheckDeps,
  groupId: string,
): Promise<{
  anchor: ListGrantsResponse['anchor']
  grants: GrantRecord[]
  anchorsAgree: boolean
}> {
  const grants: GrantRecord[] = []
  let anchor: ListGrantsResponse['anchor'] | undefined
  let anchorsAgree = true
  let cursor: string | undefined
  for (let page = 0; page < MAX_GRANT_PAGES; page++) {
    const res = await deps.listGrants(groupId, cursor)
    if (anchor === undefined) {
      anchor = res.anchor
    } else if (JSON.stringify(anchor) !== JSON.stringify(res.anchor)) {
      anchorsAgree = false
    }
    grants.push(...res.grants)
    if (!res.nextCursor) {
      return { anchor, grants, anchorsAgree }
    }
    cursor = res.nextCursor
  }
  throw new Error('grant pagination did not terminate')
}

/** A user whose history cannot be read is left out; the verifier fails closed on them. */
async function readKeyHistories(
  deps: GrantCheckDeps,
  ids: readonly string[],
): Promise<ReadonlyMap<string, UserKeyHistory>> {
  const wanted = [...new Set(ids)]
  const out = new Map<string, UserKeyHistory>()
  let next = 0
  const worker = async () => {
    while (next < wanted.length) {
      const id = wanted[next++] as string
      try {
        const u = await deps.getUser(id)
        out.set(id, {
          signingPublicKey: u.signingPublicKey,
          supersededSigningKeys: u.supersededSigningKeys,
        })
      } catch {
        // Fails closed in the verifier ("no key history").
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(MAX_CONCURRENT_READS, wanted.length) }, worker))
  return out
}
