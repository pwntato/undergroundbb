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
 *  - unpinned: no pin exists and none could be taken (nothing verified, or
 *    storage unavailable)
 *  - changed: differs from the pin (or the server served two anchors)
 */
export type AnchorState = 'pinned' | 'first-seen' | 'unpinned' | 'changed'

export type GrantCheck =
  | { readonly state: 'unavailable' }
  | {
      readonly state: 'checked'
      readonly anchor: AnchorState
      readonly statuses: ReadonlyMap<string, RoleStatus>
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

    let anchorState: AnchorState
    if (!anchorsAgree || (stored !== null && !result.anchorPinned)) {
      anchorState = 'changed'
    } else if (stored !== null) {
      anchorState = 'pinned'
    } else if (result.verdicts.get(anchor.rootGrantSortKey)?.valid === true) {
      // Trust on first use, and only for an anchor whose root verified.
      const saved = deps.writePin(groupId, {
        creatorUserId: anchor.creatorUserId,
        creatorSigningPublicKey: anchor.creatorSigningPublicKey,
      })
      anchorState = saved ? 'first-seen' : 'unpinned'
    } else {
      anchorState = 'unpinned'
    }

    const statuses = new Map<string, RoleStatus>()
    for (const m of members) {
      statuses.set(
        m.userId,
        anchorState === 'changed'
          ? { status: 'unverified', reason: 'the group anchor changed since you first saw it' }
          : checkMemberRole(result, m.userId, m.role),
      )
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
