// The async body behind the roster's grant-chain mark -- issue #55, slice 3.
// Reads the signed grant history and the key histories of everyone who
// signed, runs lib/crypto/grant-chain's verifier, and reports a per-member
// status. Plain function over injected deps, like runGroupMembers.ts.
//
// What the result means: "verified" from the verifier is proof against a
// dishonest server only if the anchor was pinned AND every key history was
// checked against the caller's signed PIN# rows (issue #63). This runner does
// both, and reports how far each got (anchor, keys) so the UI can say
// "verified" only when both matched something saved EARLIER. A first sighting
// is trusted and pinned (TOFU), so it is reported as first-seen, never as
// verified: a server that lied the very first time is not caught here.
//
// Key histories: every grantor's served history is checked with evaluatePin
// before the verifier sees it. match and a fresh TOFU pin are passed on;
// mismatch and bad-signature are BLOCKED (the history is withheld, so the
// verifier fails closed on that person, and the person is reported); if the
// pins or the caller's own key cannot be read the histories pass through
// unchecked and the result says so. A pin covers a user's key SET, not the
// intervals of superseded keys; that matters only once rotation (#62) exists
// and must sign intervals then. `match` is not proof of freshness either
// (docs/DESIGN.md, "A superseded pin can be replayed"): also #62's problem.

import type { ListGrantsResponse } from '@/lib/api/groups'
import type { UserProjection } from '@/lib/api/users'
import type { PinRecord } from '@/lib/crypto/pin'
import { evaluatePin, servedSigningKeySet } from '@/lib/crypto/pin'
import { base64ToBytes, bytesToBase64 } from '@/lib/crypto/base64'
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

/**
 * How the grantors' key histories relate to the caller's signed pins:
 *  - pinned: every history matched a pin saved earlier
 *  - first-seen: no history contradicted a pin, but at least one was pinned
 *    just now (trusted on first use)
 *  - unchecked: the pins or the caller's own key could not be read, or a new
 *    pin could not be saved; some histories are exactly what the server served
 *  - blocked: at least one history contradicted its pin (or failed to verify,
 *    or is malformed) and was withheld; see blockedKeyUsers
 */
export type KeyState = 'pinned' | 'first-seen' | 'unchecked' | 'blocked'

export type GrantCheck =
  | { readonly state: 'unavailable' }
  | {
      readonly state: 'checked'
      readonly anchor: AnchorState
      readonly keys: KeyState
      /** Users whose served keys were withheld from the verifier. */
      readonly blockedKeyUsers: readonly string[]
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
  /** The signed-in user's id (never pinned; checked against their own key). */
  readonly selfUserId: string
  /** The caller's own CURRENT signing public key (base64), from the worker. */
  readonly ownSigningKey: () => Promise<string>
  /** Every pin the caller has stored. */
  readonly listPins: () => Promise<readonly PinRecord[]>
  /** Signs and stores a pin (base64 keys). Rejects if it could not be saved. */
  readonly pinKeys: (
    pinnedUserId: string,
    signingPublicKeys: readonly string[],
    wrappingPublicKey: string,
  ) => Promise<void>
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
    const { served, unreadable } = await readServedKeys(deps, [
      anchor.creatorUserId,
      ...grants.map((g) => g.grantorUserId),
    ])
    const { keyHistories, keys, blockedKeyUsers } = await checkServedKeys(deps, served, unreadable)

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
    return { state: 'checked', anchor: anchorState, keys, blockedKeyUsers, statuses }
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

/**
 * A user whose keys cannot be read is left out (the verifier fails closed on
 * them) and counted in `unreadable`, so the key state cannot claim every
 * grantor's keys were checked.
 */
async function readServedKeys(
  deps: GrantCheckDeps,
  ids: readonly string[],
): Promise<{ served: ReadonlyMap<string, UserProjection>; unreadable: number }> {
  const wanted = [...new Set(ids)]
  const out = new Map<string, UserProjection>()
  let unreadable = 0
  let next = 0
  const worker = async () => {
    while (next < wanted.length) {
      const id = wanted[next++] as string
      try {
        out.set(id, await deps.getUser(id))
      } catch {
        // Fails closed in the verifier ("no key history").
        unreadable++
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(MAX_CONCURRENT_READS, wanted.length) }, worker))
  return { served: out, unreadable }
}

function historyOf(u: UserProjection): UserKeyHistory {
  return { signingPublicKey: u.signingPublicKey, supersededSigningKeys: u.supersededSigningKeys }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i])
}

/**
 * Checks each served key set against the caller's signed pins and returns the
 * histories the verifier may use. Never throws.
 */
async function checkServedKeys(
  deps: GrantCheckDeps,
  served: ReadonlyMap<string, UserProjection>,
  unreadable: number,
): Promise<{
  keyHistories: ReadonlyMap<string, UserKeyHistory>
  keys: KeyState
  blockedKeyUsers: string[]
}> {
  let own: Uint8Array | null = null
  let pins: Map<string, PinRecord> | null = null
  try {
    own = base64ToBytes(await deps.ownSigningKey())
    pins = new Map((await deps.listPins()).map((p) => [p.pinnedUserId, p]))
  } catch {
    // Handled below: histories pass through, reported as unchecked.
  }

  const keyHistories = new Map<string, UserKeyHistory>()
  const blockedKeyUsers: string[] = []
  // A grantor whose keys could not be fetched was never pin-checked.
  let unchecked = unreadable > 0
  let firstSeen = false

  for (const [id, u] of served) {
    if (own === null || pins === null) {
      keyHistories.set(id, historyOf(u))
      unchecked = true
      continue
    }
    if (id === deps.selfUserId) {
      // Your own key comes from the worker, or the copy of it cached in
      // sessionStorage at login (lib/session/ownSigningKey.ts) when a reload
      // dropped the worker's keys -- so sessionStorage is in this trust path;
      // a tampered cache fails closed. Not from the server. No rotation
      // exists yet, so a served history that differs at all is not yours.
      const current = base64ToBytes(u.signingPublicKey)
      if (sameBytes(current, own) && u.supersededSigningKeys.length === 0) {
        keyHistories.set(id, historyOf(u))
      } else {
        blockedKeyUsers.push(id)
      }
      continue
    }
    const verdict = evaluatePin({
      pinnerUserId: deps.selfUserId,
      pinnerSigningPublicKey: own,
      pinnedUserId: id,
      pin: pins.get(id),
      served: u,
    })
    if (verdict === 'match') {
      keyHistories.set(id, historyOf(u))
    } else if (verdict === 'first-sight') {
      const keys = servedSigningKeySet(u)
      if (keys === null) {
        blockedKeyUsers.push(id)
        continue
      }
      keyHistories.set(id, historyOf(u))
      try {
        await deps.pinKeys(id, keys.map(bytesToBase64), u.wrappingPublicKey)
        firstSeen = true
      } catch {
        unchecked = true
      }
    } else {
      // mismatch or bad-signature: withhold, never re-pin over it.
      blockedKeyUsers.push(id)
    }
  }

  const keys: KeyState =
    blockedKeyUsers.length > 0
      ? 'blocked'
      : unchecked
        ? 'unchecked'
        : firstSeen
          ? 'first-seen'
          : 'pinned'
  return { keyHistories, keys, blockedKeyUsers }
}
