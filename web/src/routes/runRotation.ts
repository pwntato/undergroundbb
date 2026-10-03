// The resumable key-rotation job -- issue #58, slice 3. After a Rotating-group
// removal starts a rotation (the server commits the marker, the GENKEY# link
// and the remover's own entry at the new generation), every other member's
// entry point still has to be re-wrapped to the new key, from a browser, in
// batches that can be interrupted. This is that loop, and also the on-load
// catch-up for a member who ended up behind with no rotation running.
//
// docs/DESIGN.md, "Revocation mode" and "Finishing a rotation", are the spec;
// the points that are easy to get wrong:
//   - Resume is STATE-driven: every pass re-lists the members and re-wraps
//     those whose generation is behind the target. There is no cursor, because
//     a batch's outcome is all-or-nothing on the server but a lost response
//     leaves the client not knowing which side it landed on.
//   - Other ADMINS are re-wrapped first, so any re-wrapped admin can resume if
//     this tab closes (only an admin already at the new generation can).
//   - Re-wrap ONLY members who are behind. A wrong key written over an admin
//     already at the generation would lock out exactly the admins able to
//     resume; the server's tolerance for it exists for lost-response retries.
//   - Every recipient's X25519 key is checked against the caller's signed pins
//     before anything is wrapped to it. A server-substituted key would hand the
//     server the new group key and defeat the rotation, so this FAILS CLOSED:
//     a mismatch or an unverifiable key is skipped and reported, never wrapped
//     to, and an unreadable pin set stops the run. (This differs from the
//     roster's grant check, which can show a mark while "unchecked".)
//   - The pin check covers each recipient's KEY, not WHO the recipients are:
//     the member list is whatever the server reports. A dishonest server can
//     keep listing a removed member or add its own account, so the rotation
//     protects only as far as membership is reported honestly (DESIGN.md,
//     "The recipient set is taken from the server").
//
// Plain function over injected deps, like runGrantCheck.ts, so it tests against
// stubs without a worker or the network.

import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, MemberEntry, RewrapEntry } from '@/lib/api/groups'
import { MAX_REWRAP_BATCH } from '@/lib/api/groups'
import type { UserProjection } from '@/lib/api/users'
import { base64ToBytes, bytesToBase64 } from '@/lib/crypto/base64'
import { evaluatePin, servedSigningKeySet, type PinRecord } from '@/lib/crypto/pin'
import type { RewrapGroupKeyResult } from '@/lib/crypto/worker-protocol'

/** Passes before giving up. A pass is a full re-list, so this bounds churn, not batches. */
const MAX_PASSES = 6

export interface RotationDeps {
  readonly selfUserId: string
  readonly getGroup: (groupId: string) => Promise<GroupDetail>
  /** Every member, following nextCursor. */
  readonly listAllMembers: (groupId: string) => Promise<readonly MemberEntry[]>
  readonly getUser: (userId: string) => Promise<UserProjection>
  /** The caller's own current signing public key, base64. */
  readonly ownSigningKey: () => Promise<string>
  /** Every pin the caller holds, following nextCursor. A missing pin reads as first-sight, so a partial list is unsafe. */
  readonly listPins: () => Promise<readonly PinRecord[]>
  /** Signs and stores a first-sight pin, as the roster's grant check does. */
  readonly pinKeys: (
    pinnedUserId: string,
    signingPublicKeys: readonly string[],
    wrappingPublicKey: string,
  ) => Promise<void>
  readonly rewrapCrypto: (req: {
    readonly userId: string
    readonly groupId: string
    readonly ownWrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
    readonly ownGeneration: number
    readonly recipients: readonly { userId: string; x25519PublicKey: string }[]
  }) => Promise<RewrapGroupKeyResult>
  readonly rewrapMembers: (
    groupId: string,
    req: { readonly generation: number; readonly wraps: readonly RewrapEntry[] },
  ) => Promise<void>
  readonly completeRotation: (groupId: string, generation: number) => Promise<void>
}

export type RotationOutcome =
  /** Not an admin, or nothing to do: no marker and nobody behind. */
  | { readonly status: 'none' }
  /** A marker was running and is now cleared; `rewrapped` members were moved. */
  | { readonly status: 'completed'; readonly rewrapped: number }
  /** No marker; `rewrapped` members who were behind were brought up. */
  | { readonly status: 'caught-up'; readonly rewrapped: number }
  /**
   * Members whose keys failed the pin check were NOT wrapped to, so the
   * rotation cannot finish. Everyone else was moved.
   */
  | {
      readonly status: 'blocked'
      readonly blocked: readonly string[]
      readonly rewrapped: number
    }
  /** The caller is an admin but not at the rotation's generation: another admin who is must resume. */
  | { readonly status: 'cannot-resume'; readonly reason: string }
  /** Stopped before finishing (network, churn, unreadable pins); safe to run again. */
  | { readonly status: 'incomplete'; readonly reason: string; readonly rewrapped: number }

function codeOf(err: unknown): string | undefined {
  return err instanceof ApiError ? err.code : undefined
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/** Admins first: only an admin at the new generation can resume a stalled rotation. */
function adminsFirst(members: readonly MemberEntry[]): MemberEntry[] {
  return [
    ...members.filter((m) => m.role === 'admin'),
    ...members.filter((m) => m.role !== 'admin'),
  ]
}

/**
 * Runs (or resumes) the rotation for groupId, or catches up a member left
 * behind when no rotation is running. Safe to call on every group load by an
 * admin: it does nothing and says 'none' when there is nothing to do.
 */
export async function runRotation(deps: RotationDeps, groupId: string): Promise<RotationOutcome> {
  return runOnce(deps, groupId, false, 0)
}

async function runOnce(
  deps: RotationDeps,
  groupId: string,
  restarted: boolean,
  carried: number,
): Promise<RotationOutcome> {
  let detail: GroupDetail
  try {
    detail = await deps.getGroup(groupId)
  } catch (err) {
    return { status: 'incomplete', reason: describe(err), rewrapped: carried }
  }
  if (detail.role !== 'admin' || detail.visibility !== 'private' || !detail.wrappedGroupKey) {
    return { status: 'none' }
  }

  const ownGeneration = detail.generation
  const marker = detail.rotation
  if (marker !== undefined && marker.generation !== ownGeneration) {
    return {
      status: 'cannot-resume',
      reason:
        ownGeneration < marker.generation
          ? 'your own key is not at the rotation generation yet; an admin who has it must resume'
          : 'your own key is ahead of the rotation marker; reload',
    }
  }
  const ownWrappedGroupKey = detail.wrappedGroupKey

  // Fail closed on the pin set: never wrap to a key that was not checked.
  let own: Uint8Array
  try {
    own = base64ToBytes(await deps.ownSigningKey())
  } catch (err) {
    return {
      status: 'incomplete',
      reason: `could not read your pins: ${describe(err)}`,
      rewrapped: carried,
    }
  }

  const blocked = new Set<string>()
  let rewrapped = carried

  for (let pass = 0; pass < MAX_PASSES; pass++) {
    // Re-read the pins every pass: checkRecipient pins first-sight members
    // mid-run, and a stale map would treat them as first-sight again after a
    // retry and re-pin over whatever key the server serves now.
    let pins: Map<string, PinRecord>
    let members: readonly MemberEntry[]
    try {
      pins = new Map((await deps.listPins()).map((p) => [p.pinnedUserId, p]))
    } catch (err) {
      return {
        status: 'incomplete',
        reason: `could not read your pins: ${describe(err)}`,
        rewrapped,
      }
    }
    try {
      members = await deps.listAllMembers(groupId)
    } catch (err) {
      return { status: 'incomplete', reason: describe(err), rewrapped }
    }
    const behind = adminsFirst(
      members.filter(
        (m) =>
          m.userId !== deps.selfUserId && m.generation < ownGeneration && !blocked.has(m.userId),
      ),
    )

    if (behind.length === 0) {
      if (blocked.size > 0) {
        return { status: 'blocked', blocked: [...blocked], rewrapped }
      }
      if (marker === undefined) {
        return rewrapped > 0 ? { status: 'caught-up', rewrapped } : { status: 'none' }
      }
      try {
        await deps.completeRotation(groupId, ownGeneration)
        return { status: 'completed', rewrapped }
      } catch (err) {
        const code = codeOf(err)
        if (code === 'rotation_not_active') {
          // Someone else finished it (or it was superseded): done from here.
          return { status: 'completed', rewrapped }
        }
        if (code === 'members_behind' || code === 'conflict_retry') {
          continue // a member appeared since the listing; take another pass
        }
        return { status: 'incomplete', reason: describe(err), rewrapped }
      }
    }

    for (let i = 0; i < behind.length; i += MAX_REWRAP_BATCH) {
      const chunk = behind.slice(i, i + MAX_REWRAP_BATCH)
      const recipients: { userId: string; x25519PublicKey: string }[] = []
      for (const m of chunk) {
        const verdict = await checkRecipient(deps, own, pins, m.userId)
        if (verdict.ok) {
          recipients.push({ userId: m.userId, x25519PublicKey: verdict.wrappingPublicKey })
        } else if (verdict.reason === 'blocked') {
          blocked.add(m.userId)
        } else {
          return { status: 'incomplete', reason: verdict.detail, rewrapped }
        }
      }
      if (recipients.length === 0) {
        continue
      }
      try {
        const result = await deps.rewrapCrypto({
          userId: deps.selfUserId,
          groupId,
          ownWrappedGroupKey,
          ownGeneration,
          recipients,
        })
        await deps.rewrapMembers(groupId, { generation: ownGeneration, wraps: result.wraps })
        rewrapped += recipients.length
      } catch (err) {
        const code = codeOf(err)
        if (code === 'member_changed' || code === 'conflict_retry') {
          break // the roster moved under the batch: re-list and recompute who is behind
        }
        if (code === 'rotation_not_active' && !restarted) {
          // The marker changed under us; start over from a fresh read once.
          return runOnce(deps, groupId, true, rewrapped)
        }
        return { status: 'incomplete', reason: describe(err), rewrapped }
      }
    }
  }
  return { status: 'incomplete', reason: 'the group kept changing; run again', rewrapped }
}

type RecipientCheck =
  | { readonly ok: true; readonly wrappingPublicKey: string }
  | { readonly ok: false; readonly reason: 'blocked' }
  | { readonly ok: false; readonly reason: 'unavailable'; readonly detail: string }

/**
 * Checks one recipient's served keys against the caller's signed pins. Match:
 * wrap to the key. First sight: pin it (as the roster does) and wrap, which is
 * the documented v1 trust-on-first-use. Mismatch or bad signature: blocked,
 * never wrapped to and never re-pinned over. A user whose keys cannot be
 * fetched, or a first-sight pin that cannot be stored, is "unavailable": stop,
 * because wrapping to an unrecorded key would leave nothing to check next time.
 */
async function checkRecipient(
  deps: RotationDeps,
  own: Uint8Array,
  pins: Map<string, PinRecord>,
  userId: string,
): Promise<RecipientCheck> {
  let served: UserProjection
  try {
    served = await deps.getUser(userId)
  } catch (err) {
    return {
      ok: false,
      reason: 'unavailable',
      detail: `could not fetch keys for ${userId}: ${describe(err)}`,
    }
  }
  const verdict = evaluatePin({
    pinnerUserId: deps.selfUserId,
    pinnerSigningPublicKey: own,
    pinnedUserId: userId,
    pin: pins.get(userId),
    served,
  })
  if (verdict === 'mismatch' || verdict === 'bad-signature') {
    return { ok: false, reason: 'blocked' }
  }
  if (verdict === 'first-sight') {
    const keys = servedSigningKeySet(served)
    if (keys === null) {
      return { ok: false, reason: 'blocked' }
    }
    try {
      await deps.pinKeys(userId, keys.map(bytesToBase64), served.wrappingPublicKey)
    } catch (err) {
      return {
        ok: false,
        reason: 'unavailable',
        detail: `could not pin ${userId}: ${describe(err)}`,
      }
    }
  }
  return { ok: true, wrappingPublicKey: served.wrappingPublicKey }
}
