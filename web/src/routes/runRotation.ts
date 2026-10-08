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
//     add its own account, or keep listing a removed member. For the removed
//     member, the rotation marker carries a signature by the admin who started
//     it naming whom they removed, and a resuming admin excludes that member
//     whatever the list says (#178); a marker with no verifiable signature
//     stops the run. What stays open is the server hiding the marker itself
//     (DESIGN.md, "The recipient set is taken from the server").
//   - Nor does the pin check say anyone ADMITTED the recipient: a first-sight
//     account is trusted and pinned. So before a recipient is pinned or wrapped
//     to, the inviter's signed admission of them is checked against the
//     verified grant chain (#178; lib/crypto/admission). The creator is the
//     one member with none. A recipient with no valid admission is skipped and
//     reported, never pinned and never wrapped to, so a server cannot add an
//     account of its own and be handed the new group key. FAILS CLOSED: a
//     chain that cannot be read or verified stops the run.
//
// Plain function over injected deps, like runGrantCheck.ts, so it tests against
// stubs without a worker or the network.

import { ApiError } from '@/lib/api/auth'
import type {
  GroupDetail,
  ListAdmissionsResponse,
  MemberEntry,
  RewrapEntry,
} from '@/lib/api/groups'
import { MAX_REWRAP_BATCH } from '@/lib/api/groups'
import type { UserProjection } from '@/lib/api/users'
import { verifyAdmission, type AdmissionRecord } from '@/lib/crypto/admission'
import { base64ToBytes, bytesToBase64 } from '@/lib/crypto/base64'
import { SigningContext, verify } from '@/lib/crypto/ed25519'
import { rotationStartPayload } from '@/lib/crypto/group'
import { evaluatePin, servedSigningKeySet, type PinRecord } from '@/lib/crypto/pin'
import type { RewrapGroupKeyResult } from '@/lib/crypto/worker-protocol'
import { loadVerifiedChain, type GrantCheckDeps, type VerifiedChain } from './runGrantCheck'

/** Passes before giving up. A pass is a full re-list, so this bounds churn, not batches. */
const MAX_PASSES = 6

export interface RotationDeps extends Omit<GrantCheckDeps, 'getUsers'> {
  readonly selfUserId: string
  /** Every admission record of the group, one page at a time (#178). */
  readonly listAdmissions: (groupId: string, cursor?: string) => Promise<ListAdmissionsResponse>
  readonly getGroup: (groupId: string) => Promise<GroupDetail>
  /** Every member, following nextCursor. */
  readonly listAllMembers: (groupId: string) => Promise<readonly MemberEntry[]>
  /** Every readable user among the ids, in one batch call; an absent id could not be fetched. */
  readonly getUsers: (
    userIds: readonly string[],
    onError?: (err: unknown) => void,
  ) => Promise<ReadonlyMap<string, UserProjection>>
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
      /**
       * Members no valid inviter-signed admission backs (#178), also NOT
       * wrapped to. Absent when there are none.
       */
      readonly unadmitted?: readonly string[]
      readonly rewrapped: number
    }
  /** The caller is an admin but not at the rotation's generation: another admin who is must resume. */
  | { readonly status: 'cannot-resume'; readonly reason: string }
  /** Stopped before finishing (network, churn, unreadable pins); safe to run again. */
  | { readonly status: 'incomplete'; readonly reason: string; readonly rewrapped: number }

/**
 * What to tell the admin about an outcome, or null when there is nothing to
 * say (the common case on every admin load). `label` turns a user id into a
 * name for the people a pin check blocked.
 */
export function describeRotation(
  outcome: RotationOutcome,
  label: (userId: string) => string,
): { readonly kind: 'info' | 'error'; readonly text: string } | null {
  const people = (n: number): string => `${String(n)} ${n === 1 ? 'member' : 'members'}`
  switch (outcome.status) {
    case 'none':
      return null
    case 'completed':
      return {
        kind: 'info',
        text:
          outcome.rewrapped > 0
            ? `Key rotation finished: ${people(outcome.rewrapped)} moved to the new group key.`
            : 'Key rotation finished.',
      }
    case 'caught-up':
      return {
        kind: 'info',
        text: `${people(outcome.rewrapped)} who had fallen behind ${outcome.rewrapped === 1 ? 'was' : 'were'} moved to the current group key.`,
      }
    case 'blocked': {
      const parts: string[] = []
      if (outcome.blocked.length > 0) {
        parts.push(
          `The keys the server shows for ${outcome.blocked.map(label).join(', ')} don't match the copy you saved earlier.`,
        )
      }
      const unadmitted = outcome.unadmitted ?? []
      if (unadmitted.length > 0) {
        parts.push(
          `${unadmitted.map(label).join(', ')} ${unadmitted.length === 1 ? 'is' : 'are'} listed as ${unadmitted.length === 1 ? 'a member' : 'members'} but no admin or ambassador's signed invitation backs ${unadmitted.length === 1 ? 'them' : 'it'}.`,
        )
      }
      return {
        kind: 'error',
        text: `Key rotation is paused. ${parts.join(' ')} They were NOT given the new group key. Check with them another way before relying on this group.`,
      }
    }
    case 'cannot-resume':
      return {
        kind: 'info',
        text: 'A key rotation is running, and it has to be finished by an admin who already holds the new key.',
      }
    case 'incomplete':
      return {
        kind: 'error',
        text: `Key rotation stopped (${outcome.reason}). It resumes the next time an admin opens this group.`,
      }
  }
}

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
export async function runRotation(
  deps: RotationDeps,
  groupId: string,
  opts: RotationOptions = {},
): Promise<RotationOutcome> {
  return runOnce(deps, groupId, false, 0, opts.exclude ?? NO_USERS)
}

export interface RotationOptions {
  /**
   * Users the caller just removed. They are never wrapped to, even if the
   * server still lists them (it is the server's list that cannot be trusted,
   * issue #178). The rotation then cannot complete while the server insists
   * they are behind, which fails safe. The rotation marker's signed record of
   * whom its remover removed is excluded the same way, so an admin resuming
   * later is covered without having to be told.
   */
  readonly exclude?: ReadonlySet<string>
}

const NO_USERS: ReadonlySet<string> = new Set()

async function runOnce(
  deps: RotationDeps,
  groupId: string,
  restarted: boolean,
  carried: number,
  exclude: ReadonlySet<string>,
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

  // Whom the rotation's own remover says they removed (#178), checked before
  // anything is wrapped. Added to what the caller already excludes.
  if (marker !== undefined) {
    const started = await verifyRotationStart(deps, own, groupId, marker)
    if (!started.ok) {
      return { status: 'incomplete', reason: started.reason, rewrapped: carried }
    }
    exclude = new Set([...exclude, started.removedUserId])
  }

  const blocked = new Set<string>()
  // Members no valid admission backs (#178): skipped like a pin mismatch.
  const unadmitted = new Set<string>()
  let rewrapped = carried

  for (let pass = 0; pass < MAX_PASSES; pass++) {
    // Loaded the first time a pass has a recipient to check, then reused for
    // the pass; a fresh pass re-reads it, so a member who joined meanwhile
    // is judged on current records.
    let admissions: AdmissionContext | undefined
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
          m.userId !== deps.selfUserId &&
          m.generation < ownGeneration &&
          !blocked.has(m.userId) &&
          !unadmitted.has(m.userId) &&
          !exclude.has(m.userId),
      ),
    )

    if (behind.length === 0) {
      if (blocked.size > 0 || unadmitted.size > 0) {
        return {
          status: 'blocked',
          blocked: [...blocked],
          ...(unadmitted.size > 0 && { unadmitted: [...unadmitted] }),
          rewrapped,
        }
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
      // One batch read for the chunk's keys, before any first-sight pin is
      // written: the same keys the per-recipient reads would have returned.
      let fetchFailure: unknown
      const servedKeys = await deps.getUsers(
        chunk.map((m) => m.userId),
        (err) => {
          fetchFailure = err
        },
      )
      for (const m of chunk) {
        // Before the pin check, which would trust and pin a first-sight key:
        // an account nobody admitted must not even be pinned (#178). One whose
        // keys could not be fetched is left to checkRecipient ("unavailable").
        const servedForM = servedKeys.get(m.userId)
        if (servedForM !== undefined) {
          if (admissions === undefined) {
            const loaded = await loadAdmissions(deps, groupId)
            if (!loaded.ok) {
              return { status: 'incomplete', reason: loaded.reason, rewrapped }
            }
            admissions = loaded.context
          }
          if (!isAdmitted(admissions, groupId, m.userId, servedForM)) {
            unadmitted.add(m.userId)
            continue
          }
        }
        const verdict = await checkRecipient(
          deps,
          own,
          pins,
          m.userId,
          servedKeys.get(m.userId),
          fetchFailure,
        )
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
          return runOnce(deps, groupId, true, rewrapped, exclude)
        }
        return { status: 'incomplete', reason: describe(err), rewrapped }
      }
    }
  }
  return { status: 'incomplete', reason: 'the group kept changing; run again', rewrapped }
}

/** The records and the verified chain a pass checks recipients against. */
interface AdmissionContext {
  readonly chain: VerifiedChain
  readonly byInvitee: ReadonlyMap<string, AdmissionRecord>
}

// A list this deep means the server is not honoring nextCursor; stop.
const MAX_ADMISSION_PAGES = 100

async function loadAdmissions(
  deps: RotationDeps,
  groupId: string,
): Promise<
  | { readonly ok: true; readonly context: AdmissionContext }
  | { readonly ok: false; readonly reason: string }
> {
  try {
    const records: AdmissionRecord[] = []
    let cursor: string | undefined
    for (let page = 0; ; page++) {
      if (page >= MAX_ADMISSION_PAGES) throw new Error('admission pagination did not terminate')
      const res = await deps.listAdmissions(groupId, cursor)
      records.push(...res.admissions)
      if (!res.nextCursor) break
      cursor = res.nextCursor
    }
    // Inviters may have signed no grant, so their key histories are asked for
    // by name; loadVerifiedChain pin-checks them like any grantor's.
    const chain = await loadVerifiedChain(deps, groupId, [
      ...new Set(records.map((r) => r.inviterUserId)),
    ])
    if (chain.anchorState === 'changed') {
      return {
        ok: false,
        reason: 'the group anchor changed since you first saw it, so admissions cannot be checked',
      }
    }
    if (chain.anchorState === 'root-unverified') {
      return {
        ok: false,
        reason: "the group's root grant could not be verified, so admissions cannot be checked",
      }
    }
    return {
      ok: true,
      context: { chain, byInvitee: new Map(records.map((r) => [r.inviteeUserId, r])) },
    }
  } catch (err) {
    return { ok: false, reason: `could not check who admitted the members: ${describe(err)}` }
  }
}

/**
 * Whether a recipient was admitted: the creator (the anchor, which the caller
 * trusts at this point) or a member with a record that verifies against the
 * chain and the keys the server serves for them now.
 */
function isAdmitted(
  ctx: AdmissionContext,
  groupId: string,
  userId: string,
  served: UserProjection,
): boolean {
  if (userId === ctx.chain.anchor.creatorUserId) return true
  const record = ctx.byInvitee.get(userId)
  const signingKeys = servedSigningKeySet(served)
  if (record === undefined || signingKeys === null) return false
  return verifyAdmission({
    groupId,
    record,
    inviteeSigningKeys: signingKeys,
    inviteeWrappingKey: served.wrappingPublicKey,
    chain: ctx.chain.result,
    inviterHistory: ctx.chain.keyHistories.get(record.inviterUserId),
  }).ok
}

type RotationStartCheck =
  | { readonly ok: true; readonly removedUserId: string }
  | { readonly ok: false; readonly reason: string }

/**
 * Checks the marker's signed record of whose removal started the rotation. The
 * signer is the admin named in `startedBy`, and their keys come from the
 * server like any recipient's, so a pin that disagrees with what is served
 * stops the run (a first sighting is accepted, as in the roster: the signature
 * can only ever shrink the recipient set). A marker with no signature, or one
 * that does not verify, is not trusted and the rotation does not run: carrying
 * on without it would wrap to whoever the server lists.
 */
async function verifyRotationStart(
  deps: RotationDeps,
  own: Uint8Array,
  groupId: string,
  marker: NonNullable<GroupDetail['rotation']>,
): Promise<RotationStartCheck> {
  const { removedUserId, startSignature } = marker
  if (removedUserId === undefined || startSignature === undefined) {
    return {
      ok: false,
      reason:
        'this rotation was started without a signed record of who was removed, so it cannot be resumed safely',
    }
  }
  let signature: Uint8Array
  try {
    signature = base64ToBytes(startSignature)
  } catch {
    return { ok: false, reason: "the rotation's signed start record is malformed" }
  }
  const payload = rotationStartPayload(groupId, marker.startedBy, removedUserId, marker.generation)

  let keys: Uint8Array[] | null
  if (marker.startedBy === deps.selfUserId) {
    // #62: only the CURRENT key. Once signing keys can rotate, a starter who
    // rotated mid-rotation signed under a superseded key, and as the only
    // admin at this generation nobody could resume; take the served set (as the
    // other branch does) before that ships.
    keys = [own]
  } else {
    const failure: { err?: unknown } = {}
    const served = (
      await deps.getUsers([marker.startedBy], (err) => {
        failure.err = err
      })
    ).get(marker.startedBy)
    if (served === undefined) {
      return {
        ok: false,
        reason:
          failure.err === undefined
            ? `could not fetch the keys of the admin who started this rotation (${marker.startedBy})`
            : `could not fetch the keys of the admin who started this rotation: ${describe(failure.err)}`,
      }
    }
    let pin: PinRecord | undefined
    try {
      pin = (await deps.listPins()).find((p) => p.pinnedUserId === marker.startedBy)
    } catch (err) {
      return { ok: false, reason: `could not read your pins: ${describe(err)}` }
    }
    const verdict = evaluatePin({
      pinnerUserId: deps.selfUserId,
      pinnerSigningPublicKey: own,
      pinnedUserId: marker.startedBy,
      pin,
      served,
    })
    if (verdict === 'mismatch' || verdict === 'bad-signature') {
      return {
        ok: false,
        reason: 'the keys served for the admin who started this rotation do not match your pin',
      }
    }
    keys = servedSigningKeySet(served)
  }
  if (
    keys === null ||
    !keys.some((k) => verify(k, SigningContext.RotationStart, payload, signature))
  ) {
    return { ok: false, reason: "the rotation's signed start record does not verify" }
  }
  return { ok: true, removedUserId }
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
  served: UserProjection | undefined,
  fetchFailure?: unknown,
): Promise<RecipientCheck> {
  if (served === undefined) {
    return {
      ok: false,
      reason: 'unavailable',
      detail:
        fetchFailure === undefined
          ? `could not fetch keys for ${userId}`
          : `could not fetch keys for ${userId}: ${describe(fetchFailure)}`,
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
