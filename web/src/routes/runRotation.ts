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
//     stops the run. A member removed in an EARLIER rotation is covered by the
//     signed removal record on every GENKEY# chain link below the caller's own
//     generation (lib/crypto/removal): a missing or forged one stops the run,
//     and a removed member needs an admission signed at or after the removal's
//     generation to be a recipient again (DESIGN.md, "The recipient set is
//     taken from the server").
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
  KeychainResponse,
  ListAdmissionsResponse,
  MemberEntry,
  RewrapEntry,
  TakeOverRotationRequest,
} from '@/lib/api/groups'
import { MAX_REWRAP_BATCH } from '@/lib/api/groups'
import type { UserProjection } from '@/lib/api/users'
import { verifyAdmission, type AdmissionRecord } from '@/lib/crypto/admission'
import { base64ToBytes, bytesToBase64 } from '@/lib/crypto/base64'
import { SigningContext, verify } from '@/lib/crypto/ed25519'
import { rotationStartPayload } from '@/lib/crypto/group'
import { removersOf, verifyRemovals } from '@/lib/crypto/removal'
import { evaluatePin, servedSigningKeySet, type PinRecord } from '@/lib/crypto/pin'
import type {
  RewrapGroupKeyResult,
  StartGroupRotationRequest,
  StartGroupRotationResult,
} from '@/lib/crypto/worker-protocol'
import { loadVerifiedChain, type GrantCheckDeps, type VerifiedChain } from './runGrantCheck'

/** Passes before giving up. A pass is a full re-list, so this bounds churn, not batches. */
const MAX_PASSES = 6

export interface RotationDeps extends Omit<GrantCheckDeps, 'getUsers'> {
  readonly selfUserId: string
  /** Every admission record of the group, one page at a time (#178). */
  readonly listAdmissions: (groupId: string, cursor?: string) => Promise<ListAdmissionsResponse>
  readonly getGroup: (groupId: string) => Promise<GroupDetail>
  /** The GENKEY# chain links for generations from..to inclusive, one page at a time (#178). */
  readonly getKeychain: (groupId: string, from: number, to: number) => Promise<KeychainResponse>
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
  /**
   * Mints the key of a rotation a LEAVING member started (#178): the same
   * startGroupRotation a removal uses, naming the leaver.
   */
  readonly takeOverCrypto: (
    req: Omit<StartGroupRotationRequest, 'kind' | 'id'>,
  ) => Promise<StartGroupRotationResult>
  /** Replaces the leaver's bare marker with the rotation `takeOverCrypto` minted. */
  readonly takeOverRotation: (groupId: string, req: TakeOverRotationRequest) => Promise<void>
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
          `${unadmitted.map(label).join(', ')} ${unadmitted.length === 1 ? 'is' : 'are'} listed as ${unadmitted.length === 1 ? 'a member' : 'members'} but no admin or ambassador's signed invitation backs them (for someone removed earlier, one made after the removal).`,
        )
      }
      return {
        kind: 'error',
        text: `Key rotation is paused. ${parts.join(' ')} They were NOT given the new group key. Check with them another way before relying on this group.${unadmitted.length > 0 ? ' To clear an unadmitted member, an admin can remove them and invite them again.' : ''}`,
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
  if (
    marker !== undefined &&
    marker.generation === ownGeneration + 1 &&
    marker.removedUserId !== undefined &&
    marker.startedBy === marker.removedUserId &&
    !restarted
  ) {
    // A member left and started this rotation (#178), but minted no key: that is
    // this admin's to do. Carry on from fresh state afterwards.
    const taken = await takeOverLeave(deps, groupId, detail, marker, carried)
    if (taken.status !== 'continue') return taken.outcome
    return runOnce(deps, groupId, true, carried, exclude)
  }
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
            const loaded = await loadAdmissions(deps, own, groupId, ownGeneration)
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

type TakeOver =
  { readonly status: 'continue' } | { readonly status: 'done'; readonly outcome: RotationOutcome }

/**
 * A member LEFT and started this rotation (#178), but the rotation has no key:
 * the leaver signs that they are the member removed and nothing else, because a
 * key they minted is a key a hostile leaver keeps. The first admin at the
 * leaver's generation to load the group mints it here, exactly as a remover
 * would, naming the leaver, and the run carries on to re-wrap everyone else.
 *
 *   - The marker's signed start must verify as the leaver's own (it names them
 *     as removed, signed by them); an unverifiable marker is never taken over.
 *   - Two admins racing settle on the server: the loser's takeover is refused
 *     (`rotation_not_active`), they re-read, and are re-wrapped like any member.
 *
 * 'continue' means the caller re-reads the group and carries on.
 */
async function takeOverLeave(
  deps: RotationDeps,
  groupId: string,
  detail: GroupDetail,
  marker: NonNullable<GroupDetail['rotation']>,
  carried: number,
): Promise<TakeOver> {
  const done = (outcome: RotationOutcome): TakeOver => ({ status: 'done', outcome })
  const incomplete = (reason: string): TakeOver =>
    done({ status: 'incomplete', reason, rewrapped: carried })
  const ownWrapped = detail.wrappedGroupKey
  if (ownWrapped === undefined) return done({ status: 'none' })

  let own: Uint8Array
  try {
    own = base64ToBytes(await deps.ownSigningKey())
  } catch (err) {
    return incomplete(`could not read your pins: ${describe(err)}`)
  }
  const started = await verifyRotationStart(deps, own, groupId, marker)
  if (!started.ok) return incomplete(started.reason)

  // The start only proves the leaver's key signed it, and the leaver's key is
  // whatever the server serves. This path turns the marker into the CALLER'S
  // signature naming them as removed, so a key seen for the first time is not
  // enough: without this a server can fake a leave for any member the caller
  // has not pinned (PR #209 round 3).
  const trusted = await checkLeaverKey(deps, own, groupId, detail.generation, marker)
  if (!trusted.ok) return incomplete(trusted.reason)

  // A lost race on the transaction (`conflict_retry`) can leave the marker
  // unclaimed, so it gets one more try before giving up.
  for (let attempt = 1; ; attempt++) {
    try {
      const minted = await deps.takeOverCrypto({
        userId: deps.selfUserId,
        groupId,
        ownWrappedGroupKey: ownWrapped,
        ownGeneration: detail.generation,
        subjectUserId: started.removedUserId,
      })
      await deps.takeOverRotation(groupId, {
        generation: minted.generation,
        link: minted.link,
        wrappedKey: minted.removerWrappedKey,
        startSignature: minted.startSignature,
      })
      return { status: 'continue' }
    } catch (err) {
      const code = codeOf(err)
      if (code === 'rotation_not_active') {
        return { status: 'continue' } // another admin got there first; read it again
      }
      if (code === 'conflict_retry') {
        if (attempt < 2) continue
        return incomplete('the group was busy while taking over the rotation; run again')
      }
      return incomplete(describe(err))
    }
  }
}

/**
 * Whether the key that signed the leaver's start is one the caller has a reason
 * to trust, before the caller signs a removal of them on its strength. The
 * start's signature must verify under a key that is trusted for a reason that
 * does not rest on what the server merely served:
 *   - the caller's signed pin of them (which pins the whole served set); or
 *   - for the creator, the key the verified anchor names; or
 *   - for anyone else, the invitee key on an admission that verifies against
 *     the verified grant chain for the keys served now (the leave keeps that
 *     record for this check; the takeover deletes it).
 * It is the SPECIFIC key that must verify, not "some served key": an unpinned
 * member's served set includes superseded keys the server asserts without
 * proof, so a fabricated one could sign the start while the member's real key
 * keeps their admission valid. A key seen for the first time with none of the
 * above behind it is refused: a server withholding a member can already stall
 * a group, so failing closed costs nothing new, while trusting it lets the
 * server pick who the caller signs the removal of (PR #209 round 3).
 */
async function checkLeaverKey(
  deps: RotationDeps,
  own: Uint8Array,
  groupId: string,
  ownGeneration: number,
  marker: NonNullable<GroupDetail['rotation']>,
): Promise<{ readonly ok: true } | { readonly ok: false; readonly reason: string }> {
  const leaverId = marker.removedUserId
  const startSignature = marker.startSignature
  if (leaverId === undefined || startSignature === undefined) {
    return { ok: false, reason: "the rotation's signed start record is missing" }
  }
  const refuse = (why: string) =>
    ({
      ok: false,
      reason: `the member who left has no pin of yours and no valid admission behind the key that signed their leaving, so it was not taken over (${why})`,
    }) as const
  const signature = base64ToBytes(startSignature)
  const payload = rotationStartPayload(groupId, marker.startedBy, leaverId, marker.generation)
  const signedBy = (keys: readonly Uint8Array[]): boolean =>
    keys.some((k) => verify(k, SigningContext.RotationStart, payload, signature))

  let served: UserProjection | undefined
  let pins: readonly PinRecord[]
  try {
    served = (await deps.getUsers([leaverId])).get(leaverId)
    pins = await deps.listPins()
  } catch (err) {
    return {
      ok: false,
      reason: `could not check the keys of the member who left: ${describe(err)}`,
    }
  }
  if (served === undefined) return refuse('their keys could not be fetched')
  const verdict = evaluatePin({
    pinnerUserId: deps.selfUserId,
    pinnerSigningPublicKey: own,
    pinnedUserId: leaverId,
    pin: pins.find((p) => p.pinnedUserId === leaverId),
    served,
  })
  const servedKeys = servedSigningKeySet(served)
  if (verdict === 'match') {
    return servedKeys !== null && signedBy(servedKeys)
      ? { ok: true }
      : refuse('the start was not signed by a pinned key')
  }
  if (verdict !== 'first-sight') return refuse('their keys do not match your pin')

  const loaded = await loadAdmissions(deps, own, groupId, ownGeneration)
  if (!loaded.ok) return { ok: false, reason: loaded.reason }
  const { context } = loaded
  if (context.removedAt.has(leaverId)) return refuse('the removal history already lists them')
  if (leaverId === context.chain.anchor.creatorUserId) {
    // The creator has no admission: the anchor (trusted at this point, as for
    // a recipient) names their key.
    return signedBy([base64ToBytes(context.chain.anchor.creatorSigningPublicKey)])
      ? { ok: true }
      : refuse("the start was not signed by the key the group's anchor names")
  }
  if (!isAdmitted(context, groupId, leaverId, served)) {
    return refuse('no admission signed for the keys served for them')
  }
  const record = context.byInvitee.get(leaverId)
  return record !== undefined && signedBy([base64ToBytes(record.inviteeEd25519PublicKey)])
    ? { ok: true }
    : refuse('the start was not signed by the key their admission names')
}

/** The records and the verified chain a pass checks recipients against. */
interface AdmissionContext {
  readonly chain: VerifiedChain
  readonly byInvitee: ReadonlyMap<string, AdmissionRecord>
  /** Whom the signed removal history says was removed, and at which generation (#178). */
  readonly removedAt: ReadonlyMap<string, number>
}

// A list this deep means the server is not honoring nextCursor; stop.
const MAX_ADMISSION_PAGES = 100

async function loadAdmissions(
  deps: RotationDeps,
  own: Uint8Array,
  groupId: string,
  ownGeneration: number,
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
    // Only a CHANGED anchor or an unverifiable root stops the run: a first
    // sighting is trusted, as in the roster, so on a browser that has never
    // seen this group the check rests on trust on first use (DESIGN.md, "What
    // stays open"). Failing closed on first sight would not help: opening the
    // members screen first takes the same pin.
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
    const removals = await loadRemovals(deps, own, groupId, ownGeneration)
    if (!removals.ok) return { ok: false, reason: removals.reason }
    return {
      ok: true,
      context: {
        chain,
        byInvitee: new Map(records.map((r) => [r.inviteeUserId, r])),
        removedAt: removals.removedAt,
      },
    }
  } catch (err) {
    return { ok: false, reason: `could not check who admitted the members: ${describe(err)}` }
  }
}

/**
 * Whether a recipient was admitted: the creator (the anchor, which the caller
 * trusts at this point) or a member with a record that verifies against the
 * chain and the keys the server serves for them now. Someone the signed
 * removal history says was removed (at generation g) must also hold an
 * admission signed at generation g or later, i.e. a fresh invitation after the
 * removal: their old record still verifies, and a server that re-lists them is
 * otherwise indistinguishable from a rejoin (#178). That includes the creator,
 * who is exempt only while nobody removed them.
 */
function isAdmitted(
  ctx: AdmissionContext,
  groupId: string,
  userId: string,
  served: UserProjection,
): boolean {
  const removedAt = ctx.removedAt.get(userId)
  if (userId === ctx.chain.anchor.creatorUserId && removedAt === undefined) return true
  const record = ctx.byInvitee.get(userId)
  const signingKeys = servedSigningKeySet(served)
  if (record === undefined || signingKeys === null) return false
  if (removedAt !== undefined && record.generation < removedAt) return false
  return verifyAdmission({
    groupId,
    record,
    inviteeSigningKeys: signingKeys,
    inviteeWrappingKey: served.wrappingPublicKey,
    chain: ctx.chain.result,
    inviterHistory: ctx.chain.keyHistories.get(record.inviterUserId),
  }).ok
}

type SignerKeys =
  | { readonly ok: true; readonly keys: ReadonlyMap<string, Uint8Array[] | null> }
  | { readonly ok: false; readonly reason: string }

/**
 * The signing keys to try for each signer of a record the rotation relies on,
 * fetched in one batch. The caller's own key is its current one, with no fetch
 * (#62: only the CURRENT key. Once signing keys can rotate, a signer who
 * rotated mid-rotation signed under a superseded key, and as the only admin at
 * this generation nobody could resume; take the served set, as for anyone
 * else, before that ships; this now also covers every removal the caller ever
 * signed, which live forever, so the fix is not scoped to resuming a rotation).
 * Anyone else's come from the server, checked against
 * the caller's pin: a mismatch stops the run, a first sighting is accepted (as
 * in the roster: a forged signature can only ever shrink the recipient set). A
 * signer whose keys cannot be fetched stops it too. `who` names them in the
 * reason.
 */
async function resolveSignerKeys(
  deps: RotationDeps,
  own: Uint8Array,
  signers: readonly string[],
  who: string,
): Promise<SignerKeys> {
  const keys = new Map<string, Uint8Array[] | null>()
  const others = signers.filter((id) => id !== deps.selfUserId)
  if (signers.includes(deps.selfUserId)) keys.set(deps.selfUserId, [own])
  if (others.length === 0) return { ok: true, keys }

  const failure: { err?: unknown } = {}
  const served = await deps.getUsers(others, (err) => {
    failure.err = err
  })
  let pins: readonly PinRecord[]
  try {
    pins = await deps.listPins()
  } catch (err) {
    return { ok: false, reason: `could not read your pins: ${describe(err)}` }
  }
  for (const id of others) {
    const projection = served.get(id)
    if (projection === undefined) {
      return {
        ok: false,
        reason:
          failure.err === undefined
            ? `could not fetch the keys of ${who} (${id})`
            : `could not fetch the keys of ${who}: ${describe(failure.err)}`,
      }
    }
    const verdict = evaluatePin({
      pinnerUserId: deps.selfUserId,
      pinnerSigningPublicKey: own,
      pinnedUserId: id,
      pin: pins.find((p) => p.pinnedUserId === id),
      served: projection,
    })
    if (verdict === 'mismatch' || verdict === 'bad-signature') {
      return { ok: false, reason: `the keys served for ${who} do not match your pin` }
    }
    keys.set(id, servedSigningKeySet(projection))
  }
  return { ok: true, keys }
}

// A chain this long means the server is not honoring nextFrom; stop.
const MAX_KEYCHAIN_PAGES = 100

type RemovalCheck =
  | { readonly ok: true; readonly removedAt: ReadonlyMap<string, number> }
  | { readonly ok: false; readonly reason: string }

/**
 * Loads and verifies the group's removal history from the GENKEY# chain (#178):
 * a signed record for every generation below the caller's own. A missing,
 * blank or forged one stops the run, because carrying on would take the
 * server's word that nobody was ever removed. The caller's generation is
 * authenticated by the AAD of its own wrapped key, so the server cannot
 * understate it to hide the newest removals.
 */
async function loadRemovals(
  deps: RotationDeps,
  own: Uint8Array,
  groupId: string,
  currentGeneration: number,
): Promise<RemovalCheck> {
  if (currentGeneration === 0) return { ok: true, removedAt: new Map() }
  const links: KeychainResponse['links'][number][] = []
  try {
    let from = 0
    for (let page = 0; ; page++) {
      if (page >= MAX_KEYCHAIN_PAGES) throw new Error('key chain pagination did not terminate')
      const res = await deps.getKeychain(groupId, from, currentGeneration - 1)
      links.push(...res.links)
      if (res.nextFrom === undefined) break
      if (res.nextFrom <= from) throw new Error('key chain pagination did not advance')
      from = res.nextFrom
    }
  } catch (err) {
    return { ok: false, reason: `could not read the group's removal history: ${describe(err)}` }
  }
  const signers = await resolveSignerKeys(
    deps,
    own,
    removersOf(links),
    'an admin who removed a member',
  )
  if (!signers.ok) return signers
  const verdict = verifyRemovals({
    groupId,
    currentGeneration,
    links,
    keysFor: (id) => signers.keys.get(id) ?? null,
  })
  return verdict.ok ? { ok: true, removedAt: verdict.removedAt } : verdict
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

  const resolved = await resolveSignerKeys(
    deps,
    own,
    [marker.startedBy],
    'the admin who started this rotation',
  )
  if (!resolved.ok) return resolved
  const keys = resolved.keys.get(marker.startedBy) ?? null
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
