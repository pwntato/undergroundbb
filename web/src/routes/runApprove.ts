// Approving a dormant member's new keys (#62, docs/DESIGN.md, "Approval: what
// the admin does, and when it mints"). A member who rotated their account keys
// stays in the group but their entry is still wrapped to the key they replaced.
// An admin or ambassador approves them in one of two ways, and the SERVER decides
// which one is allowed:
//
//   - POST rewrap/{uid}: a plain wrap of the approver's current group key to the
//     member's new key. Open groups always; Rotating groups when the member's
//     entry is behind the approver's generation.
//   - POST rotation/approve/{uid}: a re-key that mints a new generation, because
//     the member's entry is at the approver's generation and the keys they
//     replaced still hold the current key. Admin only, Rotating only.
//
// The client picks from the roster and falls back on the server's
// `rekey_required` / `rekey_not_required`, so a roster that moved on between the
// read and the write still lands on the right endpoint.
//
//   - The fingerprint is ALWAYS confirmed, as for a re-admission: the caller
//     compares it with the member out of band, and this signs and wraps only if
//     freshly served keys still produce that exact fingerprint.
//   - The wrapping key and the keyEpoch the server stamps on the entry come from
//     ONE projection, read once and pin-checked. Nothing else ties them together.
//   - A pin that does not match blocks. Only 'match' and 'first-sight' proceed
//     (an allowlist: a verdict added later must not fall through).
//   - A reply that does not say whether the write landed is settled by reading
//     the member's entry again, never by assuming.
//
// Plain functions over injected deps, like runReadmit.ts.

import { ApiError } from '@/lib/api/auth'
import type {
  ApproveRekeyRequest,
  ApproveRewrapRequest,
  GroupDetail,
  MemberEntry,
} from '@/lib/api/groups'
import type { UserProjection } from '@/lib/api/users'
import { base64ToBytes, bytesToBase64 } from '@/lib/crypto/base64'
import { evaluatePin, servedSigningKeySet } from '@/lib/crypto/pin'
import type {
  RewrapGroupKeyResult,
  StartApprovalRekeyRequest,
  StartApprovalRekeyResult,
} from '@/lib/crypto/worker-protocol'
import { ownHistoryFor } from './ownHistory'
import { servedFingerprint } from './runMemberVerification'
import { isLiveKeysError } from './runListGroups'
import type { RotationDeps } from './runRotation'

export interface ApproveDeps extends RotationDeps {
  readonly approveRewrap: (
    groupId: string,
    memberUserId: string,
    req: ApproveRewrapRequest,
  ) => Promise<void>
  readonly approveRekey: (
    groupId: string,
    memberUserId: string,
    req: ApproveRekeyRequest,
  ) => Promise<void>
  readonly startApprovalCrypto: (
    req: Omit<StartApprovalRekeyRequest, 'kind' | 'id'>,
  ) => Promise<StartApprovalRekeyResult>
}

export type ApproveFailure =
  /** The keys the server serves for them differ from your saved copy. */
  | { readonly kind: 'pinMismatch' }
  /** The fingerprint you confirmed is not the one their served keys give now. */
  | { readonly kind: 'keysChanged' }
  | { readonly kind: 'forbidden' }
  | { readonly kind: 'authRequired' | 'notFound' | 'deleted' | 'coldKeys' }
  /** Their entry is already wrapped to their current keys: nothing to approve. */
  | { readonly kind: 'notDormant' }
  /** This approval needs a new group key, which only an admin can mint. */
  | { readonly kind: 'askAdmin' }
  /** A key rotation is running; approving waits for it to finish. */
  | { readonly kind: 'rotationRunning' }
  /** The group or the caller's standing moved: reload and decide again. */
  | { readonly kind: 'stale' }
  /** What decides this could not be read, so nothing was signed or sent. */
  | { readonly kind: 'unchecked'; readonly reason: string }
  | { readonly kind: 'rejected'; readonly message: string }
  /** The write may or may not have landed and a re-read did not settle it. */
  | { readonly kind: 'ambiguous' }

export type PrepareApproveResult =
  { readonly ok: true; readonly fingerprint: string } | ({ readonly ok: false } & ApproveFailure)

export type ApproveResult =
  | {
      readonly ok: true
      /**
       * 'rewrap' and 'rekey' are the two writes; 'already' means the server or a
       * re-read showed the member was approved before this call. A 'rekey'
       * leaves a rotation running that the caller's job must finish.
       */
      readonly how: 'rewrap' | 'rekey' | 'already'
    }
  | ({ readonly ok: false } & ApproveFailure)

type Fail = { readonly ok: false } & ApproveFailure

const STALE_CODES = new Set(['conflict_retry', 'rotation_caller_behind', 'key_epoch_stale'])

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

function codeOf(err: unknown): string | undefined {
  return err instanceof ApiError ? err.code : undefined
}

/** Whether `member`'s entry is wrapped to a key older than the one `served` carries. */
function isDormant(member: MemberEntry, served: UserProjection): boolean {
  return member.wrapEpoch !== undefined && member.wrapEpoch < served.keyEpoch
}

type Inspection =
  | {
      readonly ok: true
      readonly detail: GroupDetail
      readonly served: UserProjection
      readonly signingKeys: readonly Uint8Array[]
      readonly firstSight: boolean
      readonly fingerprint: string
      readonly entry: MemberEntry
    }
  | Fail

/**
 * Everything that decides whether and how this member may be approved, read
 * fresh. Nothing is written.
 */
async function inspect(
  deps: ApproveDeps,
  groupId: string,
  subjectUserId: string,
): Promise<Inspection> {
  if (subjectUserId === deps.selfUserId) {
    return { ok: false, kind: 'rejected', message: 'You cannot approve your own key change.' }
  }
  let detail: GroupDetail
  try {
    detail = await deps.getGroup(groupId)
  } catch (err) {
    return readFailure(err, `could not load the group: ${describe(err)}`)
  }
  if (detail.role !== 'admin' && detail.role !== 'ambassador') {
    return { ok: false, kind: 'forbidden' }
  }

  let own: Uint8Array
  let served: UserProjection | undefined
  let pins
  let members: readonly MemberEntry[]
  try {
    own = base64ToBytes(await deps.ownSigningKey())
    let failure: unknown
    served = (
      await deps.getUsers([subjectUserId], (err) => {
        failure = err
      })
    ).get(subjectUserId)
    if (served === undefined && failure !== undefined) throw failure
    pins = await deps.listPins()
    members = await deps.listAllMembers(groupId)
  } catch (err) {
    return { ok: false, kind: 'unchecked', reason: `could not read their keys: ${describe(err)}` }
  }
  if (served === undefined) return { ok: false, kind: 'notFound' }
  if (served.deleted === true) return { ok: false, kind: 'deleted' }
  const entry = members.find((m) => m.userId === subjectUserId)
  if (entry === undefined) return { ok: false, kind: 'notFound' }
  if (!isDormant(entry, served)) return { ok: false, kind: 'notDormant' }

  const signingKeys = servedSigningKeySet(served)
  const print = servedFingerprint(served)
  if (signingKeys === null || print === null) {
    return { ok: false, kind: 'unchecked', reason: 'the keys served for them are malformed' }
  }
  const verdict = evaluatePin({
    pinnerUserId: deps.selfUserId,
    pinnerSigningPublicKey: own,
    pinnerHistory: await ownHistoryFor(deps, own),
    pinnedUserId: subjectUserId,
    pin: pins.find((p) => p.pinnedUserId === subjectUserId),
    served,
  })
  // An allowlist, so a verdict added later (rollback was) cannot fall through.
  if (verdict !== 'match' && verdict !== 'first-sight') return { ok: false, kind: 'pinMismatch' }

  return {
    ok: true,
    detail,
    served,
    signingKeys,
    firstSight: verdict === 'first-sight',
    fingerprint: print,
    entry,
  }
}

/** A failed READ: nothing was signed or sent, so it is never ambiguous. */
function readFailure(err: unknown, reason: string): Fail {
  const failure = failureOf(err)
  return failure.kind === 'ambiguous' ? { ok: false, kind: 'unchecked', reason } : failure
}

function failureOf(err: unknown): Fail {
  if (err instanceof ApiError) {
    if (err.code === 'subject_deleted') return { ok: false, kind: 'deleted' }
    if (err.code !== undefined && STALE_CODES.has(err.code)) return { ok: false, kind: 'stale' }
    if (err.status === 401) return { ok: false, kind: 'authRequired' }
    if (err.status === 403) return { ok: false, kind: 'forbidden' }
    if (err.status === 404) return { ok: false, kind: 'notFound' }
    if (err.status < 500) return { ok: false, kind: 'rejected', message: err.message }
  }
  return { ok: false, kind: 'ambiguous' }
}

/**
 * The checks that come before showing a fingerprint, so the caller is never
 * asked to confirm one for a member who cannot be approved. Returns the
 * fingerprint of the keys the server serves for them now.
 */
export async function prepareApprove(
  deps: ApproveDeps,
  groupId: string,
  subjectUserId: string,
): Promise<PrepareApproveResult> {
  const found = await inspect(deps, groupId, subjectUserId)
  return found.ok ? { ok: true, fingerprint: found.fingerprint } : found
}

/**
 * Approves subjectUserId. Everything is re-read and re-checked, so a roster the
 * caller was looking at a while ago decides nothing; `confirmedFingerprint` is
 * what the caller confirmed with the member.
 */
export async function runApprove(
  deps: ApproveDeps,
  groupId: string,
  subjectUserId: string,
  confirmedFingerprint: string,
): Promise<ApproveResult> {
  const found = await inspect(deps, groupId, subjectUserId)
  if (!found.ok) return found
  if (found.fingerprint !== confirmedFingerprint) return { ok: false, kind: 'keysChanged' }
  const { detail, served, entry } = found
  // A running rotation moves every entry; an approval against a half-moved
  // group would be wrapped for a generation about to change.
  if (detail.rotation !== undefined) return { ok: false, kind: 'rotationRunning' }
  const ownWrapped = detail.wrappedGroupKey
  if (ownWrapped === undefined) {
    return { ok: false, kind: 'unchecked', reason: 'your own copy of the group key is missing' }
  }

  // Which write to try first. An Open group has no re-key, so it always wraps.
  const mustMint = detail.revocationMode === 'rotating' && entry.generation >= detail.generation
  if (mustMint && detail.role !== 'admin') return { ok: false, kind: 'askAdmin' }

  if (found.firstSight) {
    // Pin what was confirmed, so a later swap is caught and the wrap below goes
    // to the keys this fingerprint covers.
    try {
      await deps.pinKeys(
        subjectUserId,
        found.signingKeys.map(bytesToBase64),
        served.wrappingPublicKey,
        served.keyEpoch,
      )
    } catch (err) {
      return { ok: false, kind: 'unchecked', reason: `could not save their keys: ${describe(err)}` }
    }
  }

  const ctx: Context = { deps, groupId, subjectUserId, detail, served, ownWrapped }
  const first = mustMint ? tryRekey : tryRewrap
  const second = mustMint ? tryRewrap : tryRekey
  const result = await first(ctx)
  if (result === 'fallback') {
    // The server disagrees with the roster about which write applies. An
    // ambassador cannot mint, so they are told to ask an admin.
    if (second === tryRekey && detail.role !== 'admin') return { ok: false, kind: 'askAdmin' }
    const again = await second(ctx)
    return again === 'fallback' ? { ok: false, kind: 'stale' } : again
  }
  return result
}

interface Context {
  readonly deps: ApproveDeps
  readonly groupId: string
  readonly subjectUserId: string
  readonly detail: GroupDetail
  readonly served: UserProjection
  readonly ownWrapped: NonNullable<GroupDetail['wrappedGroupKey']>
}

type Attempt = ApproveResult | 'fallback'

async function tryRewrap(ctx: Context): Promise<Attempt> {
  const { deps, groupId, subjectUserId, detail, served } = ctx
  let wrapped: RewrapGroupKeyResult
  try {
    wrapped = await deps.rewrapCrypto({
      userId: deps.selfUserId,
      groupId,
      ownWrappedGroupKey: ctx.ownWrapped,
      ownGeneration: detail.generation,
      recipients: [{ userId: subjectUserId, x25519PublicKey: served.wrappingPublicKey }],
    })
  } catch (err) {
    return signFailure(err)
  }
  const wrappedKey = wrapped.wraps.find((w) => w.userId === subjectUserId)?.wrappedKey
  if (wrappedKey === undefined) {
    return { ok: false, kind: 'rejected', message: "Couldn't wrap the group key. Try again." }
  }
  try {
    await deps.approveRewrap(groupId, subjectUserId, {
      generation: detail.generation,
      wrappedKey,
      keyEpoch: served.keyEpoch,
    })
    return { ok: true, how: 'rewrap' }
  } catch (err) {
    switch (codeOf(err)) {
      case 'rekey_required':
        return 'fallback'
      case 'member_not_dormant':
        return { ok: true, how: 'already' }
      case 'wrap_epoch_stale':
        return { ok: false, kind: 'keysChanged' }
    }
    // A code-less 400 is the generation no longer matching the caller's entry:
    // a resend after the first request landed looks the same, so look.
    if (err instanceof ApiError && err.status === 400 && err.code === undefined) {
      return settle(ctx)
    }
    const failure = failureOf(err)
    return failure.kind === 'ambiguous' ? settle(ctx) : failure
  }
}

async function tryRekey(ctx: Context): Promise<Attempt> {
  const { deps, groupId, subjectUserId, detail, served } = ctx
  if (detail.role !== 'admin') return { ok: false, kind: 'askAdmin' }
  let minted: StartApprovalRekeyResult
  try {
    minted = await deps.startApprovalCrypto({
      userId: deps.selfUserId,
      groupId,
      ownWrappedGroupKey: ctx.ownWrapped,
      ownGeneration: detail.generation,
      memberUserId: subjectUserId,
      memberWrappingPublicKey: served.wrappingPublicKey,
    })
  } catch (err) {
    return signFailure(err)
  }
  try {
    await deps.approveRekey(groupId, subjectUserId, {
      generation: minted.generation,
      link: minted.link,
      wrappedKey: minted.removerWrappedKey,
      startSignature: minted.startSignature,
      memberWrappedKey: minted.memberWrappedKey,
      memberKeyEpoch: served.keyEpoch,
    })
    return { ok: true, how: 'rekey' }
  } catch (err) {
    switch (codeOf(err)) {
      case 'rekey_not_required':
        return 'fallback'
      case 'member_not_dormant':
        return { ok: true, how: 'already' }
      case 'wrap_epoch_stale':
        return { ok: false, kind: 'keysChanged' }
      case 'rotation_in_progress':
        return { ok: false, kind: 'rotationRunning' }
    }
    // A resent start is a code-less 400 on the generation (the first one moved
    // the caller's own entry), whether its rotation is running or done.
    if (err instanceof ApiError && err.status === 400 && err.code === undefined) {
      return settle(ctx)
    }
    const failure = failureOf(err)
    return failure.kind === 'ambiguous' ? settle(ctx) : failure
  }
}

function signFailure(err: unknown): Fail {
  return isLiveKeysError(err)
    ? { ok: false, kind: 'coldKeys' }
    : { ok: false, kind: 'rejected', message: "Couldn't prepare this approval. Try again." }
}

/**
 * A write whose outcome is unknown: read the member's entry again. Approved
 * means their entry now carries a wrap epoch at or past the keyEpoch served;
 * anything else, including a failed read, stays ambiguous.
 */
async function settle(ctx: Context): Promise<Attempt> {
  const { deps, groupId, subjectUserId } = ctx
  try {
    const members = await deps.listAllMembers(groupId)
    const entry = members.find((m) => m.userId === subjectUserId)
    if (entry === undefined) return { ok: false, kind: 'notFound' }
    const served = (await deps.getUsers([subjectUserId])).get(subjectUserId)
    if (served === undefined) return { ok: false, kind: 'ambiguous' }
    return isDormant(entry, served)
      ? { ok: false, kind: 'ambiguous' }
      : { ok: true, how: 'already' }
  } catch {
    return { ok: false, kind: 'ambiguous' }
  }
}

const FAILURE_MESSAGES: Record<
  Exclude<ApproveFailure['kind'], 'rejected' | 'unchecked'>,
  string
> = {
  pinMismatch:
    "The keys the server shows for them don't match the copy you saved earlier, so nothing was approved. Check with them another way.",
  keysChanged:
    'Their keys are not the ones whose fingerprint you confirmed, so nothing was approved. Start again and compare the new fingerprint with them.',
  forbidden: 'Only a group admin or ambassador can approve a key change.',
  authRequired: 'Your session has expired. Log in again and retry.',
  notFound: 'This member or group no longer exists.',
  deleted: "That member's account was deleted.",
  coldKeys: 'This tab needs your password again to approve a key change.',
  notDormant: 'Their keys are already approved here.',
  askAdmin:
    'Approving them needs a new key for the whole group, which only an admin can make. Ask an admin to approve them.',
  rotationRunning: 'A key rotation is running. Wait for it to finish, then approve them.',
  stale:
    'The group changed while you were working, so nothing was saved. The latest roster is shown; try again.',
  ambiguous:
    "We couldn't confirm whether the approval was saved. The latest roster is shown; check it before trying again.",
}

export function approveFailureMessage(outcome: Fail): string {
  if (outcome.kind === 'rejected') return outcome.message
  if (outcome.kind === 'unchecked') {
    return `Nothing was approved, because what decides this could not be checked (${outcome.reason}).`
  }
  return FAILURE_MESSAGES[outcome.kind]
}

/** Whether the roster should be reloaded after an approval attempt. */
export function shouldReloadAfterApprove(outcome: ApproveResult): boolean {
  return (
    outcome.ok ||
    outcome.kind === 'stale' ||
    outcome.kind === 'ambiguous' ||
    outcome.kind === 'notDormant' ||
    outcome.kind === 'rotationRunning'
  )
}
