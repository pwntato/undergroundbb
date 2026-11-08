// Requests to join a PUBLIC group (#72). The server half is internal/handlers/join_request.go; this is
// the part only a client can do.
//
// A join request is NOT an invite. An invite's acceptance carries a MAC under a secret that travels in
// the link, so a server that swaps keys cannot forge one. A stranger has no link, so a first request
// from someone the approver has never seen is TRUST ON FIRST USE (docs/THREAT_MODEL.md). What protects
// the group is therefore this client, not the server's own check:
//
//   - the requester's signature is verified HERE, over the exact keys the approver is shown;
//   - the keys are checked against the approver's pins: a mismatch blocks, only 'match' and
//     'first-sight' proceed (an allowlist, so a verdict added later cannot fall through);
//   - the keys the server serves for the requester now must be the keys they signed;
//   - the fingerprint is ALWAYS shown and confirmed before the group key is wrapped, and the wrap
//     happens only if freshly checked keys still produce exactly the fingerprint that was confirmed.
//
// Plain functions over injected deps, like runReadmit.ts, so they test against stubs.

import { ApiError } from '@/lib/api/auth'
import type { GroupDetail } from '@/lib/api/groups'
import type {
  ApproveJoinRequestBody,
  CreateJoinRequestBody,
  JoinRequestEntry,
} from '@/lib/api/joinRequests'
import type { UserProjection } from '@/lib/api/users'
import { base64ToBytes, bytesToBase64 } from '@/lib/crypto/base64'
import * as ed25519 from '@/lib/crypto/ed25519'
import { fingerprint } from '@/lib/crypto/fingerprint'
import { joinRequestPayload } from '@/lib/crypto/joinRequest'
import { evaluatePin, servedSigningKeySet } from '@/lib/crypto/pin'
import type {
  SignJoinRequestRequest,
  SignJoinRequestResult,
  SignReadmissionRequest,
  SignReadmissionResult,
} from '@/lib/crypto/worker-protocol'
import { ownHistoryFor } from './ownHistory'
import { CLOCK_SKEW_MESSAGE } from './replyState'
import { isLiveKeysError } from './runListGroups'
import type { RotationDeps } from './runRotation'

// ---------------------------------------------------------------------------------------------
// The requester's side
// ---------------------------------------------------------------------------------------------

export interface RequestToJoinDeps {
  readonly selfUserId: string
  readonly signJoinRequest: (
    req: Omit<SignJoinRequestRequest, 'kind' | 'id'>,
  ) => Promise<SignJoinRequestResult>
  readonly createJoinRequest: (groupId: string, body: CreateJoinRequestBody) => Promise<unknown>
  /** A fresh random UUID. */
  readonly newRequestId: () => string
}

export type RequestToJoinResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly kind: RequestToJoinFailureKind; readonly message: string }

export type RequestToJoinFailureKind =
  | 'alreadyMember'
  | 'pending'
  | 'coolingOff'
  | 'keysChanged'
  | 'notFound'
  | 'authRequired'
  | 'coldKeys'
  | 'rejected'
  | 'ambiguous'

function fail(kind: RequestToJoinFailureKind, message: string): RequestToJoinResult {
  return { ok: false, kind, message }
}

/** Signs and sends a request to join `groupId` as the caller. */
export async function runRequestToJoin(
  deps: RequestToJoinDeps,
  groupId: string,
): Promise<RequestToJoinResult> {
  const requestId = deps.newRequestId()
  let signed: SignJoinRequestResult
  try {
    signed = await deps.signJoinRequest({ userId: deps.selfUserId, groupId, requestId })
  } catch (err) {
    return isLiveKeysError(err)
      ? fail('coldKeys', 'This tab needs your password again before it can send a request.')
      : fail('rejected', "Couldn't sign the request. Try again.")
  }
  try {
    await deps.createJoinRequest(groupId, { requestId, signature: signed.signature })
    return { ok: true }
  } catch (err) {
    if (err instanceof ApiError) {
      switch (err.code) {
        case 'already_member':
          return fail('alreadyMember', 'You are already a member of this group.')
        case 'request_pending':
          return fail('pending', 'You already have a request waiting for this group.')
        case 'request_cooling_off':
          // The server's text names the day the cool-off ends.
          return fail('coolingOff', err.message)
        case 'keys_changed':
          return fail('keysChanged', 'Your keys changed while this was sent. Reload and try again.')
      }
      if (err.status === 401) return fail('authRequired', 'Your session has expired. Log in again.')
      if (err.status === 404) return fail('notFound', 'This group is not open to requests.')
      if (err.status < 500) return fail('rejected', err.message)
    }
    return fail('ambiguous', "We couldn't confirm the request was sent. Check My requests first.")
  }
}

export interface WithdrawDeps {
  readonly withdrawJoinRequest: (groupId: string) => Promise<void>
}

export type SimpleResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly message: string; readonly authRequired?: true }

function simpleFailure(err: unknown, fallback: string): SimpleResult {
  if (err instanceof ApiError) {
    if (err.status === 401) {
      return { ok: false, message: 'Your session has expired. Log in again.', authRequired: true }
    }
    if (err.status < 500) return { ok: false, message: err.message }
  }
  return { ok: false, message: fallback }
}

/** Takes back the caller's own pending request. A declined one cannot be withdrawn. */
export async function runWithdrawJoinRequest(
  deps: WithdrawDeps,
  groupId: string,
): Promise<SimpleResult> {
  try {
    await deps.withdrawJoinRequest(groupId)
    return { ok: true }
  } catch (err) {
    return simpleFailure(err, "Couldn't withdraw the request. Try again.")
  }
}

// ---------------------------------------------------------------------------------------------
// The approver's side
// ---------------------------------------------------------------------------------------------

export interface JoinApprovalDeps extends RotationDeps {
  readonly signReadmission: (
    req: Omit<SignReadmissionRequest, 'kind' | 'id'>,
  ) => Promise<SignReadmissionResult>
  readonly approveJoinRequest: (
    groupId: string,
    requesterUserId: string,
    body: ApproveJoinRequestBody,
  ) => Promise<void>
  readonly denyJoinRequest: (groupId: string, requesterUserId: string) => Promise<void>
  /** The clock, ms since the epoch; the admission is dated by its UTC day. Defaults to Date.now. */
  readonly now?: () => number
}

export type JoinApprovalFailure =
  /** The signature on the request does not verify over the keys it carries: nothing was wrapped. */
  | { readonly kind: 'badSignature' }
  /** The keys differ from the copy you saved of this person: blocked, nothing was wrapped. */
  | { readonly kind: 'pinMismatch' }
  /** The keys the server serves for them now are not the keys they signed. They must ask again. */
  | { readonly kind: 'requesterKeysChanged' }
  /** The fingerprint you confirmed is not the one their keys give now. */
  | { readonly kind: 'keysChanged' }
  | { readonly kind: 'alreadyMember' }
  /** The group is at its member limit. The request stays pending. */
  | { readonly kind: 'groupFull' }
  /** The requester withdrew and asked again since you loaded the list. */
  | { readonly kind: 'requestChanged' }
  /** The request is gone (withdrawn, expired, or handled by someone else). */
  | { readonly kind: 'gone' }
  | { readonly kind: 'forbidden' }
  | { readonly kind: 'deleted' }
  | { readonly kind: 'authRequired' | 'coldKeys' }
  /** A key rotation is running; approving waits for it to finish. */
  | { readonly kind: 'rotationRunning' }
  /** The group or your standing moved: reload and decide again. */
  | { readonly kind: 'stale' }
  /** What decides this could not be read, so nothing was wrapped or sent. */
  | { readonly kind: 'unchecked'; readonly reason: string }
  | { readonly kind: 'rejected'; readonly message: string }
  /** The write may or may not have landed. */
  | { readonly kind: 'ambiguous' }

type Fail = { readonly ok: false } & JoinApprovalFailure

export type PrepareJoinApprovalResult =
  { readonly ok: true; readonly fingerprint: string; readonly firstSight: boolean } | Fail

export type JoinApprovalResult = { readonly ok: true } | Fail

type Inspection =
  | {
      readonly ok: true
      readonly served: UserProjection
      readonly signingKeys: readonly Uint8Array[]
      readonly firstSight: boolean
      readonly fingerprint: string
    }
  | Fail

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

function sameKey(a: string, b: string): boolean {
  try {
    return bytesToBase64(base64ToBytes(a)) === bytesToBase64(base64ToBytes(b))
  } catch {
    return false
  }
}

/**
 * Everything that decides whether this request may be approved, read fresh. Nothing is written.
 * The order matters: the signature first (a request that does not verify is never shown), then the
 * pin, then that the served keys are the signed ones.
 */
async function inspect(
  deps: JoinApprovalDeps,
  groupId: string,
  request: JoinRequestEntry,
): Promise<Inspection> {
  if (request.userId === deps.selfUserId) {
    return { ok: false, kind: 'rejected', message: 'You cannot approve your own request.' }
  }
  let edKey: Uint8Array
  let xKey: Uint8Array
  let signature: Uint8Array
  try {
    edKey = base64ToBytes(request.ed25519PublicKey)
    xKey = base64ToBytes(request.x25519PublicKey)
    signature = base64ToBytes(request.signature)
  } catch {
    return { ok: false, kind: 'badSignature' }
  }
  const payload = joinRequestPayload(request.requestId, groupId, request.userId, edKey, xKey)
  if (!ed25519.verify(edKey, ed25519.SigningContext.JoinRequest, payload, signature)) {
    return { ok: false, kind: 'badSignature' }
  }

  let own: Uint8Array
  let served: UserProjection | undefined
  let pins
  try {
    own = base64ToBytes(await deps.ownSigningKey())
    let failure: unknown
    served = (
      await deps.getUsers([request.userId], (err) => {
        failure = err
      })
    ).get(request.userId)
    if (served === undefined && failure !== undefined) throw failure
    pins = await deps.listPins()
  } catch (err) {
    return { ok: false, kind: 'unchecked', reason: `could not read their keys: ${describe(err)}` }
  }
  if (served === undefined) return { ok: false, kind: 'gone' }
  if (served.deleted === true) return { ok: false, kind: 'deleted' }

  const signingKeys = servedSigningKeySet(served)
  if (signingKeys === null) {
    return { ok: false, kind: 'unchecked', reason: 'the keys served for them are malformed' }
  }
  const verdict = evaluatePin({
    pinnerUserId: deps.selfUserId,
    pinnerSigningPublicKey: own,
    pinnerHistory: await ownHistoryFor(deps, own),
    pinnedUserId: request.userId,
    pin: pins.find((p) => p.pinnedUserId === request.userId),
    served,
  })
  // An allowlist, so a verdict added later (rollback was) cannot fall through.
  if (verdict !== 'match' && verdict !== 'first-sight') {
    return { ok: false, kind: 'pinMismatch' }
  }
  // The wrap goes to the keys they signed, and the server refuses it unless those are still their
  // current keys. Check that here too, so a request signed under old keys is never confirmed.
  if (
    !sameKey(served.signingPublicKey, request.ed25519PublicKey) ||
    !sameKey(served.wrappingPublicKey, request.x25519PublicKey)
  ) {
    return { ok: false, kind: 'requesterKeysChanged' }
  }
  return {
    ok: true,
    served,
    signingKeys,
    firstSight: verdict === 'first-sight',
    // Of the keys the requester SIGNED, which the check above made equal to the served ones.
    fingerprint: fingerprint(edKey, xKey),
  }
}

/**
 * The checks that come before showing a fingerprint: a request that fails them is refused here, so
 * the approver is never asked to confirm one. Returns the fingerprint of the signed keys.
 */
export async function prepareJoinApproval(
  deps: JoinApprovalDeps,
  groupId: string,
  request: JoinRequestEntry,
): Promise<PrepareJoinApprovalResult> {
  const found = await inspect(deps, groupId, request)
  return found.ok
    ? { ok: true, fingerprint: found.fingerprint, firstSight: found.firstSight }
    : found
}

const STALE_CODES = new Set(['grantor_ref_stale', 'grantor_changed', 'conflict_retry'])

/**
 * Approves `request`. Everything is re-read and re-checked, so a list the approver was looking at a
 * while ago decides nothing; `confirmedFingerprint` is what they compared with the requester, and the
 * group key is wrapped only if the keys checked NOW still give exactly that fingerprint.
 */
export async function runApproveJoinRequest(
  deps: JoinApprovalDeps,
  groupId: string,
  request: JoinRequestEntry,
  confirmedFingerprint: string,
): Promise<JoinApprovalResult> {
  const found = await inspect(deps, groupId, request)
  if (!found.ok) return found
  if (found.fingerprint !== confirmedFingerprint) return { ok: false, kind: 'keysChanged' }

  let detail: GroupDetail
  try {
    detail = await deps.getGroup(groupId)
  } catch (err) {
    const failure = failureOf(err)
    return failure.kind === 'ambiguous'
      ? { ok: false, kind: 'unchecked', reason: `could not load the group: ${describe(err)}` }
      : failure
  }
  if (detail.role !== 'admin' && detail.role !== 'ambassador') {
    return { ok: false, kind: 'forbidden' }
  }
  // A running rotation moves every entry; a wrap made mid-way is for a generation about to change.
  if (detail.rotation !== undefined) return { ok: false, kind: 'rotationRunning' }
  const ownWrapped = detail.wrappedGroupKey
  if (ownWrapped === undefined) {
    return { ok: false, kind: 'unchecked', reason: 'your own copy of the group key is missing' }
  }
  const grantRef = detail.myGrantSortKey ?? ''
  if (grantRef === '') {
    return { ok: false, kind: 'unchecked', reason: 'your own grant is not on record' }
  }

  if (found.firstSight) {
    // Pin what was confirmed, so a later swap is caught and a rotation that follows checks the same
    // keys this wrap went to.
    try {
      await deps.pinKeys(
        request.userId,
        found.signingKeys.map(bytesToBase64),
        found.served.wrappingPublicKey,
        found.served.keyEpoch,
      )
    } catch (err) {
      return { ok: false, kind: 'unchecked', reason: `could not save their keys: ${describe(err)}` }
    }
  }

  let wrappedKey
  try {
    const wrapped = await deps.rewrapCrypto({
      userId: deps.selfUserId,
      groupId,
      ownWrappedGroupKey: ownWrapped,
      ownGeneration: detail.generation,
      // The key they signed: found.served's keys were just checked equal to it.
      recipients: [{ userId: request.userId, x25519PublicKey: request.x25519PublicKey }],
    })
    wrappedKey = wrapped.wraps.find((w) => w.userId === request.userId)?.wrappedKey
  } catch (err) {
    return signFailure(err)
  }
  if (wrappedKey === undefined) {
    return { ok: false, kind: 'rejected', message: "Couldn't wrap the group key. Try again." }
  }

  // The admission carries the REQUEST id in the invite-id slot: it is the only id this person's
  // entry into the group has.
  let admission: SignReadmissionResult
  const day = new Date((deps.now ?? Date.now)()).toISOString().slice(0, 10)
  try {
    admission = await deps.signReadmission({
      userId: deps.selfUserId,
      groupId,
      subjectUserId: request.userId,
      subjectEd25519PublicKey: request.ed25519PublicKey,
      subjectX25519PublicKey: request.x25519PublicKey,
      inviteId: request.requestId,
      inviterGrantRef: grantRef,
      day,
      generation: detail.generation,
    })
  } catch (err) {
    return signFailure(err)
  }

  try {
    await deps.approveJoinRequest(groupId, request.userId, {
      requestId: request.requestId,
      wrappedGroupKey: wrappedKey,
      generation: detail.generation,
      admission: {
        inviterGrantRef: admission.inviterGrantRef,
        day: admission.day,
        signature: admission.signature,
      },
    })
    return { ok: true }
  } catch (err) {
    return failureOf(err)
  }
}

function signFailure(err: unknown): Fail {
  return isLiveKeysError(err)
    ? { ok: false, kind: 'coldKeys' }
    : { ok: false, kind: 'rejected', message: "Couldn't sign this approval. Try again." }
}

function failureOf(err: unknown): Fail {
  if (err instanceof ApiError) {
    switch (err.code) {
      case 'group_full':
        return { ok: false, kind: 'groupFull' }
      case 'requester_keys_changed':
        return { ok: false, kind: 'requesterKeysChanged' }
      case 'already_member':
        return { ok: false, kind: 'alreadyMember' }
      case 'request_changed':
        return { ok: false, kind: 'requestChanged' }
      case 'requester_deleted':
        return { ok: false, kind: 'deleted' }
      case 'bad_signature':
        // The server holds different keys for them than the ones signed over.
        return { ok: false, kind: 'requesterKeysChanged' }
      case 'clock_skew':
        return { ok: false, kind: 'rejected', message: CLOCK_SKEW_MESSAGE }
    }
    if (err.code !== undefined && STALE_CODES.has(err.code)) return { ok: false, kind: 'stale' }
    if (err.status === 401) return { ok: false, kind: 'authRequired' }
    if (err.status === 403) return { ok: false, kind: 'forbidden' }
    if (err.status === 404) return { ok: false, kind: 'gone' }
    if (err.status === 410) return { ok: false, kind: 'deleted' }
    if (err.status < 500) return { ok: false, kind: 'rejected', message: err.message }
  }
  return { ok: false, kind: 'ambiguous' }
}

/** Declines a request. The requester can ask again after the server's cool-off. */
export async function runDenyJoinRequest(
  deps: Pick<JoinApprovalDeps, 'denyJoinRequest'>,
  groupId: string,
  requesterUserId: string,
): Promise<SimpleResult> {
  try {
    await deps.denyJoinRequest(groupId, requesterUserId)
    return { ok: true }
  } catch (err) {
    return simpleFailure(err, "Couldn't decline the request. Try again.")
  }
}

const FAILURE_MESSAGES: Record<
  Exclude<JoinApprovalFailure['kind'], 'rejected' | 'unchecked'>,
  string
> = {
  badSignature:
    "This request's signature does not verify over the keys it carries, so nothing was wrapped.",
  pinMismatch:
    "The keys shown for them don't match the copy you saved earlier, so nothing was wrapped. Check with them another way.",
  requesterKeysChanged:
    'Their keys changed since they asked, so nothing was wrapped. They need to ask again.',
  keysChanged:
    'Their keys are not the ones whose fingerprint you confirmed, so nothing was wrapped. Start again and compare the new fingerprint with them.',
  alreadyMember: 'They are already a member of this group.',
  groupFull:
    'This group is at its member limit. The request stays waiting; try again once someone has left.',
  requestChanged:
    'They withdrew and asked again since you loaded the list. The latest requests are shown; check the new one.',
  gone: 'That request is gone: it was withdrawn, expired, or handled by someone else.',
  forbidden: 'Only a group admin or ambassador can approve requests.',
  deleted: 'That account was deleted.',
  authRequired: 'Your session has expired. Log in again and retry.',
  coldKeys: 'This tab needs your password again to approve requests.',
  rotationRunning: 'A key rotation is running. Approving waits for it to finish.',
  stale: 'The group changed while you were working, so nothing was saved. Try again.',
  ambiguous:
    "We couldn't confirm whether the approval was saved. The latest requests are shown; check before trying again.",
}

export function joinApprovalFailureMessage(outcome: Fail): string {
  if (outcome.kind === 'rejected') return outcome.message
  if (outcome.kind === 'unchecked') {
    return `Nothing was wrapped, because what decides this could not be checked (${outcome.reason}).`
  }
  return FAILURE_MESSAGES[outcome.kind]
}

/** Whether the request list should be reloaded after an approval attempt. */
export function shouldReloadAfterJoinApproval(outcome: JoinApprovalResult): boolean {
  return (
    outcome.ok ||
    outcome.kind === 'requestChanged' ||
    outcome.kind === 'gone' ||
    outcome.kind === 'alreadyMember' ||
    outcome.kind === 'requesterKeysChanged' ||
    outcome.kind === 'deleted' ||
    outcome.kind === 'ambiguous'
  )
}
