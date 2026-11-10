// Direct messages (#73). The server half is internal/handlers/dm.go; this is the part only a client
// can do, and it is where the trust decisions live.
//
// A DM has no invite link, so the first one between two people is TRUST ON FIRST USE, exactly like a
// join request (docs/THREAT_MODEL.md): nothing but the fingerprint the two people compare tells a
// real account from one the server invented. So BOTH clients show the other person's fingerprint
// before anything irreversible, and neither relies on the server's own checks:
//
//   - the sender's client shows the RECIPIENT's fingerprint before it wraps the group key or signs the
//     admission (the admission signs the recipient's keys as the server serves them);
//   - the recipient's client verifies the SENDER's admission signature, checks the sender's keys
//     against its pins, checks the admission names its own keys, and shows the sender's fingerprint
//     before it calls accept.
//
// Both sides use an allowlist on the pin verdict (match / first-sight), so a verdict added later
// cannot fall through, and both re-read and re-check everything at the moment of the irreversible
// step: a fingerprint confirmed earlier decides nothing unless the keys checked NOW still produce it.
//
// Plain functions over injected deps, like runJoinRequests.ts, so they test against stubs.

import { ApiError } from '@/lib/api/auth'
import { DMExistsError } from '@/lib/api/dms'
import type { CreateDMBody, IncomingDM } from '@/lib/api/dms'
import type { CreateGroupRequest, CreateGroupResponse } from '@/lib/api/groups'
import type { UserProjection } from '@/lib/api/users'
import { base64ToBytes, bytesToBase64 } from '@/lib/crypto/base64'
import * as ed25519 from '@/lib/crypto/ed25519'
import { fingerprint } from '@/lib/crypto/fingerprint'
import { admissionPayload } from '@/lib/crypto/group'
import { evaluatePin, servedSigningKeySet } from '@/lib/crypto/pin'
import type {
  SignGroupCreationResult,
  SignReadmissionRequest,
  SignReadmissionResult,
} from '@/lib/crypto/worker-protocol'
import { ownHistoryFor } from './ownHistory'
import { CLOCK_SKEW_MESSAGE } from './replyState'
import { isLiveKeysError } from './runListGroups'
import type { RotationDeps } from './runRotation'

type PersonDeps = Pick<
  RotationDeps,
  | 'selfUserId'
  | 'getUsers'
  | 'listPins'
  | 'pinKeys'
  | 'ownSigningKey'
  | 'loadOwnKeyHistory'
  | 'ownKeyHistoryFailure'
>

// ---------------------------------------------------------------------------------------------
// Looking at the other person (both sides)
// ---------------------------------------------------------------------------------------------

/** Why the other person's keys cannot be used, shared by both sides. */
export type PersonFailure =
  /** The keys differ from the copy you saved of this person: blocked. */
  | { readonly kind: 'pinMismatch' }
  /** The fingerprint you confirmed is not the one their keys give now. */
  | { readonly kind: 'keysChanged' }
  /** No such account (or it could not be read as one). */
  | { readonly kind: 'gone' }
  | { readonly kind: 'deleted' }
  | { readonly kind: 'self' }
  /** What decides this could not be read, so nothing was wrapped, signed or sent. */
  | { readonly kind: 'unchecked'; readonly reason: string }

type Inspected =
  | {
      readonly ok: true
      readonly served: UserProjection
      readonly signingKeys: readonly Uint8Array[]
      readonly firstSight: boolean
      /** Of the CURRENT keys the server serves for them. */
      readonly fingerprint: string
    }
  | ({ readonly ok: false } & PersonFailure)

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/** Reads the person's keys fresh and checks them against the caller's pins. Writes nothing. */
async function inspectPerson(deps: PersonDeps, userId: string): Promise<Inspected> {
  if (userId === deps.selfUserId) return { ok: false, kind: 'self' }
  let own: Uint8Array
  let served: UserProjection | undefined
  let pins
  try {
    own = base64ToBytes(await deps.ownSigningKey())
    let failure: unknown
    served = (
      await deps.getUsers([userId], (err) => {
        failure = err
      })
    ).get(userId)
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
  let ed: Uint8Array
  let x: Uint8Array
  try {
    ed = base64ToBytes(served.signingPublicKey)
    x = base64ToBytes(served.wrappingPublicKey)
  } catch {
    return { ok: false, kind: 'unchecked', reason: 'the keys served for them are malformed' }
  }
  const verdict = evaluatePin({
    pinnerUserId: deps.selfUserId,
    pinnerSigningPublicKey: own,
    pinnerHistory: await ownHistoryFor(deps, own),
    pinnedUserId: userId,
    pin: pins.find((p) => p.pinnedUserId === userId),
    served,
  })
  // An allowlist, so a verdict added later (rollback was) cannot fall through.
  if (verdict !== 'match' && verdict !== 'first-sight') return { ok: false, kind: 'pinMismatch' }
  let print: string
  try {
    print = fingerprint(ed, x)
  } catch {
    return { ok: false, kind: 'unchecked', reason: 'the keys served for them are malformed' }
  }
  return { ok: true, served, signingKeys, firstSight: verdict === 'first-sight', fingerprint: print }
}

/** Saves what was just confirmed, so a later swap is caught. Returns a failure to report, or null. */
async function pinFirstSight(
  deps: PersonDeps,
  userId: string,
  found: Extract<Inspected, { ok: true }>,
): Promise<PersonFailure | null> {
  if (!found.firstSight) return null
  try {
    await deps.pinKeys(
      userId,
      found.signingKeys.map(bytesToBase64),
      found.served.wrappingPublicKey,
      found.served.keyEpoch,
    )
    return null
  } catch (err) {
    return { kind: 'unchecked', reason: `could not save their keys: ${describe(err)}` }
  }
}

// ---------------------------------------------------------------------------------------------
// The sender's side
// ---------------------------------------------------------------------------------------------

export type StartDMFailure =
  | PersonFailure
  /** A conversation with them already exists. */
  | { readonly kind: 'exists'; readonly groupId: string }
  /** They declined; the server's text names the day you can try again. */
  | { readonly kind: 'coolingOff'; readonly message: string }
  | { readonly kind: 'tooManyPending' }
  /** Their keys changed between the fingerprint you were shown and the send: nothing was sent. */
  | { readonly kind: 'recipientKeysChanged' }
  /** Something changed while it was being sent; trying again is safe. */
  | { readonly kind: 'conflict' }
  /** Your own admission was refused: this tab holds keys that are no longer your current ones. */
  | { readonly kind: 'authRequired' | 'coldKeys' }
  | { readonly kind: 'accountDeleted' }
  | { readonly kind: 'rejected'; readonly message: string }
  /** The write may or may not have landed. The same material may be sent again. */
  | { readonly kind: 'ambiguous' }

type StartFail = { readonly ok: false } & StartDMFailure

export type PrepareDMResult =
  { readonly ok: true; readonly fingerprint: string; readonly firstSight: boolean } | StartFail

export interface StartDMDeps extends PersonDeps {
  readonly signGroupCreation: (req: {
    readonly userId: string
    readonly groupId: string
    readonly groupKey: string
  }) => Promise<SignGroupCreationResult>
  readonly rewrapCrypto: RotationDeps['rewrapCrypto']
  readonly signReadmission: (
    req: Omit<SignReadmissionRequest, 'kind' | 'id'>,
  ) => Promise<SignReadmissionResult>
  readonly createDM: (req: CreateGroupRequest) => Promise<CreateGroupResponse>
  /** The clock, ms since the epoch; the admission is dated by its UTC day. Defaults to Date.now. */
  readonly now?: () => number
}

/** The ids and key a send uses, kept by the screen so a retry after a lost response reuses them. */
export interface DMMaterial {
  readonly groupId: string
  /** Base64 of the 32-byte Generation 0 group key. */
  readonly groupKeyB64: string
  readonly requestId: string
}

/**
 * The checks that come before showing a fingerprint: a person who fails them is refused here, so the
 * sender is never asked to confirm one. Returns the fingerprint of the keys the server serves now.
 */
export async function prepareStartDM(
  deps: PersonDeps,
  recipientUserId: string,
): Promise<PrepareDMResult> {
  const found = await inspectPerson(deps, recipientUserId)
  return found.ok
    ? { ok: true, fingerprint: found.fingerprint, firstSight: found.firstSight }
    : found
}

export type StartDMResult =
  | { readonly ok: true; readonly groupId: string }
  | StartFail

/**
 * Starts a DM with `recipientUserId`. Everything is re-read and re-checked, so a screen the sender
 * was looking at a while ago decides nothing; `confirmedFingerprint` is what they compared with the
 * recipient, and the group key is wrapped and the admission signed only if the keys checked NOW still
 * give exactly that fingerprint.
 */
export async function runStartDM(
  deps: StartDMDeps,
  recipientUserId: string,
  confirmedFingerprint: string,
  material: DMMaterial,
  expirationDays: number,
): Promise<StartDMResult> {
  const found = await inspectPerson(deps, recipientUserId)
  if (!found.ok) return found
  if (found.fingerprint !== confirmedFingerprint) return { ok: false, kind: 'keysChanged' }
  const pinFailure = await pinFirstSight(deps, recipientUserId, found)
  if (pinFailure !== null) return { ok: false, ...pinFailure }

  let signed: SignGroupCreationResult
  try {
    signed = await deps.signGroupCreation({
      userId: deps.selfUserId,
      groupId: material.groupId,
      groupKey: material.groupKeyB64,
    })
  } catch (err) {
    return signFailure(err)
  }

  let wrappedKey
  try {
    const wrapped = await deps.rewrapCrypto({
      userId: deps.selfUserId,
      groupId: material.groupId,
      ownWrappedGroupKey: signed.groupKeyWrapped,
      ownGeneration: 0,
      // The key just checked: found.served's wrapping key produced the confirmed fingerprint.
      recipients: [{ userId: recipientUserId, x25519PublicKey: found.served.wrappingPublicKey }],
    })
    wrappedKey = wrapped.wraps.find((w) => w.userId === recipientUserId)?.wrappedKey
  } catch (err) {
    return signFailure(err)
  }
  if (wrappedKey === undefined) {
    return { ok: false, kind: 'rejected', message: "Couldn't wrap the group key. Try again." }
  }

  // The admission carries the DM's request id in the invite-id slot and the sender's root grant as
  // its grant ref; it signs the recipient's keys exactly as just checked.
  const day = new Date((deps.now ?? Date.now)()).toISOString().slice(0, 10)
  let admission: SignReadmissionResult
  try {
    admission = await deps.signReadmission({
      userId: deps.selfUserId,
      groupId: material.groupId,
      subjectUserId: recipientUserId,
      subjectEd25519PublicKey: found.served.signingPublicKey,
      subjectX25519PublicKey: found.served.wrappingPublicKey,
      inviteId: material.requestId,
      inviterGrantRef: signed.rootGrantSortKey,
      day,
      generation: 0,
    })
  } catch (err) {
    return signFailure(err)
  }

  const dm: CreateDMBody = {
    recipientUserId,
    requestId: material.requestId,
    wrappedGroupKey: wrappedKey,
    admission: { day: admission.day, signature: admission.signature },
  }
  try {
    await deps.createDM({
      groupId: material.groupId,
      visibility: 'private',
      revocationMode: 'open',
      expirationDays,
      groupKeyWrapped: signed.groupKeyWrapped,
      trustAnchorSignature: signed.trustAnchorSignature,
      rootGrantSortKey: signed.rootGrantSortKey,
      rootGrantSignature: signed.rootGrantSignature,
      dm,
    })
    return { ok: true, groupId: material.groupId }
  } catch (err) {
    return startFailureOf(err, material.groupId)
  }
}

function signFailure(err: unknown): StartFail {
  return isLiveKeysError(err)
    ? { ok: false, kind: 'coldKeys' }
    : { ok: false, kind: 'rejected', message: "Couldn't sign this message. Try again." }
}

function startFailureOf(err: unknown, ownGroupId: string): StartDMResult {
  if (err instanceof DMExistsError) {
    // The pair marker names a group of ours: if it is THIS group, an earlier send of this very
    // material landed and only its answer was lost. Only that send could have used this id.
    return err.groupId === ownGroupId
      ? { ok: true, groupId: ownGroupId }
      : { ok: false, kind: 'exists', groupId: err.groupId }
  }
  if (err instanceof ApiError) {
    switch (err.code) {
      case 'dm_cooling_off':
        return { ok: false, kind: 'coolingOff', message: err.message }
      case 'too_many_pending_dms':
        return { ok: false, kind: 'tooManyPending' }
      case 'dm_conflict':
        return { ok: false, kind: 'conflict' }
      case 'bad_signature':
        // The admission signs the recipient's keys as the server holds them at the moment of the
        // send, and this one was signed over the keys just checked: they changed in between.
        return { ok: false, kind: 'recipientKeysChanged' }
      case 'recipient_not_found':
        return { ok: false, kind: 'gone' }
      case 'recipient_deleted':
        return { ok: false, kind: 'deleted' }
      case 'account_deleted':
        return { ok: false, kind: 'accountDeleted' }
      case 'clock_skew':
        return { ok: false, kind: 'rejected', message: CLOCK_SKEW_MESSAGE }
      case 'key_epoch_stale':
        return { ok: false, kind: 'rejected', message: 'Your keys changed while this was sent. Reload and try again.' }
    }
    if (err.status === 401) return { ok: false, kind: 'authRequired' }
    if (err.status < 500) return { ok: false, kind: 'rejected', message: err.message }
  }
  return { ok: false, kind: 'ambiguous' }
}

const START_MESSAGES: Record<
  Exclude<StartDMFailure['kind'], 'rejected' | 'unchecked' | 'coolingOff'>,
  string
> = {
  pinMismatch:
    "The keys shown for them don't match the copy you saved earlier, so nothing was sent. Check with them another way.",
  keysChanged:
    'Their keys are not the ones whose fingerprint you confirmed, so nothing was sent. Start again and compare the new fingerprint with them.',
  gone: 'No such user.',
  deleted: 'That account was deleted.',
  self: 'You cannot message yourself.',
  exists: 'You already have a conversation with this person.',
  tooManyPending:
    'Too many of your messages are waiting for an answer. Wait for replies or leave some before starting another.',
  recipientKeysChanged:
    'Their keys changed while this was being sent, so nothing was sent. Start again and compare the new fingerprint with them.',
  conflict: 'That changed while it was being sent. Try again.',
  authRequired: 'Your session has expired. Log in again and retry.',
  coldKeys: 'This tab needs your password again to send a message.',
  accountDeleted: 'Your account was deleted.',
  ambiguous:
    "We couldn't confirm whether the message was sent. Check your groups list before trying again; sending again is safe.",
}

export function startDMFailureMessage(outcome: StartFail): string {
  if (outcome.kind === 'rejected' || outcome.kind === 'coolingOff') return outcome.message
  if (outcome.kind === 'unchecked') {
    return `Nothing was sent, because what decides this could not be checked (${outcome.reason}).`
  }
  return START_MESSAGES[outcome.kind]
}

// ---------------------------------------------------------------------------------------------
// The recipient's side
// ---------------------------------------------------------------------------------------------

export type AcceptDMFailure =
  | PersonFailure
  /** The sender's signature does not verify over what it claims: nothing was accepted. */
  | { readonly kind: 'badAdmission' }
  /** The admission names keys that are not this device's: not made for you. */
  | { readonly kind: 'notYourKeys' }
  /** Your keys changed since it was sent (the server's keys_changed): decline it, they can resend. */
  | { readonly kind: 'myKeysChanged' }
  | { readonly kind: 'alreadyMember' }
  /** The sender withdrew and sent again since you loaded the list. */
  | { readonly kind: 'requestChanged' }
  /** It is gone (withdrawn, or the sender left). */
  | { readonly kind: 'goneRequest' }
  | { readonly kind: 'accountDeleted' }
  | { readonly kind: 'authRequired' | 'coldKeys' }
  | { readonly kind: 'rejected'; readonly message: string }
  | { readonly kind: 'ambiguous' }

type AcceptFail = { readonly ok: false } & AcceptDMFailure

export interface AcceptDMDeps extends PersonDeps {
  readonly acceptDM: (groupId: string, requestId: string) => Promise<void>
  readonly declineDM: (groupId: string, requestId: string) => Promise<void>
  /** The fingerprint of the keys this tab holds (the worker's getOwnFingerprint). */
  readonly ownFingerprint: () => Promise<string>
}

export type PrepareAcceptResult =
  { readonly ok: true; readonly fingerprint: string; readonly firstSight: boolean } | AcceptFail

type Verified =
  | { readonly ok: true; readonly found: Extract<Inspected, { ok: true }> }
  | AcceptFail

/**
 * Everything that decides whether this DM may be opened, read fresh. Nothing is written. The order
 * matters: the admission is checked against THIS device's keys first (a DM made for other keys is
 * never shown), then the sender's keys against the pins, then the signature over all of it.
 */
async function verifyIncoming(deps: AcceptDMDeps, dm: IncomingDM): Promise<Verified> {
  let ed: Uint8Array
  let x: Uint8Array
  let signature: Uint8Array
  try {
    ed = base64ToBytes(dm.recipientEd25519PublicKey)
    x = base64ToBytes(dm.recipientX25519PublicKey)
    signature = base64ToBytes(dm.admissionSignature)
  } catch {
    return { ok: false, kind: 'badAdmission' }
  }
  let named: string
  let mine: string
  try {
    named = fingerprint(ed, x)
    mine = await deps.ownFingerprint()
  } catch (err) {
    return isLiveKeysError(err)
      ? { ok: false, kind: 'coldKeys' }
      : { ok: false, kind: 'unchecked', reason: `could not read your own keys: ${describe(err)}` }
  }
  if (named !== mine) return { ok: false, kind: 'notYourKeys' }

  const found = await inspectPerson(deps, dm.senderUserId)
  if (!found.ok) return found

  const payload = admissionPayload(
    dm.groupId,
    dm.senderUserId,
    deps.selfUserId,
    ed,
    x,
    dm.requestId,
    dm.admissionGrantRef,
    dm.admissionDay,
    0,
  )
  // Any key the sender has held: the admission was signed when they sent it, and they may have
  // rotated since. The whole set was just checked against the pin.
  const signedByTheSender = found.signingKeys.some((key) =>
    ed25519.verify(key, ed25519.SigningContext.Admission, payload, signature),
  )
  if (!signedByTheSender) return { ok: false, kind: 'badAdmission' }
  return { ok: true, found }
}

/**
 * The checks that come before showing the sender's fingerprint: a DM that fails them is refused here,
 * so the recipient is never asked to confirm one. Returns the fingerprint of the sender's keys.
 */
export async function prepareAcceptDM(
  deps: AcceptDMDeps,
  dm: IncomingDM,
): Promise<PrepareAcceptResult> {
  const verified = await verifyIncoming(deps, dm)
  return verified.ok
    ? { ok: true, fingerprint: verified.found.fingerprint, firstSight: verified.found.firstSight }
    : verified
}

export type AcceptDMResult = { readonly ok: true; readonly groupId: string } | AcceptFail

/**
 * Opens `dm`. Everything is re-read and re-checked, and `confirmedFingerprint` is what the recipient
 * compared with the sender: accept is called only if the keys checked NOW still give exactly that.
 */
export async function runAcceptDM(
  deps: AcceptDMDeps,
  dm: IncomingDM,
  confirmedFingerprint: string,
): Promise<AcceptDMResult> {
  const verified = await verifyIncoming(deps, dm)
  if (!verified.ok) return verified
  if (verified.found.fingerprint !== confirmedFingerprint) return { ok: false, kind: 'keysChanged' }
  const pinFailure = await pinFirstSight(deps, dm.senderUserId, verified.found)
  if (pinFailure !== null) return { ok: false, ...pinFailure }
  try {
    await deps.acceptDM(dm.groupId, dm.requestId)
    return { ok: true, groupId: dm.groupId }
  } catch (err) {
    return acceptFailureOf(err)
  }
}

function acceptFailureOf(err: unknown): AcceptFail {
  if (err instanceof ApiError) {
    switch (err.code) {
      case 'keys_changed':
        return { ok: false, kind: 'myKeysChanged' }
      case 'already_member':
        return { ok: false, kind: 'alreadyMember' }
      case 'request_changed':
        return { ok: false, kind: 'requestChanged' }
      case 'account_deleted':
        return { ok: false, kind: 'accountDeleted' }
    }
    if (err.status === 401) return { ok: false, kind: 'authRequired' }
    if (err.status === 404) return { ok: false, kind: 'goneRequest' }
    if (err.status < 500) return { ok: false, kind: 'rejected', message: err.message }
  }
  return { ok: false, kind: 'ambiguous' }
}

export type DeclineDMResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly message: string; readonly gone?: true }

/** Declines a DM. The sender is kept out for a few days; you can still message them yourself. */
export async function runDeclineDM(deps: AcceptDMDeps, dm: IncomingDM): Promise<DeclineDMResult> {
  try {
    await deps.declineDM(dm.groupId, dm.requestId)
    return { ok: true }
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.status === 401) return { ok: false, message: 'Your session has expired. Log in again.' }
      if (err.code === 'request_changed') {
        return { ok: false, message: ACCEPT_MESSAGES.requestChanged, gone: true }
      }
      if (err.status === 404) return { ok: false, message: ACCEPT_MESSAGES.goneRequest, gone: true }
      if (err.status < 500) return { ok: false, message: err.message }
    }
    return { ok: false, message: "Couldn't decline the message. Try again." }
  }
}

const ACCEPT_MESSAGES: Record<
  Exclude<AcceptDMFailure['kind'], 'rejected' | 'unchecked'>,
  string
> = {
  pinMismatch:
    "The keys shown for the sender don't match the copy you saved earlier, so nothing was opened. Check with them another way, or decline.",
  keysChanged:
    'Their keys are not the ones whose fingerprint you confirmed, so nothing was opened. Compare the new fingerprint with them.',
  gone: 'The sender no longer exists.',
  deleted: 'The sender deleted their account.',
  self: 'You cannot open your own message.',
  badAdmission:
    "This message's signature does not verify over what it claims, so nothing was opened. Decline it.",
  notYourKeys:
    "This message was made for keys that aren't the ones this device holds, so nothing was opened. Decline it; the sender can send it again.",
  myKeysChanged:
    'Your keys changed since this was sent. Decline it and message them yourself (they can also withdraw it and send it again).',
  alreadyMember: 'You are already in this conversation.',
  requestChanged:
    'The sender withdrew it and sent again since you loaded the list. The latest is shown; check the new one.',
  goneRequest: 'That message is gone: it was withdrawn, or the sender left.',
  accountDeleted: 'Your account was deleted.',
  authRequired: 'Your session has expired. Log in again and retry.',
  coldKeys: 'This tab needs your password again to open messages.',
  ambiguous:
    "We couldn't confirm whether it was opened. The latest list is shown; check your groups before trying again.",
}

export function acceptDMFailureMessage(outcome: AcceptFail): string {
  if (outcome.kind === 'rejected') return outcome.message
  if (outcome.kind === 'unchecked') {
    return `Nothing was opened, because what decides this could not be checked (${outcome.reason}).`
  }
  return ACCEPT_MESSAGES[outcome.kind]
}

/** Whether the incoming list should be reloaded after an accept attempt. */
export function shouldReloadAfterAccept(outcome: AcceptDMResult): boolean {
  return (
    outcome.ok ||
    outcome.kind === 'requestChanged' ||
    outcome.kind === 'goneRequest' ||
    outcome.kind === 'alreadyMember' ||
    outcome.kind === 'ambiguous'
  )
}
