// Re-admitting a member (#178 part 5b): an admin or ambassador replaces the
// admission of a member whose stored record can no longer verify (the inviter's
// keys cannot be read, or the inviter's role changed on the admission's day),
// which pauses every key rotation on them. The server half is
// POST /api/groups/{gid}/members/{uid}/readmit; this is the part only a client
// can do, because only a client holds the verified history:
//
//   - NEVER for anyone the signed removal history names. A colluding server
//     could re-list a removed member, and a re-admission at the current
//     generation would satisfy the generation rule and admit them. They return
//     only through a fresh invitation.
//   - NEVER over a record that still verifies: the server's overwrite is
//     unconditional, so this declines instead of replacing a working admission.
//   - A pin mismatch blocks. The signature is only ever over keys the caller has
//     pinned or just pinned.
//   - The fingerprint is ALWAYS confirmed. The caller is shown the fingerprint
//     of the keys the server serves now, confirms it against the member out of
//     band, and runReadmit signs only if freshly served keys still produce that
//     exact fingerprint. Signing is vouching that these keys are this person's.
//
// Plain functions over injected deps, like runRemoveMember.ts, so they test
// against stubs without a worker or the network.

import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, ReadmitMemberRequest } from '@/lib/api/groups'
import type { UserProjection } from '@/lib/api/users'
import { base64ToBytes, bytesToBase64 } from '@/lib/crypto/base64'
import { fingerprint } from '@/lib/crypto/fingerprint'
import { evaluatePin, servedSigningKeySet } from '@/lib/crypto/pin'
import type { SignReadmissionRequest, SignReadmissionResult } from '@/lib/crypto/worker-protocol'
import { isLiveKeysError } from './runListGroups'
import { isAdmitted, loadAdmissions, type RotationDeps, type RotationOutcome } from './runRotation'

export interface ReadmitDeps extends RotationDeps {
  readonly signReadmission: (
    req: Omit<SignReadmissionRequest, 'kind' | 'id'>,
  ) => Promise<SignReadmissionResult>
  readonly readmitMember: (
    groupId: string,
    userId: string,
    req: ReadmitMemberRequest,
  ) => Promise<void>
  /** A fresh random UUID for the invite slot. */
  readonly newInviteId: () => string
  /** The clock, ms since the epoch; the admission is dated by its UTC day. Defaults to Date.now. */
  readonly now?: () => number
}

export type ReadmitFailure =
  /** The signed removal history names this member: only a fresh invitation brings them back. */
  | { readonly kind: 'removed' }
  /** Their admission verifies, so there is nothing to repair and nothing was replaced. */
  | { readonly kind: 'alreadyAdmitted' }
  /** The keys the server serves for them differ from your saved copy. */
  | { readonly kind: 'pinMismatch' }
  /** The fingerprint you confirmed is not the one their served keys give now. */
  | { readonly kind: 'keysChanged' }
  /** Not an admin or ambassador of this group. */
  | { readonly kind: 'forbidden' }
  | { readonly kind: 'authRequired' | 'notFound' | 'deleted' | 'coldKeys' }
  /** The caller's own grant is not on record, so there is nothing to sign under. */
  | { readonly kind: 'grantMissing' }
  /** The group or the caller's standing moved: reload and decide again. */
  | { readonly kind: 'stale' }
  /** The history that decides this could not be read or verified, so nothing was signed. */
  | { readonly kind: 'unchecked'; readonly reason: string }
  /** A 4xx with the server's own message. */
  | { readonly kind: 'rejected'; readonly message: string }
  /** Network failure or 5xx: the re-admission may or may not have been stored. */
  | { readonly kind: 'ambiguous' }

export type PrepareReadmitResult =
  { readonly ok: true; readonly fingerprint: string } | ({ readonly ok: false } & ReadmitFailure)

export type ReadmitResult = { readonly ok: true } | ({ readonly ok: false } & ReadmitFailure)

const STALE_CODES = new Set(['grantor_ref_stale', 'grantor_changed', 'conflict_retry'])

type Inspection =
  | {
      readonly ok: true
      readonly detail: GroupDetail
      readonly served: UserProjection
      readonly signingKeys: readonly Uint8Array[]
      readonly firstSight: boolean
      readonly fingerprint: string
    }
  | ({ readonly ok: false } & ReadmitFailure)

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/**
 * Everything that decides whether this member may be re-admitted, read fresh:
 * the caller's standing, the member's served keys against the caller's pin, and
 * the verified admission and removal history. Nothing is written.
 */
async function inspect(
  deps: ReadmitDeps,
  groupId: string,
  subjectUserId: string,
): Promise<Inspection> {
  let detail: GroupDetail
  try {
    detail = await deps.getGroup(groupId)
  } catch (err) {
    return failureOf(err)
  }
  if (detail.role !== 'admin' && detail.role !== 'ambassador') {
    return { ok: false, kind: 'forbidden' }
  }
  if (subjectUserId === deps.selfUserId) {
    return { ok: false, kind: 'rejected', message: 'You cannot re-admit yourself.' }
  }
  if ((detail.myGrantSortKey ?? '') === '') {
    return { ok: false, kind: 'grantMissing' }
  }

  let own: Uint8Array
  let served: UserProjection | undefined
  let pins
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
  } catch (err) {
    return { ok: false, kind: 'unchecked', reason: `could not read their keys: ${describe(err)}` }
  }
  if (served === undefined) return { ok: false, kind: 'notFound' }
  if (served.deleted === true) return { ok: false, kind: 'deleted' }

  const signingKeys = servedSigningKeySet(served)
  if (signingKeys === null) {
    return { ok: false, kind: 'unchecked', reason: 'the keys served for them are malformed' }
  }
  const verdict = evaluatePin({
    pinnerUserId: deps.selfUserId,
    pinnerSigningPublicKey: own,
    pinnedUserId: subjectUserId,
    pin: pins.find((p) => p.pinnedUserId === subjectUserId),
    served,
  })
  if (verdict === 'mismatch' || verdict === 'bad-signature') {
    return { ok: false, kind: 'pinMismatch' }
  }

  const loaded = await loadAdmissions(deps, own, groupId, detail.generation)
  if (!loaded.ok) return { ok: false, kind: 'unchecked', reason: loaded.reason }
  // Before anything else about the record: a removed member is never offered,
  // whatever their old admission says.
  if (loaded.context.removedAt.has(subjectUserId)) return { ok: false, kind: 'removed' }
  if (isAdmitted(loaded.context, groupId, subjectUserId, served)) {
    return { ok: false, kind: 'alreadyAdmitted' }
  }

  let print: string
  try {
    print = fingerprint(
      base64ToBytes(served.signingPublicKey),
      base64ToBytes(served.wrappingPublicKey),
    )
  } catch {
    return { ok: false, kind: 'unchecked', reason: 'the keys served for them are malformed' }
  }
  return {
    ok: true,
    detail,
    served,
    signingKeys,
    firstSight: verdict === 'first-sight',
    fingerprint: print,
  }
}

/**
 * The checks that come before showing a fingerprint: a member who may not be
 * re-admitted is refused here, so the caller is never asked to confirm one.
 * Returns the fingerprint of the keys the server serves for them now.
 */
export async function prepareReadmit(
  deps: ReadmitDeps,
  groupId: string,
  subjectUserId: string,
): Promise<PrepareReadmitResult> {
  const found = await inspect(deps, groupId, subjectUserId)
  return found.ok ? { ok: true, fingerprint: found.fingerprint } : found
}

/**
 * Re-admits subjectUserId. Everything is re-read and re-checked, so a roster
 * the caller was looking at a while ago decides nothing; `confirmedFingerprint`
 * is what the caller confirmed with the member, and signing happens only if the
 * keys served NOW still give it.
 */
export async function runReadmit(
  deps: ReadmitDeps,
  groupId: string,
  subjectUserId: string,
  confirmedFingerprint: string,
): Promise<ReadmitResult> {
  const found = await inspect(deps, groupId, subjectUserId)
  if (!found.ok) return found
  if (found.fingerprint !== confirmedFingerprint) return { ok: false, kind: 'keysChanged' }

  const { detail, served } = found
  if (found.firstSight) {
    // Pin what was confirmed, so a later swap is caught and the rotation that
    // follows checks the same keys this signature covers.
    try {
      await deps.pinKeys(
        subjectUserId,
        found.signingKeys.map(bytesToBase64),
        served.wrappingPublicKey,
      )
    } catch (err) {
      return { ok: false, kind: 'unchecked', reason: `could not save their keys: ${describe(err)}` }
    }
  }

  const inviterGrantRef = detail.myGrantSortKey ?? ''
  const inviteId = deps.newInviteId()
  const day = new Date((deps.now ?? Date.now)()).toISOString().slice(0, 10)
  let signed: SignReadmissionResult
  try {
    signed = await deps.signReadmission({
      userId: deps.selfUserId,
      groupId,
      subjectUserId,
      subjectEd25519PublicKey: served.signingPublicKey,
      subjectX25519PublicKey: served.wrappingPublicKey,
      inviteId,
      inviterGrantRef,
      day,
      generation: detail.generation,
    })
  } catch (err) {
    return isLiveKeysError(err)
      ? { ok: false, kind: 'coldKeys' }
      : { ok: false, kind: 'rejected', message: "Couldn't sign this re-admission. Try again." }
  }
  try {
    await deps.readmitMember(groupId, subjectUserId, {
      inviteId,
      generation: detail.generation,
      inviterGrantRef: signed.inviterGrantRef,
      day: signed.day,
      signature: signed.signature,
    })
    return { ok: true }
  } catch (err) {
    if (err instanceof ApiError && err.status === 400 && err.code === 'bad_signature') {
      // The server holds different keys for them than the ones signed over.
      return { ok: false, kind: 'keysChanged' }
    }
    return failureOf(err)
  }
}

function failureOf(err: unknown): { readonly ok: false } & ReadmitFailure {
  if (err instanceof ApiError) {
    if (err.code !== undefined && STALE_CODES.has(err.code)) return { ok: false, kind: 'stale' }
    if (err.code === 'subject_deleted') return { ok: false, kind: 'deleted' }
    if (err.status === 401) return { ok: false, kind: 'authRequired' }
    if (err.status === 403) return { ok: false, kind: 'forbidden' }
    if (err.status === 404) return { ok: false, kind: 'notFound' }
    if (err.status < 500) return { ok: false, kind: 'rejected', message: err.message }
  }
  return { ok: false, kind: 'ambiguous' }
}

const FAILURE_MESSAGES: Record<
  Exclude<ReadmitFailure['kind'], 'rejected' | 'unchecked'>,
  string
> = {
  removed:
    "The group's signed history shows this member was removed, so they can only come back through a fresh invitation.",
  alreadyAdmitted: 'Their invitation record verifies, so there is nothing to re-admit.',
  pinMismatch:
    "The keys the server shows for them don't match the copy you saved earlier, so nothing was signed. Check with them another way.",
  keysChanged:
    'Their keys are not the ones whose fingerprint you confirmed, so nothing was signed. Start again and compare the new fingerprint with them.',
  forbidden: 'Only a group admin or ambassador can re-admit members.',
  authRequired: 'Your session has expired. Log in again and retry.',
  notFound: 'This member or group no longer exists.',
  deleted: "That member's account was deleted.",
  coldKeys: 'Log in again to re-admit members.',
  grantMissing: "Your own grant isn't on record, so a re-admission can't be signed from here yet.",
  stale:
    'The group changed while you were working, so nothing was saved. The latest roster is shown; try again.',
  ambiguous:
    "We couldn't confirm whether the re-admission was saved. The latest roster is shown; check it before trying again.",
}

export function readmitFailureMessage(outcome: { readonly ok: false } & ReadmitFailure): string {
  if (outcome.kind === 'rejected') return outcome.message
  if (outcome.kind === 'unchecked') {
    return `Nothing was signed, because the history that decides this could not be checked (${outcome.reason}).`
  }
  return FAILURE_MESSAGES[outcome.kind]
}

/** Whether the roster should be reloaded after a re-admission attempt. */
export function shouldReloadAfterReadmit(outcome: ReadmitResult): boolean {
  return (
    outcome.ok ||
    outcome.kind === 'stale' ||
    outcome.kind === 'ambiguous' ||
    outcome.kind === 'alreadyAdmitted'
  )
}

/**
 * Whom the screen may offer Re-admit for, after a rotation job ended with
 * `outcome`. A blocked run names them (never anyone the removal history names);
 * a run that finished or found nothing to do clears the set; a run that stopped
 * early learned nothing new, so the last answer stands. Offering is only a
 * convenience: prepareReadmit and runReadmit re-check everything themselves.
 */
export function readmittableAfter(
  outcome: RotationOutcome | undefined,
  previous: ReadonlySet<string>,
): ReadonlySet<string> {
  if (outcome === undefined) return previous
  switch (outcome.status) {
    case 'blocked':
      return new Set(outcome.readmittable ?? [])
    case 'incomplete':
    case 'cannot-resume':
      return previous
    case 'none':
    case 'completed':
    case 'caught-up':
      return new Set()
  }
}
