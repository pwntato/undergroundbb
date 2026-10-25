// Accepting another user's key change (#62, docs/DESIGN.md "Other admins after
// an approval"). The caller pinned a user's keys earlier; the user has since
// rotated, so the keys the server serves fail that pin with the `mismatch`
// verdict and every check that depends on it blocks. Accepting replaces the
// caller's pin with the served keys, after the caller compares the fingerprint
// with the person out of band.
//
//   - ONLY a `mismatch`. A `rollback` (the server serves keys older than ones
//     already seen) has no legitimate cause and stays a hard block; a pin that
//     does not verify is tampering, never a key change; `first-sight` and
//     `match` have nothing to accept.
//   - The fingerprint is ALWAYS confirmed against freshly served keys, and the
//     pin is written from that same read.
//   - The evidence (lib/crypto/key-change-evidence) is shown to the human and
//     decides nothing: no signed link from the saved keys is a warning, not a
//     refusal, because some legitimate histories have none (a pin of keys the
//     chain starts before).
//
// Plain functions over injected deps, like runApprove.ts.

import { ApiError } from '@/lib/api/auth'
import type { UserDetail } from '@/lib/api/users'
import { base64ToBytes, bytesToBase64 } from '@/lib/crypto/base64'
import { keyChangeEvidence, type KeyChangeEvidence } from '@/lib/crypto/key-change-evidence'
import { evaluatePin, servedSigningKeySet, type PinRecord } from '@/lib/crypto/pin'
import type { OwnKeyHistory } from '@/lib/crypto/own-history'
import { ownHistoryFor } from './ownHistory'
import { isLiveKeysError } from './runListGroups'
import { servedFingerprint } from './runMemberVerification'

export interface AcceptKeyChangeDeps {
  readonly selfUserId: string
  /** The user's served keys and their whole KEYCHANGE# chain. */
  readonly getUserDetail: (userId: string) => Promise<UserDetail>
  readonly ownSigningKey: () => Promise<string>
  readonly listPins: () => Promise<readonly PinRecord[]>
  readonly loadOwnKeyHistory?: (ownSigningKey: Uint8Array) => Promise<OwnKeyHistory | null>
  /** Why that history could not be loaded, or null when it did (lib/session/ownKeyHistory). */
  readonly ownKeyHistoryFailure?: (ownSigningKey: Uint8Array) => Promise<string | null>
  /** Signs and stores a pin of the keys served, replacing the saved one. */
  readonly pinKeys: (
    pinnedUserId: string,
    signingPublicKeys: readonly string[],
    wrappingPublicKey: string,
    keyEpoch: number,
  ) => Promise<void>
}

export type AcceptFailure =
  /** Their keys match what you saved, or you never saved any: nothing to accept. */
  | { readonly kind: 'notChanged' }
  /** The server serves keys older than ones you already saw. Never accepted. */
  | { readonly kind: 'rollback' }
  /** Your saved copy does not verify, so it is not a pin of theirs. */
  | { readonly kind: 'pinUnverifiable' }
  /** The fingerprint you confirmed is not the one their served keys give now. */
  | { readonly kind: 'keysChanged' }
  /** They rotated again while you were deciding: read their keys again. */
  | { readonly kind: 'stale' }
  | { readonly kind: 'authRequired' | 'notFound' | 'deleted' | 'coldKeys' }
  | { readonly kind: 'unchecked'; readonly reason: string }
  | { readonly kind: 'rejected'; readonly message: string }

type Fail = { readonly ok: false } & AcceptFailure

export type PrepareAcceptResult =
  { readonly ok: true; readonly fingerprint: string; readonly evidence: KeyChangeEvidence } | Fail

export type AcceptResult = { readonly ok: true } | Fail

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

type Inspection =
  | {
      readonly ok: true
      readonly served: UserDetail
      readonly signingKeys: readonly Uint8Array[]
      readonly fingerprint: string
      readonly evidence: KeyChangeEvidence
    }
  | Fail

async function inspect(deps: AcceptKeyChangeDeps, subjectUserId: string): Promise<Inspection> {
  if (subjectUserId === deps.selfUserId) {
    return { ok: false, kind: 'rejected', message: 'You cannot accept your own key change.' }
  }
  let served: UserDetail
  let own: Uint8Array
  let pins: readonly PinRecord[]
  try {
    served = await deps.getUserDetail(subjectUserId)
    own = base64ToBytes(await deps.ownSigningKey())
    pins = await deps.listPins()
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return { ok: false, kind: 'notFound' }
    if (err instanceof ApiError && err.status === 401) return { ok: false, kind: 'authRequired' }
    return { ok: false, kind: 'unchecked', reason: `could not read their keys: ${describe(err)}` }
  }
  if (served.deleted === true) return { ok: false, kind: 'deleted' }
  const signingKeys = servedSigningKeySet(served)
  const print = servedFingerprint(served)
  if (signingKeys === null || print === null) {
    return { ok: false, kind: 'unchecked', reason: 'the keys served for them are malformed' }
  }
  const pin = pins.find((p) => p.pinnedUserId === subjectUserId)
  const verdict = evaluatePin({
    pinnerUserId: deps.selfUserId,
    pinnerSigningPublicKey: own,
    pinnerHistory: await ownHistoryFor(deps, own),
    pinnedUserId: subjectUserId,
    pin,
    served,
  })
  // An allowlist: only a mismatch is a key change. A verdict added later must
  // not become acceptable by falling through.
  if (verdict === 'rollback') return { ok: false, kind: 'rollback' }
  if (verdict === 'bad-signature') {
    // A pin the caller signed before rotating fails the same way when their own
    // key history could not be read: that is a failed read, not tampering.
    const failure = await deps.ownKeyHistoryFailure?.(own)
    if (failure !== null && failure !== undefined) {
      return {
        ok: false,
        kind: 'unchecked',
        reason: `could not load your key history: ${failure}`,
      }
    }
    return { ok: false, kind: 'pinUnverifiable' }
  }
  if (verdict !== 'mismatch' || pin === undefined) return { ok: false, kind: 'notChanged' }
  return {
    ok: true,
    served,
    signingKeys,
    fingerprint: print,
    evidence: keyChangeEvidence({
      userId: subjectUserId,
      pin,
      served,
      changes: served.keyChanges,
    }),
  }
}

/**
 * The checks that come before showing a fingerprint, so nobody is asked to
 * confirm one for keys that cannot be accepted. Returns the fingerprint of the
 * keys served now and what the server's own history says about the change.
 */
export async function prepareAcceptKeyChange(
  deps: AcceptKeyChangeDeps,
  subjectUserId: string,
): Promise<PrepareAcceptResult> {
  const found = await inspect(deps, subjectUserId)
  return found.ok ? { ok: true, fingerprint: found.fingerprint, evidence: found.evidence } : found
}

/**
 * Replaces the saved pin with the keys served now, if they still give the
 * fingerprint the caller confirmed. Everything is read again first.
 */
export async function runAcceptKeyChange(
  deps: AcceptKeyChangeDeps,
  subjectUserId: string,
  confirmedFingerprint: string,
): Promise<AcceptResult> {
  const found = await inspect(deps, subjectUserId)
  if (!found.ok) return found
  if (found.fingerprint !== confirmedFingerprint) return { ok: false, kind: 'keysChanged' }
  try {
    await deps.pinKeys(
      subjectUserId,
      found.signingKeys.map(bytesToBase64),
      found.served.wrappingPublicKey,
      found.served.keyEpoch,
    )
    return { ok: true }
  } catch (err) {
    if (isLiveKeysError(err)) return { ok: false, kind: 'coldKeys' }
    if (err instanceof ApiError) {
      if (err.code === 'pin_epoch_stale') return { ok: false, kind: 'stale' }
      if (err.status === 401) return { ok: false, kind: 'authRequired' }
      if (err.status === 404) return { ok: false, kind: 'notFound' }
    }
    return { ok: false, kind: 'unchecked', reason: `could not save their keys: ${describe(err)}` }
  }
}

const FAILURE_MESSAGES: Record<Exclude<AcceptFailure['kind'], 'rejected' | 'unchecked'>, string> = {
  notChanged: 'Their keys match the copy you saved, so there is nothing to accept.',
  rollback:
    'The server is showing older keys for them than you saw before. That should never happen, so nothing was accepted. Check with them another way.',
  pinUnverifiable:
    "The copy of their keys you saved doesn't verify, so it can't be replaced from here. Check with them another way.",
  keysChanged:
    'Their keys are not the ones whose fingerprint you confirmed, so nothing was saved. Start again and compare the new fingerprint with them.',
  stale: 'They changed their keys again while you were checking. Start again with the new ones.',
  authRequired: 'Your session has expired. Log in again and retry.',
  notFound: 'That account no longer exists.',
  deleted: "That member's account was deleted.",
  coldKeys: 'This tab needs your password again to accept a key change.',
}

export function acceptFailureMessage(outcome: Fail): string {
  if (outcome.kind === 'rejected') return outcome.message
  if (outcome.kind === 'unchecked') {
    return `Nothing was saved, because what decides this could not be checked (${outcome.reason}).`
  }
  return FAILURE_MESSAGES[outcome.kind]
}

/** What the server's own history says, in words for the person comparing the fingerprint. */
export function evidenceText(evidence: KeyChangeEvidence): string {
  switch (evidence) {
    case 'signed-rotation':
      return 'The server shows a rotation signed by the keys you saved, so whoever held them made this change.'
    case 'no-link':
      return 'Nothing signed by the keys you saved leads to these. Only accept if they confirm this fingerprint themselves.'
    case 'unverified':
      return "The server's record of their key changes does not verify. Only accept if they confirm this fingerprint themselves."
  }
}
