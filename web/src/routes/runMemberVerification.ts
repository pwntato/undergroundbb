// The async body behind the roster's fingerprint verification -- issue #65.
// Plain functions over injected deps, like runGrantCheck.ts and
// runGroupMembers.ts.
//
// loadMemberVerifications reads every member's served keys and the caller's own
// signed VERIFIED# records, computes each member's fingerprint locally from the
// keys the server served (never taking a fingerprint from the server), and
// reports a verdict per member (lib/crypto/verification.ts's
// evaluateVerification). A record only ever says "verified" while the served
// keys still give the fingerprint the person compared; a record whose
// fingerprint no longer matches is reported as changed, a warning, because a
// legitimate key change and a substituted key look the same from here.
//
// verifyMember is the action: it re-reads the member's keys, refuses if their
// fingerprint is not the one on screen, signs it, and stores it. The person has
// already compared the on-screen value out of band by the time this runs.

import type { PutVerificationRequest } from '@/lib/api/verifications'
import type { UserProjection } from '@/lib/api/users'
import { ApiError } from '@/lib/api/auth'
import { base64ToBytes } from '@/lib/crypto/base64'
import { fingerprint } from '@/lib/crypto/fingerprint'
import {
  evaluateVerification,
  type VerificationRecord,
  type VerificationVerdict,
} from '@/lib/crypto/verification'
import type { SignVerificationResult } from '@/lib/crypto/worker-protocol'
import { isLiveKeysError } from './runListGroups'

export interface MemberVerification {
  /** The fingerprint of the keys the server serves for this member now; null if unreadable. */
  readonly fingerprint: string | null
  readonly verdict: VerificationVerdict
}

export type MemberVerifications =
  | { readonly state: 'unavailable' }
  | { readonly state: 'ready'; readonly byUser: ReadonlyMap<string, MemberVerification> }

export interface LoadVerificationsDeps {
  readonly getUsers: (ids: readonly string[]) => Promise<ReadonlyMap<string, UserProjection>>
  readonly listVerifications: () => Promise<readonly VerificationRecord[]>
  /** The caller's own CURRENT signing public key, base64. Throws when it cannot be read. */
  readonly ownSigningKey: () => Promise<string>
  readonly selfUserId: string
}

/** The fingerprint of a served projection's two current keys, or null if either is malformed. */
export function servedFingerprint(user: UserProjection | undefined): string | null {
  if (user === undefined || user.deleted === true) {
    return null
  }
  try {
    return fingerprint(base64ToBytes(user.signingPublicKey), base64ToBytes(user.wrappingPublicKey))
  } catch {
    return null
  }
}

export async function loadMemberVerifications(
  deps: LoadVerificationsDeps,
  memberIds: readonly string[],
): Promise<MemberVerifications> {
  const others = memberIds.filter((id) => id !== deps.selfUserId)
  if (others.length === 0) {
    return { state: 'ready', byUser: new Map() }
  }
  let ownKey: Uint8Array
  let records: readonly VerificationRecord[]
  let users: ReadonlyMap<string, UserProjection>
  try {
    ownKey = base64ToBytes(await deps.ownSigningKey())
    ;[records, users] = await Promise.all([deps.listVerifications(), deps.getUsers(others)])
  } catch {
    return { state: 'unavailable' }
  }
  const recordFor = new Map(records.map((r) => [r.verifiedUserId, r]))
  const byUser = new Map<string, MemberVerification>()
  for (const id of others) {
    const served = servedFingerprint(users.get(id))
    byUser.set(id, {
      fingerprint: served,
      verdict: evaluateVerification({
        verifierUserId: deps.selfUserId,
        verifierSigningPublicKey: ownKey,
        verifiedUserId: id,
        record: recordFor.get(id),
        servedFingerprint: served,
      }),
    })
  }
  return { state: 'ready', byUser }
}

export type VerifyFailureKind = 'changed' | 'coldKeys' | 'authRequired' | 'failed'

export type VerifyResult =
  { readonly ok: true } | { readonly ok: false; readonly kind: VerifyFailureKind }

export interface VerifyDeps {
  readonly getUsers: (ids: readonly string[]) => Promise<ReadonlyMap<string, UserProjection>>
  readonly signVerification: (req: {
    readonly userId: string
    readonly verifiedUserId: string
    readonly fingerprint: string
  }) => Promise<SignVerificationResult>
  readonly putVerification: (userId: string, req: PutVerificationRequest) => Promise<void>
  readonly selfUserId: string
}

/**
 * Signs and stores a verification of `subjectUserId` at `shownFingerprint`, the
 * value the person compared. Refuses with 'changed' if the keys the server
 * serves now give a different fingerprint, so a record is never signed over
 * something the person did not see.
 */
export async function verifyMember(
  deps: VerifyDeps,
  subjectUserId: string,
  shownFingerprint: string,
): Promise<VerifyResult> {
  let current: string | null
  try {
    current = servedFingerprint((await deps.getUsers([subjectUserId])).get(subjectUserId))
  } catch {
    return { ok: false, kind: 'failed' }
  }
  if (current === null) {
    return { ok: false, kind: 'failed' }
  }
  if (current !== shownFingerprint) {
    return { ok: false, kind: 'changed' }
  }
  try {
    const signed = await deps.signVerification({
      userId: deps.selfUserId,
      verifiedUserId: subjectUserId,
      fingerprint: shownFingerprint,
    })
    await deps.putVerification(subjectUserId, { fingerprint: shownFingerprint, ...signed })
    return { ok: true }
  } catch (err) {
    if (isLiveKeysError(err)) {
      return { ok: false, kind: 'coldKeys' }
    }
    if (err instanceof ApiError) {
      if (err.status === 401) {
        return { ok: false, kind: 'authRequired' }
      }
      if (err.status === 409 && err.code === 'fingerprint_stale') {
        return { ok: false, kind: 'changed' }
      }
    }
    return { ok: false, kind: 'failed' }
  }
}

/** Withdraws the caller's own record. Returns whether it went through. */
export async function unverifyMember(
  deps: { readonly deleteVerification: (userId: string) => Promise<void> },
  subjectUserId: string,
): Promise<boolean> {
  try {
    await deps.deleteVerification(subjectUserId)
    return true
  } catch {
    return false
  }
}

/** The text for a failed verify, shared by the screen and its tests. */
export function verifyFailureMessage(kind: VerifyFailureKind): string {
  switch (kind) {
    case 'changed':
      return 'Their keys changed while you were comparing, so nothing was saved. Compare their new fingerprint from the start.'
    case 'coldKeys':
      return 'This tab needs your password to sign a verification.'
    case 'authRequired':
      return 'Your session has expired. Log in again and retry.'
    case 'failed':
      return "Couldn't save the verification. Try again."
  }
}
