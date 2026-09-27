// The async body of AcceptInviteScreen's handling of a fetched invite --
// issue #39, step 2. Deps-injected like runCreateGroup.ts/runCreateInvite.ts,
// for the same reason: unit-testable against real ApiError instances and
// stubbed network/worker calls, without jsdom or a real worker.
//
// This file's job is split into two independently useful pieces, since
// they run at genuinely different times in the real flow:
//
//  - verifyInvite: checks the invite's step-1 signature (client-side,
//    never trusting the server already did) and, if a fingerprint was
//    carried in the invite link's URL fragment, checks it too. Runs the
//    moment the invite is fetched, BEFORE the visitor even has an account
//    -- this is what decides whether AcceptInviteScreen shows "you've been
//    invited" at all, or refuses to.
//  - runAcceptInvite: signs and submits step 2. Runs only once the visitor
//    is authenticated (an existing account, or one they just created) --
//    see AcceptInviteScreen's own header comment for how those two moments
//    are threaded together across a signup/login detour.

import { ApiError } from '@/lib/api/auth'
import type {
  AcceptInviteRequest,
  AcceptInviteResponse,
  GetInviteResponse,
} from '@/lib/api/invites'
import { base64ToBytes } from '@/lib/crypto/base64'
import * as ed25519 from '@/lib/crypto/ed25519'
import { fingerprint } from '@/lib/crypto/fingerprint'
import { inviteCreationPayload } from '@/lib/crypto/invite'
import type { SignInviteAcceptanceResult } from '@/lib/crypto/worker-protocol'

export type InviteVerificationFailure =
  'signatureInvalid' | 'fingerprintMismatch' | 'alreadyAccepted' | 'expired'

export type VerifyInviteResult =
  { readonly ok: true } | { readonly ok: false; readonly reason: InviteVerificationFailure }

/**
 * Verifies a fetched invite client-side, independently of anything the
 * server claims about it -- this is the actual security-relevant check for
 * an accountless visitor, since GET /api/invites/{id} is unauthenticated
 * and the server has already had every opportunity to lie about the
 * invite's contents if it wanted to (it cannot forge the signature, but
 * this function is what actually proves that, rather than assuming it).
 *
 * fragmentFingerprint is the invite link's URL fragment (never sent to any
 * server -- see docs/DESIGN.md's own reasoning), or undefined for a link
 * that was shared without one (e.g. copied without the fragment, or an
 * older link format). When present, it is checked against a fingerprint
 * this function recomputes from invite.inviterSigningPublicKey/
 * inviterWrappingPublicKey -- see GetInviteResponse's own doc comment for
 * why the wrapping key has to be fetched fresh for this to be possible at
 * all. A mismatch is reported distinctly from a bad signature: either one
 * refuses the invite, but a fingerprint mismatch means the LINK and the
 * SERVER'S CURRENT ANSWER disagree about who the inviter is (a compromised
 * or MITM'd server, or the inviter rotated keys since the link was
 * shared), while a bad signature means the invite itself is malformed or
 * tampered.
 *
 * Order matches acceptInvite's own server-side requirement (issue #39):
 * signature first, then expiry -- an unverified expiresAt is a value an
 * untrustworthy server could have altered, so checking it before the
 * signature would be checking the attacker's own number.
 */
export function verifyInvite(
  inviteId: string,
  invite: GetInviteResponse,
  fragmentFingerprint: string | undefined,
): VerifyInviteResult {
  const payload = inviteCreationPayload(
    inviteId,
    invite.groupId,
    base64ToBytes(invite.inviterSigningPublicKey),
    invite.expiresAt,
  )
  const verified = ed25519.verify(
    base64ToBytes(invite.inviterSigningPublicKey),
    ed25519.SigningContext.Invite,
    payload,
    base64ToBytes(invite.creationSignature),
  )
  if (!verified) {
    return { ok: false, reason: 'signatureInvalid' }
  }

  if (fragmentFingerprint !== undefined) {
    const computed = fingerprint(
      base64ToBytes(invite.inviterSigningPublicKey),
      base64ToBytes(invite.inviterWrappingPublicKey),
    )
    if (computed !== fragmentFingerprint) {
      return { ok: false, reason: 'fingerprintMismatch' }
    }
  }

  if (invite.accepted) {
    return { ok: false, reason: 'alreadyAccepted' }
  }
  if (new Date(invite.expiresAt).getTime() < Date.now()) {
    return { ok: false, reason: 'expired' }
  }

  return { ok: true }
}

export type AcceptInviteErrorKind =
  'definitelyUncommitted' | 'ambiguous' | 'authRequired' | 'alreadyAccepted' | 'expired'

export type RunAcceptInviteResult =
  | { readonly ok: true; readonly response: AcceptInviteResponse }
  | { readonly ok: false; readonly kind: AcceptInviteErrorKind; readonly error: unknown }

/**
 * Whether err is an ApiError whose status proves
 * POST /api/invites/{id}/accept's write never ran -- every 4xx (a stale
 * challenge is not possible here, but validation and a malformed request
 * both are) is returned before db.AcceptInvite's transaction ever runs,
 * except 409 (invite_already_accepted, a real committed state on the
 * SERVER side, just not this caller's own write) and 410 (expired, also
 * definite but its own distinct UX), both handled as their own kinds
 * before this check is ever consulted -- see runAcceptInvite's own switch.
 */
export function isDefinitelyUncommitted(err: unknown): boolean {
  return err instanceof ApiError && err.status < 500 && err.status !== 409 && err.status !== 410
}

export interface RunAcceptInviteDeps {
  readonly signInviteAcceptance: (req: {
    readonly userId: string
    readonly inviteId: string
  }) => Promise<SignInviteAcceptanceResult>
  readonly acceptInvite: (
    inviteId: string,
    req: AcceptInviteRequest,
  ) => Promise<AcceptInviteResponse>
  readonly userId: string
}

/**
 * Runs step 2 itself: signInviteAcceptance (worker) -> acceptInvite
 * (server), for an invite that has already passed verifyInvite. There is
 * no client-chosen secret material generated by this flow (unlike
 * runCreateGroup's group key) -- a retry of an ambiguous failure is always
 * safe to resend as-is, since accepting is naturally idempotent from the
 * caller's own perspective (a repeat of their OWN successful accept just
 * 409s harmlessly, distinguishable via the 'alreadyAccepted' kind from a
 * genuine second-acceptor conflict only by knowing it's your own retry --
 * which this function does not attempt to distinguish, since the
 * server-side effect is identical either way: nothing further to do).
 */
export async function runAcceptInvite(
  deps: RunAcceptInviteDeps,
  inviteId: string,
): Promise<RunAcceptInviteResult> {
  let signed: SignInviteAcceptanceResult
  try {
    signed = await deps.signInviteAcceptance({ userId: deps.userId, inviteId })
  } catch (err) {
    return { ok: false, kind: 'definitelyUncommitted', error: err }
  }

  try {
    const response = await deps.acceptInvite(inviteId, {
      acceptanceSignature: signed.acceptanceSignature,
    })
    return { ok: true, response }
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      return { ok: false, kind: 'authRequired', error: err }
    }
    if (err instanceof ApiError && err.code === 'invite_already_accepted') {
      return { ok: false, kind: 'alreadyAccepted', error: err }
    }
    if (err instanceof ApiError && err.status === 410) {
      return { ok: false, kind: 'expired', error: err }
    }
    if (isDefinitelyUncommitted(err)) {
      return { ok: false, kind: 'definitelyUncommitted', error: err }
    }
    return { ok: false, kind: 'ambiguous', error: err }
  }
}
