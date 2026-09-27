// Issue #40, step 3 of the invite handshake: "the next time the inviter's
// client is online" -- driven by login (docs/DESIGN.md: "completion is
// driven by that query on login, not by the notification path"), not by a
// dedicated screen. LoginScreen calls this right after a successful
// session.login(), once liveKeys is populated -- see this file's own
// runCompleteInvites doc comment for why that ordering matters.
//
// Deps-injected like runCreateGroup.ts/runListGroups.ts, for the same
// reason: this can be unit-tested against stubbed network/worker calls,
// without jsdom or a real worker.

import { ApiError } from '@/lib/api/auth'
import type { PendingInviteCompletion, PendingInviteCompletionsResponse } from '@/lib/api/invites'
import { base64ToBytes } from '@/lib/crypto/base64'
import { InviteMACError } from '@/lib/crypto/credential-material'
import * as ed25519 from '@/lib/crypto/ed25519'
import { inviteAcceptancePayload } from '@/lib/crypto/invite'
import type { CompleteInviteResult } from '@/lib/crypto/worker-protocol'

/** One group's own membership, the shape completeInvite needs to unwrap the inviter's own copy. */
export interface OwnMembershipForCompletion {
  readonly generation: number
  readonly wrappedGroupKey: {
    readonly ephemeralPub: string
    readonly nonce: string
    readonly ciphertext: string
  }
}

export interface CompleteInvitesDeps {
  readonly userId: string
  readonly pendingInviteCompletions: () => Promise<PendingInviteCompletionsResponse>
  /**
   * Returns the caller's own membership (generation + wrapped group key)
   * for groupId, or null if the caller is somehow not a member of it
   * anymore -- a defensive case (e.g. left the group between creating an
   * invite and this login) rather than one this handshake can otherwise
   * produce, since only a member could have created the invite in the
   * first place.
   */
  readonly getOwnMembership: (groupId: string) => Promise<OwnMembershipForCompletion | null>
  readonly completeInviteCrypto: (req: {
    readonly userId: string
    readonly inviteId: string
    readonly groupId: string
    readonly ownWrappedGroupKey: {
      readonly ephemeralPub: string
      readonly nonce: string
      readonly ciphertext: string
    }
    readonly ownGeneration: number
    readonly invitedUserId: string
    readonly invitedEd25519PublicKey: string
    readonly invitedX25519PublicKey: string
    readonly inviteMAC: string
  }) => Promise<CompleteInviteResult>
  readonly completeInvite: (
    inviteId: string,
    req: {
      readonly wrappedGroupKey: {
        readonly ephemeralPub: string
        readonly nonce: string
        readonly ciphertext: string
      }
      readonly generation: number
    },
  ) => Promise<void>
}

/** One pending invite's own completion outcome -- for logging/telemetry, never shown to the user directly. */
export interface CompletionOutcome {
  readonly inviteId: string
  readonly ok: boolean
  readonly reason?: string
}

/**
 * Runs step 3 for every one of the caller's own pending invite completions:
 * fetches the list, and for each entry independently -- one entry's
 * failure must never abort the rest, the same "partial result beats
 * blanking everything" reasoning decryptGroupNames' own doc comment gives
 * for a batch of independently-fallible items -- re-verifies
 * AcceptanceSignature against the invitee's own signed keys (NEVER trusting
 * that the server already checked it: this client's own verification is
 * what actually protects the handshake, per docs/DESIGN.md's "wraps the
 * group key to the X25519 key that was signed in step 2 -- never to a key
 * the server offers unilaterally"), then unwraps its own group key and
 * re-wraps it to the invitee, then posts the result.
 *
 * This function is deliberately fire-and-forget from its caller's
 * perspective: it returns a result array for tests/logging, but
 * LoginScreen does not block navigation on it, and a failure here (a
 * network error, a stale liveKeys, one invite whose signature somehow
 * fails to verify) must never prevent the user from reaching Home --
 * completing a pending invite is a background chore triggered by login,
 * not a precondition for using the app. Any invite this call fails to
 * complete simply remains pending and is retried on the next login,
 * because CompleteInvite is exactly that: a pending SENT# row is not
 * cleared until it actually succeeds.
 */
export async function runCompleteInvites(deps: CompleteInvitesDeps): Promise<CompletionOutcome[]> {
  let pending: readonly PendingInviteCompletion[]
  try {
    const resp = await deps.pendingInviteCompletions()
    pending = resp.invites
  } catch (err) {
    // Can't even fetch the list -- nothing to do this login, and nothing
    // for the caller to treat as fatal (see this function's own doc
    // comment: this is a background chore, not a precondition).
    return [{ inviteId: '(list)', ok: false, reason: describeError(err) }]
  }

  const outcomes: CompletionOutcome[] = []
  for (const invite of pending) {
    outcomes.push(await completeOne(deps, invite))
  }
  return outcomes
}

async function completeOne(
  deps: CompleteInvitesDeps,
  invite: PendingInviteCompletion,
): Promise<CompletionOutcome> {
  try {
    // Re-verify the invitee's own acceptance signature -- this client's
    // own check, not a trust of the server's. A failure here means the
    // stored row is corrupt or the invitee's keys have since rotated in a
    // way this handshake does not (yet) account for; either way, wrapping
    // the group key to whatever key is on file would be wrapping to a key
    // nobody actually signed for, so this invite is skipped rather than
    // completed.
    const payload = inviteAcceptancePayload(
      invite.inviteId,
      base64ToBytes(invite.invitedEd25519PublicKey),
      base64ToBytes(invite.invitedX25519PublicKey),
    )
    const verified = ed25519.verify(
      base64ToBytes(invite.invitedEd25519PublicKey),
      ed25519.SigningContext.Invite,
      payload,
      base64ToBytes(invite.acceptanceSignature),
    )
    if (!verified) {
      return {
        inviteId: invite.inviteId,
        ok: false,
        reason: 'acceptance signature does not verify',
      }
    }

    const membership = await deps.getOwnMembership(invite.groupId)
    if (membership === null) {
      return { inviteId: invite.inviteId, ok: false, reason: 'no longer a member of this group' }
    }

    // inviteMAC is re-verified inside completeInviteCrypto itself, not
    // here -- it needs the inviter's own long-term signing seed
    // (deriveInviteMACKey), which lives only inside the worker's liveKeys
    // cache and can never cross this postMessage boundary, unlike
    // acceptanceSignature's plain-public-key verification above. See
    // credential-material.ts's completeInvite for what this closes.
    const wrapped = await deps.completeInviteCrypto({
      userId: deps.userId,
      inviteId: invite.inviteId,
      groupId: invite.groupId,
      ownWrappedGroupKey: membership.wrappedGroupKey,
      ownGeneration: membership.generation,
      invitedUserId: invite.invitedUserId,
      invitedEd25519PublicKey: invite.invitedEd25519PublicKey,
      invitedX25519PublicKey: invite.invitedX25519PublicKey,
      inviteMAC: invite.inviteMAC,
    })

    await deps.completeInvite(invite.inviteId, {
      wrappedGroupKey: wrapped.wrappedGroupKey,
      generation: wrapped.generation,
    })
    return { inviteId: invite.inviteId, ok: true }
  } catch (err) {
    // ApiError(409, 'already_member') and a plain "already completed" 200
    // (server-side idempotency for two racing tabs/devices) both count as
    // success from this caller's perspective -- the membership this call
    // would have produced already exists either way. The server's own
    // completeInvite handler now runs a cleanup transaction before ever
    // returning this 409 (db.CleanupAlreadyMemberInvite), so this invite's
    // two rows are already gone by the time this branch runs -- this is
    // no longer a zombie invite that would keep reappearing from
    // pending-completions on every future login.
    if (err instanceof ApiError && err.code === 'already_member') {
      return { inviteId: invite.inviteId, ok: true }
    }
    // InviteMACError means one of two things (PR #146 round-2 review):
    // either the server just attempted the exact key-substitution this
    // MAC exists to block, or -- the legitimate, permanent case -- the
    // inviter's OWN signing key has since rotated, so the seed
    // deriveInviteMACKey re-derives k from no longer matches the one used
    // at creation, and this invite can never complete (no key-rotation
    // superseded-seed fallback exists yet, since rotation itself, #78,
    // doesn't exist). Either way, this must not look like an ordinary
    // transient failure that a future login might silently resolve on its
    // own: logged loudly (console.error, not console.warn -- this is
    // exactly the failure mode a malicious server would try to hide
    // among ordinary noise) and given its own reason so a caller
    // surfacing per-invite outcomes (none does yet -- #83's own
    // surfacing is the natural home for this) can tell it apart from a
    // plain network hiccup.
    if (err instanceof InviteMACError) {
      console.error(
        `runCompleteInvites: invite ${invite.inviteId} failed its MAC check -- either a malicious server substituted its own keys, or the inviter's signing key has rotated since this invite was created`,
        err,
      )
      return { inviteId: invite.inviteId, ok: false, reason: 'invite MAC does not verify' }
    }
    return { inviteId: invite.inviteId, ok: false, reason: describeError(err) }
  }
}

function describeError(err: unknown): string {
  if (err instanceof ApiError) {
    return `ApiError(${err.status}): ${err.message}`
  }
  if (err instanceof Error) {
    return err.message
  }
  return String(err)
}
