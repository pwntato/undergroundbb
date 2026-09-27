import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { PendingInviteCompletion } from '@/lib/api/invites'
import * as ed25519 from '@/lib/crypto/ed25519'
import { inviteAcceptancePayload } from '@/lib/crypto/invite'
import {
  runCompleteInvites,
  type CompleteInvitesDeps,
  type OwnMembershipForCompletion,
} from './runCompleteInvites'

const USER_ID = 'inviter-uuid-1'
const GROUP_ID = 'group-uuid-1'
const INVITED_USER_ID = 'invitee-uuid-1'
const INVITE_ID = 'invite-uuid-1'

const WRAPPED_KEY = { ephemeralPub: 'ZXBoZW1lcmFs', nonce: 'bm9uY2U=', ciphertext: 'Y2lwaGVy' }

const OWN_MEMBERSHIP: OwnMembershipForCompletion = {
  generation: 0,
  wrappedGroupKey: WRAPPED_KEY,
}

/** Builds a genuinely-signed PendingInviteCompletion, so acceptance-signature verification is exercised for real. */
function realPendingInvite(): PendingInviteCompletion {
  const key = ed25519.signingKeyFromSeed(new Uint8Array(32).fill(4))
  const x25519Pub = new Uint8Array(32).fill(6)
  const payload = inviteAcceptancePayload(INVITE_ID, key.publicKey, x25519Pub)
  const signature = ed25519.sign(key, ed25519.SigningContext.Invite, payload)
  return {
    inviteId: INVITE_ID,
    groupId: GROUP_ID,
    invitedUserId: INVITED_USER_ID,
    invitedEd25519PublicKey: toBase64(key.publicKey),
    invitedX25519PublicKey: toBase64(x25519Pub),
    acceptanceSignature: toBase64(signature),
  }
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64')
}

function makeDeps(overrides: Partial<CompleteInvitesDeps> = {}): CompleteInvitesDeps {
  return {
    userId: USER_ID,
    pendingInviteCompletions: vi.fn().mockResolvedValue({ invites: [realPendingInvite()] }),
    getOwnMembership: vi.fn().mockResolvedValue(OWN_MEMBERSHIP),
    completeInviteCrypto: vi
      .fn()
      .mockResolvedValue({ wrappedGroupKey: WRAPPED_KEY, generation: 0 }),
    completeInvite: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  }
}

describe('runCompleteInvites', () => {
  it('completes a single pending invite end to end', async () => {
    const deps = makeDeps()
    const outcomes = await runCompleteInvites(deps)

    expect(outcomes).toEqual([{ inviteId: INVITE_ID, ok: true }])
    expect(deps.getOwnMembership).toHaveBeenCalledWith(GROUP_ID)
    expect(deps.completeInviteCrypto).toHaveBeenCalledWith({
      userId: USER_ID,
      groupId: GROUP_ID,
      ownWrappedGroupKey: WRAPPED_KEY,
      ownGeneration: 0,
      invitedUserId: INVITED_USER_ID,
      invitedX25519PublicKey: expect.any(String),
    })
    expect(deps.completeInvite).toHaveBeenCalledWith(INVITE_ID, {
      wrappedGroupKey: WRAPPED_KEY,
      generation: 0,
    })
  })

  it('returns an empty result with no pending invites', async () => {
    const deps = makeDeps({ pendingInviteCompletions: vi.fn().mockResolvedValue({ invites: [] }) })
    const outcomes = await runCompleteInvites(deps)
    expect(outcomes).toEqual([])
    expect(deps.getOwnMembership).not.toHaveBeenCalled()
  })

  it('reports a failure without throwing when the list fetch itself fails', async () => {
    const deps = makeDeps({
      pendingInviteCompletions: vi.fn().mockRejectedValue(new ApiError(500, 'internal error')),
    })
    const outcomes = await runCompleteInvites(deps)
    expect(outcomes).toHaveLength(1)
    expect(outcomes[0]?.ok).toBe(false)
  })

  // Mutation-style check: a TAMPERED acceptance signature must not verify,
  // and the invite must be skipped (not completed) rather than wrapping to
  // a key nobody actually signed for. Without this check, a corrupted or
  // maliciously altered stored row would silently be trusted.
  it('skips an invite whose acceptance signature does not verify', async () => {
    const invite = realPendingInvite()
    const tampered: PendingInviteCompletion = {
      ...invite,
      invitedX25519PublicKey: toBase64(new Uint8Array(32).fill(9)), // different key than what was signed
    }
    const deps = makeDeps({
      pendingInviteCompletions: vi.fn().mockResolvedValue({ invites: [tampered] }),
    })
    const outcomes = await runCompleteInvites(deps)

    expect(outcomes).toEqual([
      { inviteId: INVITE_ID, ok: false, reason: 'acceptance signature does not verify' },
    ])
    expect(deps.getOwnMembership).not.toHaveBeenCalled()
    expect(deps.completeInvite).not.toHaveBeenCalled()
  })

  it('skips an invite when the caller is no longer a member of its group', async () => {
    const deps = makeDeps({ getOwnMembership: vi.fn().mockResolvedValue(null) })
    const outcomes = await runCompleteInvites(deps)
    expect(outcomes).toEqual([
      { inviteId: INVITE_ID, ok: false, reason: 'no longer a member of this group' },
    ])
    expect(deps.completeInvite).not.toHaveBeenCalled()
  })

  // Two tabs/devices racing on the same pending invite: the server's own
  // idempotency (db.ErrAlreadyMember) surfaces here as ApiError with code
  // 'already_member' -- this must count as SUCCESS, not a failure, since
  // the membership this call would have produced already exists.
  it('treats an already_member conflict as success, not a failure', async () => {
    const deps = makeDeps({
      completeInvite: vi
        .fn()
        .mockRejectedValue(new ApiError(409, 'already a member', 'already_member')),
    })
    const outcomes = await runCompleteInvites(deps)
    expect(outcomes).toEqual([{ inviteId: INVITE_ID, ok: true }])
  })

  it('one invite failing does not prevent a second, independent invite from completing', async () => {
    const goodInvite = realPendingInvite()
    const badInvite: PendingInviteCompletion = {
      ...goodInvite,
      inviteId: 'invite-uuid-2',
      groupId: 'group-uuid-2',
    }

    const deps = makeDeps({
      pendingInviteCompletions: vi.fn().mockResolvedValue({ invites: [goodInvite, badInvite] }),
      getOwnMembership: vi.fn().mockImplementation(async (groupId: string) => {
        if (groupId === 'group-uuid-2') {
          throw new Error('boom')
        }
        return OWN_MEMBERSHIP
      }),
    })
    const outcomes = await runCompleteInvites(deps)

    expect(outcomes).toHaveLength(2)
    expect(outcomes[0]).toEqual({ inviteId: goodInvite.inviteId, ok: true })
    expect(outcomes[1]?.ok).toBe(false)
  })
})
