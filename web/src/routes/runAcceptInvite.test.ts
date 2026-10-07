import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GetInviteResponse } from '@/lib/api/invites'
import { bytesToBase64 } from '@/lib/crypto/base64'
import * as ed25519 from '@/lib/crypto/ed25519'
import { fingerprint } from '@/lib/crypto/fingerprint'
import { inviteCreationPayload } from '@/lib/crypto/invite'
import {
  inviteLoadFailure,
  isDefinitelyUncommitted,
  runAcceptInvite,
  verifyInvite,
  type RunAcceptInviteDeps,
} from './runAcceptInvite'

const INVITE_ID = 'invite-uuid-1'
const GROUP_ID = 'group-uuid-1'

/**
 * Builds a genuinely-signed invite. expiresAt/accepted may be overridden
 * for a scenario-specific invite whose SIGNATURE still covers the given
 * expiresAt correctly (unlike a naive field override afterward, which
 * would make the signature stop matching and mask what's actually being
 * tested).
 */
function realInvite(opts: { expiresAt?: string; accepted?: boolean } = {}): {
  invite: GetInviteResponse
  inviterFingerprint: string
} {
  const signingKey = ed25519.signingKeyFromSeed(new Uint8Array(32).fill(2))
  const wrappingPub = new Uint8Array(32).fill(3)
  // Relative to now: a fixed date default is a date bomb (it expired on main).
  const expiresAt =
    opts.expiresAt ??
    new Date(Date.now() + 24 * 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')
  const payload = inviteCreationPayload(INVITE_ID, GROUP_ID, signingKey.publicKey, expiresAt)
  const signature = ed25519.sign(signingKey, ed25519.SigningContext.Invite, payload)

  const invite: GetInviteResponse = {
    groupId: GROUP_ID,
    inviterUserId: 'inviter-uuid-1',
    inviterSigningPublicKey: bytesToBase64(signingKey.publicKey),
    inviterWrappingPublicKey: bytesToBase64(wrappingPub),
    expiresAt,
    creationSignature: bytesToBase64(signature),
    accepted: opts.accepted ?? false,
  }
  return { invite, inviterFingerprint: fingerprint(signingKey.publicKey, wrappingPub) }
}

describe('verifyInvite', () => {
  it('accepts a genuinely well-formed, unexpired, unaccepted invite with no fragment', () => {
    const { invite } = realInvite()
    expect(verifyInvite(INVITE_ID, invite, undefined)).toEqual({ ok: true })
  })

  it('accepts when the fragment fingerprint matches the recomputed one', () => {
    const { invite, inviterFingerprint } = realInvite()
    expect(verifyInvite(INVITE_ID, invite, inviterFingerprint)).toEqual({ ok: true })
  })

  it('rejects when the fragment fingerprint does not match', () => {
    const { invite } = realInvite()
    const result = verifyInvite(INVITE_ID, invite, 'a-completely-different-fingerprint')
    expect(result).toEqual({ ok: false, reason: 'fingerprintMismatch' })
  })

  // Mutation check: a field changed AFTER signing must fail signature
  // verification -- proves the signature is actually checked against
  // these fields (via the server's own claimed data), not merely present.
  // Using a DIFFERENT groupId at signing time (realInvite's own opts)
  // would instead produce a genuinely valid signature over that new
  // payload, which would not exercise this at all -- the tamper has to
  // happen on the already-signed object, exactly as a malicious or
  // corrupted server response would present it.
  it('rejects when the invite payload was tampered with after signing', () => {
    const { invite } = realInvite()
    const tampered: GetInviteResponse = { ...invite, groupId: 'a-different-group-id' }
    expect(verifyInvite(INVITE_ID, tampered, undefined)).toEqual({
      ok: false,
      reason: 'signatureInvalid',
    })
  })

  it('rejects an already-accepted invite even with a valid signature', () => {
    const { invite } = realInvite({ accepted: true })
    expect(verifyInvite(INVITE_ID, invite, undefined)).toEqual({
      ok: false,
      reason: 'alreadyAccepted',
    })
  })

  it('rejects an expired invite even with a valid signature', () => {
    const { invite } = realInvite({ expiresAt: '2020-01-01T00:00:00Z' })
    expect(verifyInvite(INVITE_ID, invite, undefined)).toEqual({ ok: false, reason: 'expired' })
  })

  // Order matters (issue #39): signature is checked BEFORE expiry, so a
  // forged invite with a fabricated past expiresAt (tampered after
  // signing, so the signature no longer matches) is still reported as a
  // bad signature, not as merely expired.
  it('reports signatureInvalid, not expired, when both are wrong', () => {
    const { invite } = realInvite()
    const tampered: GetInviteResponse = { ...invite, expiresAt: '2020-01-01T00:00:00Z' }
    expect(verifyInvite(INVITE_ID, tampered, undefined)).toEqual({
      ok: false,
      reason: 'signatureInvalid',
    })
  })
})

const SIGN_RESULT = {
  acceptanceSignature: 'YWNjZXB0YW5jZS1zaWc=',
  inviteMAC: 'aW52aXRlLW1hYw==',
}
const ACCEPT_RESPONSE = { groupId: GROUP_ID }
const MAC_KEY = 'bWFjLWtleS1mcmFnbWVudA'

function makeDeps(overrides: Partial<RunAcceptInviteDeps> = {}): RunAcceptInviteDeps {
  return {
    signInviteAcceptance: vi.fn().mockResolvedValue(SIGN_RESULT),
    acceptInvite: vi.fn().mockResolvedValue(ACCEPT_RESPONSE),
    userId: 'invitee-uuid-1',
    ...overrides,
  }
}

describe('inviteLoadFailure', () => {
  it('maps 404 to notFound and 410 to expired', () => {
    expect(inviteLoadFailure(new ApiError(404, 'gone'))).toBe('notFound')
    expect(inviteLoadFailure(new ApiError(410, 'invite has expired'))).toBe('expired')
  })

  it('treats anything else as a failure worth retrying', () => {
    expect(inviteLoadFailure(new ApiError(500, 'boom'))).toBe('networkError')
    expect(inviteLoadFailure(new TypeError('Failed to fetch'))).toBe('networkError')
  })
})

describe('isDefinitelyUncommitted', () => {
  const cases: { readonly err: unknown; readonly want: boolean }[] = [
    { err: new ApiError(400, 'bad request'), want: true },
    { err: new ApiError(401, 'unauthorized'), want: true },
    { err: new ApiError(409, 'already accepted', 'invite_already_accepted'), want: false },
    { err: new ApiError(410, 'gone'), want: false },
    { err: new ApiError(500, 'internal error'), want: false },
    { err: new TypeError('network error'), want: false },
  ]
  for (const { err, want } of cases) {
    it(`${err instanceof Error ? err.message : String(err)} -> ${String(want)}`, () => {
      expect(isDefinitelyUncommitted(err)).toBe(want)
    })
  }
})

describe('runAcceptInvite', () => {
  it('signs and submits, returning ok:true on success', async () => {
    const deps = makeDeps()
    const result = await runAcceptInvite(deps, INVITE_ID, MAC_KEY)
    expect(result).toEqual({ ok: true, response: ACCEPT_RESPONSE })
    expect(deps.signInviteAcceptance).toHaveBeenCalledWith({
      userId: 'invitee-uuid-1',
      inviteId: INVITE_ID,
      inviteMACKey: MAC_KEY,
    })
    expect(deps.acceptInvite).toHaveBeenCalledWith(INVITE_ID, {
      acceptanceSignature: SIGN_RESULT.acceptanceSignature,
      inviteMAC: SIGN_RESULT.inviteMAC,
    })
  })

  it('signInviteAcceptance throwing is definitelyUncommitted', async () => {
    const deps = makeDeps({ signInviteAcceptance: vi.fn().mockRejectedValue(new Error('boom')) })
    const result = await runAcceptInvite(deps, INVITE_ID, MAC_KEY)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('definitelyUncommitted')
    }
    expect(deps.acceptInvite).not.toHaveBeenCalled()
  })

  it('a 409 invite_already_accepted from acceptInvite is its own kind', async () => {
    const deps = makeDeps({
      acceptInvite: vi
        .fn()
        .mockRejectedValue(new ApiError(409, 'already accepted', 'invite_already_accepted')),
    })
    const result = await runAcceptInvite(deps, INVITE_ID, MAC_KEY)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('alreadyAccepted')
    }
  })

  // Regression for PR #146 round-2 review: this 409 was falling through to
  // 'ambiguous' (isDefinitelyUncommitted excludes every 409, including
  // this one), telling the caller to retry a request that would just 409
  // again with the same code.
  it('a 409 already_member from acceptInvite is its own kind, not ambiguous', async () => {
    const deps = makeDeps({
      acceptInvite: vi
        .fn()
        .mockRejectedValue(new ApiError(409, 'already a member', 'already_member')),
    })
    const result = await runAcceptInvite(deps, INVITE_ID, MAC_KEY)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('alreadyMember')
    }
  })

  it('a 410 from acceptInvite is expired', async () => {
    const deps = makeDeps({
      acceptInvite: vi.fn().mockRejectedValue(new ApiError(410, 'invite has expired')),
    })
    const result = await runAcceptInvite(deps, INVITE_ID, MAC_KEY)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('expired')
    }
  })

  it('a 401 from acceptInvite is authRequired', async () => {
    const deps = makeDeps({
      acceptInvite: vi.fn().mockRejectedValue(new ApiError(401, 'not authenticated')),
    })
    const result = await runAcceptInvite(deps, INVITE_ID, MAC_KEY)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('authRequired')
    }
  })

  it('a network failure from acceptInvite is ambiguous', async () => {
    const deps = makeDeps({
      acceptInvite: vi.fn().mockRejectedValue(new TypeError('fetch failed')),
    })
    const result = await runAcceptInvite(deps, INVITE_ID, MAC_KEY)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('ambiguous')
    }
  })
})
