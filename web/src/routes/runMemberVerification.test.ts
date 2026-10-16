// Tests for the roster's fingerprint verification runner. Records are signed
// with a real key through the same signVerification the worker uses, so a
// verdict is evaluateVerification's decision and not a malformed fixture.

import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { UserProjection } from '@/lib/api/users'
import { bytesToBase64 } from '@/lib/crypto/base64'
import { signVerification } from '@/lib/crypto/credential-material'
import { generateSigningKey } from '@/lib/crypto/ed25519'
import { fingerprint } from '@/lib/crypto/fingerprint'
import {
  loadMemberVerifications,
  unverifyMember,
  verifyMember,
  type LoadVerificationsDeps,
  type VerifyDeps,
} from './runMemberVerification'

const ME = 'a0000000-0000-4000-8000-000000000001'
const BOB = 'b0000000-0000-4000-8000-000000000002'
const CAROL = 'c0000000-0000-4000-8000-000000000003'

const meKey = generateSigningKey()
const liveKeys = { userId: ME, signingKey: meKey } as unknown as Parameters<
  typeof signVerification
>[0]
const wrap = new Uint8Array(32).fill(5)

function user(id: string, key = generateSigningKey(), wrapping = wrap): UserProjection {
  return {
    userId: id,
    username: id.slice(0, 1),
    signingPublicKey: bytesToBase64(key.publicKey),
    wrappingPublicKey: bytesToBase64(wrapping),
    supersededSigningKeys: [],
  }
}

function fpOf(u: UserProjection): string {
  return fingerprint(
    Uint8Array.from(atob(u.signingPublicKey), (c) => c.charCodeAt(0)),
    Uint8Array.from(atob(u.wrappingPublicKey), (c) => c.charCodeAt(0)),
  )
}

function recordFor(u: UserProjection, fp = fpOf(u)) {
  return { verifiedUserId: u.userId, fingerprint: fp, ...signVerification(liveKeys, u.userId, fp) }
}

function loadDeps(
  users: UserProjection[],
  records: ReturnType<typeof recordFor>[],
  over: Partial<LoadVerificationsDeps> = {},
): LoadVerificationsDeps {
  return {
    getUsers: vi.fn().mockResolvedValue(new Map(users.map((u) => [u.userId, u]))),
    listVerifications: vi.fn().mockResolvedValue(records),
    ownSigningKey: vi.fn().mockResolvedValue(bytesToBase64(meKey.publicKey)),
    selfUserId: ME,
    ...over,
  }
}

describe('loadMemberVerifications', () => {
  it('computes each fingerprint from the served keys and reports none, verified, changed', async () => {
    const bob = user(BOB)
    const carol = user(CAROL)
    // Carol was verified at a fingerprint her served keys no longer give.
    const staleCarol = recordFor(carol, fpOf(user(CAROL)))
    const out = await loadMemberVerifications(
      loadDeps([bob, carol], [recordFor(bob), staleCarol]),
      [ME, BOB, CAROL],
    )
    expect(out.state).toBe('ready')
    if (out.state !== 'ready') return
    expect(out.byUser.get(BOB)).toEqual({ fingerprint: fpOf(bob), verdict: 'verified' })
    expect(out.byUser.get(CAROL)?.verdict).toBe('changed')
    expect(out.byUser.has(ME)).toBe(false)

    const none = await loadMemberVerifications(loadDeps([bob], []), [ME, BOB])
    if (none.state !== 'ready') throw new Error('want ready')
    expect(none.byUser.get(BOB)).toEqual({ fingerprint: fpOf(bob), verdict: 'none' })
  })

  it('a member the server did not return has no fingerprint, and a record for them is changed', async () => {
    const bob = user(BOB)
    const out = await loadMemberVerifications(loadDeps([], [recordFor(bob)]), [ME, BOB])
    if (out.state !== 'ready') throw new Error('want ready')
    expect(out.byUser.get(BOB)).toEqual({ fingerprint: null, verdict: 'changed' })
  })

  it('a record signed by a different key is bad-signature', async () => {
    const bob = user(BOB)
    const forged = {
      verifiedUserId: BOB,
      fingerprint: fpOf(bob),
      ...signVerification(
        { userId: ME, signingKey: generateSigningKey() } as unknown as typeof liveKeys,
        BOB,
        fpOf(bob),
      ),
    }
    const out = await loadMemberVerifications(loadDeps([bob], [forged]), [ME, BOB])
    if (out.state !== 'ready') throw new Error('want ready')
    expect(out.byUser.get(BOB)?.verdict).toBe('bad-signature')
  })

  it('is unavailable, not unverified, when a read fails', async () => {
    const bob = user(BOB)
    for (const over of [
      { listVerifications: vi.fn().mockRejectedValue(new Error('down')) },
      { ownSigningKey: vi.fn().mockRejectedValue(new Error('cold')) },
      { getUsers: vi.fn().mockRejectedValue(new Error('down')) },
    ]) {
      const out = await loadMemberVerifications(loadDeps([bob], [], over), [ME, BOB])
      expect(out).toEqual({ state: 'unavailable' })
    }
  })

  it('reads nothing when the caller is the only member', async () => {
    const deps = loadDeps([], [])
    expect(await loadMemberVerifications(deps, [ME])).toEqual({ state: 'ready', byUser: new Map() })
    expect(deps.getUsers).not.toHaveBeenCalled()
  })
})

describe('verifyMember', () => {
  function verifyDeps(users: UserProjection[], over: Partial<VerifyDeps> = {}): VerifyDeps {
    return {
      getUsers: vi.fn().mockResolvedValue(new Map(users.map((u) => [u.userId, u]))),
      signVerification: vi
        .fn()
        .mockImplementation((req: { verifiedUserId: string; fingerprint: string }) =>
          Promise.resolve(signVerification(liveKeys, req.verifiedUserId, req.fingerprint)),
        ),
      putVerification: vi.fn().mockResolvedValue(undefined),
      selfUserId: ME,
      ...over,
    }
  }

  it('signs and stores the fingerprint that was shown', async () => {
    const bob = user(BOB)
    const deps = verifyDeps([bob])
    expect(await verifyMember(deps, BOB, fpOf(bob))).toEqual({ ok: true })
    expect(deps.putVerification).toHaveBeenCalledWith(
      BOB,
      expect.objectContaining({ fingerprint: fpOf(bob) }),
    )
  })

  it('refuses without signing when the served keys no longer give the shown fingerprint', async () => {
    const bob = user(BOB)
    const deps = verifyDeps([bob])
    expect(await verifyMember(deps, BOB, fpOf(user(BOB)))).toEqual({ ok: false, kind: 'changed' })
    expect(deps.signVerification).not.toHaveBeenCalled()
    expect(deps.putVerification).not.toHaveBeenCalled()
  })

  it('maps a server fingerprint_stale 409 to changed, a cold worker to coldKeys, 401 to authRequired', async () => {
    const bob = user(BOB)
    const stale = verifyDeps([bob], {
      putVerification: vi.fn().mockRejectedValue(new ApiError(409, 'stale', 'fingerprint_stale')),
    })
    expect(await verifyMember(stale, BOB, fpOf(bob))).toEqual({ ok: false, kind: 'changed' })
    const cold = verifyDeps([bob], {
      signVerification: vi.fn().mockRejectedValue(new Error('worker: no live keys cached')),
    })
    expect(await verifyMember(cold, BOB, fpOf(bob))).toEqual({ ok: false, kind: 'coldKeys' })
    const auth = verifyDeps([bob], {
      putVerification: vi.fn().mockRejectedValue(new ApiError(401, 'no')),
    })
    expect(await verifyMember(auth, BOB, fpOf(bob))).toEqual({ ok: false, kind: 'authRequired' })
    const other = verifyDeps([bob], {
      putVerification: vi.fn().mockRejectedValue(new ApiError(500, 'boom')),
    })
    expect(await verifyMember(other, BOB, fpOf(bob))).toEqual({ ok: false, kind: 'failed' })
  })

  it('fails without signing when the member cannot be read', async () => {
    const deps = verifyDeps([])
    expect(await verifyMember(deps, BOB, 'x')).toEqual({ ok: false, kind: 'failed' })
    expect(deps.signVerification).not.toHaveBeenCalled()
  })
})

describe('unverifyMember', () => {
  it('reports whether the delete went through', async () => {
    expect(
      await unverifyMember({ deleteVerification: vi.fn().mockResolvedValue(undefined) }, BOB),
    ).toBe(true)
    expect(
      await unverifyMember({ deleteVerification: vi.fn().mockRejectedValue(new Error('x')) }, BOB),
    ).toBe(false)
  })
})
