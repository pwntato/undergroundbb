// Pins issue #124's client-side half: a resubmission of the SAME username
// after an ambiguous register() failure must reuse the first attempt's
// userId (and therefore, once generateSignupMaterial is called again with
// it, the same wrapped material) rather than generating a fresh one --
// otherwise internal/db/register.go's own #124 fix can never recognize the
// retry as this caller's earlier write. isDefinitelyUncommitted is table-
// tested directly against real ApiError instances, the same way PR #129
// round 3 established for runRecovery's/runChangePassword's own copies, so
// the actual status-code boundary is pinned rather than exercised only
// through a stub.

import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import { isDefinitelyUncommitted, runSignup, type SignupDeps } from './runSignup'

const MATERIAL = {
  signingPublicKey: 'c2lnbmluZw==',
  wrappingPublicKey: 'd3JhcHBpbmc=',
  salt: 'c2FsdA==',
  argon2Params: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  wrappedPrivateKeys: { nonce: 'bm9uY2U=', ciphertext: 'Y2lwaGVy' },
  recoverySalt: 'cmVjb3Zlcnktc2FsdA==',
  recoveryArgon2Params: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  recoveryWrappedPrivateKeys: { nonce: 'bm9uY2U=', ciphertext: 'cmVjb3ZlcnktY2lwaGVy' },
  recoveryVerifierSalt: 'dmVyaWZpZXItc2FsdA==',
  recoveryVerifierParams: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  recoveryVerifier: 'dmVyaWZpZXI=',
  recoveryCode: 'NEW00-00000-00000-00000-000000',
}

const CHALLENGE_RESPONSE = {
  nonce: 'bm9uY2U=',
  userId: 'user-1',
  salt: 'c2FsdA==',
  argon2Params: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  wrappedPrivateKeys: { nonce: 'bm9uY2U=', ciphertext: 'Y2lwaGVy' },
}

function makeDeps(overrides: Partial<SignupDeps> = {}): SignupDeps {
  return {
    generateUserID: vi.fn().mockReturnValue('generated-user-id'),
    generateSignupMaterial: vi.fn().mockResolvedValue(MATERIAL),
    register: vi.fn().mockResolvedValue({ userId: 'user-1' }),
    challenge: vi.fn().mockResolvedValue(CHALLENGE_RESPONSE),
    completeLogin: vi.fn().mockResolvedValue('signature'),
    verify: vi.fn().mockResolvedValue({ userId: 'user-1', credentialVersion: 1 }),
    onProgress: () => {},
    onLogin: () => {},
    onRegistered: () => {},
    ...overrides,
  }
}

describe('isDefinitelyUncommitted', () => {
  const cases: { readonly err: unknown; readonly uncommitted: boolean }[] = [
    { err: new ApiError(400, 'bad request'), uncommitted: true },
    { err: new ApiError(403, 'registration is closed'), uncommitted: true },
    { err: new ApiError(409, 'username is taken'), uncommitted: true },
    { err: new ApiError(409, 'userId is taken'), uncommitted: true },
    { err: new ApiError(500, 'internal'), uncommitted: false },
    { err: new ApiError(503, 'unavailable'), uncommitted: false },
    { err: new TypeError('Failed to fetch'), uncommitted: false },
    { err: new Error('plain error'), uncommitted: false },
  ]
  it.each(cases)(
    '$err.constructor.name $err.message -> uncommitted=$uncommitted',
    ({ err, uncommitted }) => {
      expect(isDefinitelyUncommitted(err)).toBe(uncommitted)
    },
  )
})

describe('runSignup', () => {
  it('generates a fresh userId on a plain (non-retry) submission', async () => {
    const deps = makeDeps()
    await runSignup(deps, 'alice', 'password123')

    expect(deps.generateUserID).toHaveBeenCalledOnce()
    expect(deps.generateSignupMaterial).toHaveBeenCalledWith(
      'password123',
      'generated-user-id',
      deps.onProgress,
    )
    expect(deps.register).toHaveBeenCalledWith(
      expect.objectContaining({ username: 'alice', userId: 'generated-user-id' }),
    )
  })

  it('returns ok:true with the material and loggedIn:true on full success', async () => {
    const onRegistered = vi.fn()
    const deps = makeDeps({ onRegistered })
    const result = await runSignup(deps, 'alice', 'password123')

    expect(result).toEqual({ ok: true, material: MATERIAL, loggedIn: true })
    expect(onRegistered).toHaveBeenCalledWith(MATERIAL)
  })

  it("calls onLogin with verify()'s userId only once login succeeds", async () => {
    const onLogin = vi.fn()
    const deps = makeDeps({ onLogin })
    await runSignup(deps, 'alice', 'password123')

    expect(onLogin).toHaveBeenCalledWith('user-1')
  })

  it('reports ok:true with loggedIn:false if the post-register login fails, without discarding material', async () => {
    const onLogin = vi.fn()
    const deps = makeDeps({
      challenge: vi.fn().mockRejectedValue(new Error('network error')),
      onLogin,
    })
    const result = await runSignup(deps, 'alice', 'password123')

    expect(result).toEqual({ ok: true, material: MATERIAL, loggedIn: false })
    expect(onLogin).not.toHaveBeenCalled()
  })

  it('a definite 4xx register() failure reports no resume -- nothing to retry', async () => {
    const deps = makeDeps({
      register: vi.fn().mockRejectedValue(new ApiError(409, 'username is taken')),
    })
    const result = await runSignup(deps, 'alice', 'password123')

    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error('unreachable')
    }
    expect(result.kind).toBe('definitelyUncommitted')
    expect(result.resume).toBeUndefined()
  })

  it("an ambiguous register() failure (network error) returns a resume with this attempt's userId", async () => {
    const deps = makeDeps({
      generateUserID: vi.fn().mockReturnValue('first-attempt-user-id'),
      register: vi.fn().mockRejectedValue(new TypeError('Failed to fetch')),
    })
    const result = await runSignup(deps, 'alice', 'password123')

    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error('unreachable')
    }
    expect(result.kind).toBe('ambiguous')
    expect(result.resume).toEqual({
      username: 'alice',
      userId: 'first-attempt-user-id',
      password: 'password123',
    })
  })

  it('an ambiguous register() failure (5xx) also returns a resume', async () => {
    const deps = makeDeps({
      register: vi.fn().mockRejectedValue(new ApiError(500, 'internal')),
    })
    const result = await runSignup(deps, 'alice', 'password123')

    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error('unreachable')
    }
    expect(result.kind).toBe('ambiguous')
  })

  // This is #124's actual fix, exercised end to end at this layer: a
  // resubmission passing the prior ambiguous failure's `resume` must NOT
  // call generateUserID again, and must send the SAME userId to register()
  // that the first, possibly-already-committed attempt did.
  it('a retry with `resume` reuses the same userId instead of generating a new one', async () => {
    const deps = makeDeps({ generateUserID: vi.fn().mockReturnValue('should-not-be-used') })
    const resume = { username: 'alice', userId: 'first-attempt-user-id', password: 'password123' }

    await runSignup(deps, 'alice', 'password123', resume)

    expect(deps.generateUserID).not.toHaveBeenCalled()
    expect(deps.generateSignupMaterial).toHaveBeenCalledWith(
      'password123',
      'first-attempt-user-id',
      deps.onProgress,
    )
    expect(deps.register).toHaveBeenCalledWith(
      expect.objectContaining({ userId: 'first-attempt-user-id' }),
    )
  })
})
