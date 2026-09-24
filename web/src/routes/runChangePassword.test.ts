// Mirrors runRecovery.test.ts's structure and reasoning exactly -- see that
// file's own header comment and runChangePassword.ts's for what's the same
// and what genuinely differs here (no server-side old-password check to
// fail on, so isCredentialFailure has only one route in, not two).

import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import { DecryptionFailedError } from '@/lib/crypto/aesgcm'
import {
  isCredentialFailure,
  isDefinitelyUncommitted,
  isStaleVersionConflict,
  runChangePassword,
  type ChangePasswordDeps,
} from './runChangePassword'

const CREDENTIALS_RESPONSE = {
  userId: 'user-1',
  salt: 'c2FsdA==',
  argon2Params: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  wrappedPrivateKeys: { nonce: 'bm9uY2U=', ciphertext: 'Y2lwaGVy' },
  credentialVersion: 1,
}

const CHANGE_PASSWORD_MATERIAL = {
  salt: 'c2FsdA==',
  argon2Params: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  wrappedPrivateKeys: { nonce: 'bm9uY2U=', ciphertext: 'Y2lwaGVy' },
  recoverySalt: 'c2FsdA==',
  recoveryArgon2Params: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  recoveryWrappedPrivateKeys: { nonce: 'bm9uY2U=', ciphertext: 'Y2lwaGVy' },
  recoveryVerifierSalt: 'c2FsdA==',
  recoveryVerifierParams: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  recoveryVerifier: 'dmVyaWZpZXI=',
  recoveryCode: 'NEW00-00000-00000-00000-000000',
}

function makeDeps(overrides: Partial<ChangePasswordDeps> = {}): ChangePasswordDeps {
  return {
    getCredentials: vi.fn().mockResolvedValue(CREDENTIALS_RESPONSE),
    completeChangePassword: vi.fn().mockResolvedValue(CHANGE_PASSWORD_MATERIAL),
    changePassword: vi.fn().mockResolvedValue({ credentialVersion: 2 }),
    onProgress: () => {},
    onStep: () => {},
    ...overrides,
  }
}

describe('isCredentialFailure / isStaleVersionConflict / isDefinitelyUncommitted', () => {
  // Unlike runRecovery's identical table, a 401 here is NOT a credential
  // failure -- changePassword's own server-side handler never returns one
  // for a wrong password (there is nothing server-side to check), so a real
  // 401 would only mean an expired/invalid session, which is exactly what
  // isDefinitelyUncommitted (and thus 'unreachable', not 'credential') should
  // say. This is the one deliberate divergence from runRecovery.test.ts's
  // table -- everything else matches.
  const cases: {
    readonly err: unknown
    readonly credential: boolean
    readonly staleVersion: boolean
    readonly uncommitted: boolean
  }[] = [
    { err: new DecryptionFailedError(), credential: true, staleVersion: false, uncommitted: false },
    {
      err: new ApiError(401, 'not authenticated'),
      credential: false,
      staleVersion: false,
      uncommitted: true,
    },
    {
      err: new ApiError(400, 'bad request'),
      credential: false,
      staleVersion: false,
      uncommitted: true,
    },
    {
      err: new ApiError(403, 'rate limited'),
      credential: false,
      staleVersion: false,
      uncommitted: true,
    },
    {
      err: new ApiError(409, 'stale version'),
      credential: false,
      staleVersion: true,
      uncommitted: true,
    },
    {
      err: new ApiError(500, 'internal'),
      credential: false,
      staleVersion: false,
      uncommitted: false,
    },
    {
      err: new ApiError(503, 'unavailable'),
      credential: false,
      staleVersion: false,
      uncommitted: false,
    },
    { err: new TypeError('network'), credential: false, staleVersion: false, uncommitted: false },
    { err: new Error('plain'), credential: false, staleVersion: false, uncommitted: false },
  ]

  it.each(cases)(
    '$err.constructor.name $err.message',
    ({ err, credential, staleVersion, uncommitted }) => {
      expect(isCredentialFailure(err)).toBe(credential)
      expect(isStaleVersionConflict(err)).toBe(staleVersion)
      expect(isDefinitelyUncommitted(err)).toBe(uncommitted)
    },
  )
})

describe('runChangePassword', () => {
  it('passes the fetched credentials and userId through to completeChangePassword', async () => {
    const deps = makeDeps()
    const result = await runChangePassword(deps, 'old-password', 'new-password')

    expect(result.ok).toBe(true)
    expect(deps.completeChangePassword).toHaveBeenCalledWith(
      expect.objectContaining({
        oldPassword: 'old-password',
        newPassword: 'new-password',
        userId: CREDENTIALS_RESPONSE.userId,
        salt: CREDENTIALS_RESPONSE.salt,
      }),
      expect.any(Function),
    )
    expect(deps.changePassword).toHaveBeenCalledWith(
      expect.objectContaining({
        expectedCredentialVersion: CREDENTIALS_RESPONSE.credentialVersion,
      }),
    )
  })

  it('classifies a non-401 getCredentials() failure as unreachable, never credential', async () => {
    const deps = makeDeps({
      getCredentials: vi.fn().mockRejectedValue(new ApiError(500, 'internal')),
    })
    const result = await runChangePassword(deps, 'old-password', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'unreachable', error: expect.any(ApiError) })
    expect(deps.completeChangePassword).not.toHaveBeenCalled()
  })

  // PR #132 round 2: a 401 from getCredentials() means the session expired
  // between page load and submit (requireSession guards this endpoint), not
  // an outage -- collapsing it into 'unreachable' showed "Couldn't reach
  // the server" for a case ChangePasswordScreen's own bootstrap effect
  // already handles correctly by redirecting to /login.
  it('classifies a 401 getCredentials() failure as authRequired, not unreachable', async () => {
    const deps = makeDeps({
      getCredentials: vi.fn().mockRejectedValue(new ApiError(401, 'no session')),
    })
    const result = await runChangePassword(deps, 'old-password', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'authRequired', error: expect.any(ApiError) })
    expect(deps.completeChangePassword).not.toHaveBeenCalled()
  })

  // Same reasoning, but for a session that expires between the GET and the
  // PUT rather than before the GET.
  it('classifies a 401 at changePassword() as authRequired, not unreachable', async () => {
    const deps = makeDeps({
      changePassword: vi.fn().mockRejectedValue(new ApiError(401, 'no session')),
    })
    const result = await runChangePassword(deps, 'old-password', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'authRequired', error: expect.any(ApiError) })
  })

  it('classifies a wrong-old-password unwrap failure at completeChangePassword() as credential', async () => {
    const deps = makeDeps({
      completeChangePassword: vi.fn().mockRejectedValue(new DecryptionFailedError()),
    })
    const result = await runChangePassword(deps, 'wrong-password', 'new-password')
    expect(result).toEqual({
      ok: false,
      kind: 'credential',
      error: expect.any(DecryptionFailedError),
    })
    expect(deps.changePassword).not.toHaveBeenCalled()
  })

  it('classifies a stale-version 409 at changePassword() as staleVersion, not changeResponseLost', async () => {
    const deps = makeDeps({ changePassword: vi.fn().mockRejectedValue(new ApiError(409, 'stale')) })
    const result = await runChangePassword(deps, 'old-password', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'staleVersion', error: expect.any(ApiError) })
  })

  it('classifies a provably-uncommitted 4xx at changePassword() as unreachable, not changeResponseLost', async () => {
    const deps = makeDeps({
      changePassword: vi.fn().mockRejectedValue(new ApiError(400, 'bad request')),
    })
    const result = await runChangePassword(deps, 'old-password', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'unreachable', error: expect.any(ApiError) })
  })

  it('classifies a WAF 403 at changePassword() as unreachable, not changeResponseLost', async () => {
    const deps = makeDeps({
      changePassword: vi.fn().mockRejectedValue(new ApiError(403, 'rate limited')),
    })
    const result = await runChangePassword(deps, 'old-password', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'unreachable', error: expect.any(ApiError) })
  })

  it('classifies a 503 at changePassword() as changeResponseLost -- genuinely ambiguous, not provably safe', async () => {
    const deps = makeDeps({
      changePassword: vi.fn().mockRejectedValue(new ApiError(503, 'unavailable')),
    })
    const result = await runChangePassword(deps, 'old-password', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'changeResponseLost', error: expect.any(ApiError) })
  })

  it('classifies a network failure at changePassword() as changeResponseLost', async () => {
    const err = new TypeError('network')
    const deps = makeDeps({ changePassword: vi.fn().mockRejectedValue(err) })
    const result = await runChangePassword(deps, 'old-password', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'changeResponseLost', error: err })
  })

  it('reports the changing and committing steps with the fetched credentials and material', async () => {
    const steps: unknown[] = []
    const deps = makeDeps({
      onStep: (step) => {
        steps.push(step)
      },
    })
    await runChangePassword(deps, 'old-password', 'new-password')
    expect(steps).toEqual([
      { name: 'changing', credentials: CREDENTIALS_RESPONSE },
      { name: 'committing', material: CHANGE_PASSWORD_MATERIAL },
    ])
  })
})
