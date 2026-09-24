// Pins PR #129 round 2's non-blocking finding: the bug that actually
// shipped (an unnormalized recoveryCode reaching the wire, sent to
// CheckRecoveryVerifier with no normalization of its own) is NOT caught by
// credential-material.test.ts's round-trip test, because
// deriveRecoveryWrapKey/deriveRecoveryVerifier normalize internally either
// way. Only the wire value runRecovery hands to release/reset is at risk,
// so this test stubs those two and asserts what they were actually called
// with. No jsdom/RTL needed -- these are plain functions.
//
// PR #129 round 3: the error-classifier functions (isCredentialFailure/
// isStaleVersionConflict/isDefinitelyUncommitted) used to be part of
// RecoveryDeps, stubbed by every case below -- so the actual status-code
// mapping was never exercised (changing `< 500` to `< 600` still passed
// all tests). They're now real exports of runRecovery.ts, and this file
// table-tests them directly against real ApiError/DecryptionFailedError
// instances, and the reset()-catch cases below use real instances too
// rather than stubbed predicates.

import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import { DecryptionFailedError } from '@/lib/crypto/aesgcm'
import { normalizeRecoveryCode } from '@/lib/crypto/recovery-code'
import {
  isCredentialFailure,
  isDefinitelyUncommitted,
  isStaleVersionConflict,
  runRecovery,
  type RecoveryDeps,
} from './runRecovery'

const RELEASE_RESPONSE = {
  credentialVersion: 1,
  userId: 'user-1',
  salt: 'c2FsdA==',
  argon2Params: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  wrappedPrivateKeys: { nonce: 'bm9uY2U=', ciphertext: 'Y2lwaGVy' },
}

const RECOVERY_MATERIAL = {
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

function makeDeps(overrides: Partial<RecoveryDeps> = {}): RecoveryDeps {
  return {
    release: vi.fn().mockResolvedValue(RELEASE_RESPONSE),
    completeRecovery: vi.fn().mockResolvedValue(RECOVERY_MATERIAL),
    reset: vi.fn().mockResolvedValue({ credentialVersion: 2 }),
    onProgress: () => {},
    onStep: () => {},
    ...overrides,
  }
}

describe('isCredentialFailure / isStaleVersionConflict / isDefinitelyUncommitted', () => {
  // Table-tested against real instances, per round 3: these decide which of
  // the four user-facing messages a real failure gets, and a stub can't
  // pin the actual status-code boundaries (e.g. `< 500` vs. `< 600`, or
  // exactly 401/409 vs. "anything close").
  const cases: {
    readonly err: unknown
    readonly credential: boolean
    readonly staleVersion: boolean
    readonly uncommitted: boolean
  }[] = [
    { err: new DecryptionFailedError(), credential: true, staleVersion: false, uncommitted: false },
    { err: new ApiError(401, 'invalid'), credential: true, staleVersion: false, uncommitted: true },
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

describe('runRecovery', () => {
  it('sends the normalized code to release, completeRecovery, and reset -- never the raw input', async () => {
    const deps = makeDeps()
    // Lowercase, hyphenated, with a confusable 'l'/'o' the way a user might
    // actually type it -- normalizeRecoveryCode uppercases, strips
    // whitespace/hyphens, and maps I/L->1, O->0 (recovery-code.ts).
    const entered = 'nEw00-Ol0Ol-00000-00000-00000O'
    const expected = normalizeRecoveryCode(entered)
    expect(expected).not.toBe(entered.trim())

    const result = await runRecovery(deps, 'alice', entered, 'new-password')

    expect(result.ok).toBe(true)
    expect(deps.release).toHaveBeenCalledWith('alice', expected)
    expect(deps.completeRecovery).toHaveBeenCalledWith(
      expect.objectContaining({ recoveryCode: expected }),
      expect.any(Function),
    )
    expect(deps.reset).toHaveBeenCalledWith(expect.objectContaining({ recoveryCode: expected }))

    // The bug this pins: if any call site used the raw entered string (or
    // just trim()) instead of the normalized value, this would fail.
    expect(deps.release).not.toHaveBeenCalledWith('alice', entered)
  })

  it('classifies a credential failure at release()', async () => {
    const deps = makeDeps({ release: vi.fn().mockRejectedValue(new ApiError(401, 'invalid')) })
    const result = await runRecovery(deps, 'alice', 'code', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'credential', error: expect.any(ApiError) })
    expect(deps.completeRecovery).not.toHaveBeenCalled()
  })

  it('classifies a wrong-code unwrap failure at completeRecovery() as credential', async () => {
    const deps = makeDeps({
      completeRecovery: vi.fn().mockRejectedValue(new DecryptionFailedError()),
    })
    const result = await runRecovery(deps, 'alice', 'code', 'new-password')
    expect(result).toEqual({
      ok: false,
      kind: 'credential',
      error: expect.any(DecryptionFailedError),
    })
    expect(deps.reset).not.toHaveBeenCalled()
  })

  it('classifies a stale-version 409 at reset() as staleVersion, not resetResponseLost', async () => {
    const deps = makeDeps({ reset: vi.fn().mockRejectedValue(new ApiError(409, 'stale')) })
    const result = await runRecovery(deps, 'alice', 'code', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'staleVersion', error: expect.any(ApiError) })
  })

  it('classifies a provably-uncommitted 4xx at reset() as unreachable, not resetResponseLost', async () => {
    const deps = makeDeps({ reset: vi.fn().mockRejectedValue(new ApiError(400, 'bad request')) })
    const result = await runRecovery(deps, 'alice', 'code', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'unreachable', error: expect.any(ApiError) })
  })

  it('classifies a WAF 403 at reset() as unreachable, not resetResponseLost', async () => {
    const deps = makeDeps({ reset: vi.fn().mockRejectedValue(new ApiError(403, 'rate limited')) })
    const result = await runRecovery(deps, 'alice', 'code', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'unreachable', error: expect.any(ApiError) })
  })

  it('classifies a 503 at reset() as resetResponseLost -- genuinely ambiguous, not provably safe', async () => {
    const deps = makeDeps({ reset: vi.fn().mockRejectedValue(new ApiError(503, 'unavailable')) })
    const result = await runRecovery(deps, 'alice', 'code', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'resetResponseLost', error: expect.any(ApiError) })
  })

  it('classifies a network failure at reset() as resetResponseLost', async () => {
    const err = new TypeError('network')
    const deps = makeDeps({ reset: vi.fn().mockRejectedValue(err) })
    const result = await runRecovery(deps, 'alice', 'code', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'resetResponseLost', error: err })
  })

  it('reports the recovering and resetting steps with the release response and material', async () => {
    const steps: unknown[] = []
    const deps = makeDeps({
      onStep: (step) => {
        steps.push(step)
      },
    })
    await runRecovery(deps, 'alice', 'code', 'new-password')
    expect(steps).toEqual([
      { name: 'recovering', release: RELEASE_RESPONSE },
      { name: 'resetting', material: RECOVERY_MATERIAL },
    ])
  })
})
