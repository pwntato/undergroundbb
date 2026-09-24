// Pins PR #129 round 2's non-blocking finding: the bug that actually
// shipped (an unnormalized recoveryCode reaching the wire, sent to
// CheckRecoveryVerifier with no normalization of its own) is NOT caught by
// credential-material.test.ts's round-trip test, because
// deriveRecoveryWrapKey/deriveRecoveryVerifier normalize internally either
// way. Only the wire value runRecovery hands to release/reset is at risk,
// so this test stubs those two and asserts what they were actually called
// with. No jsdom/RTL needed -- these are plain functions.

import { describe, expect, it, vi } from 'vitest'
import { runRecovery, type RecoveryDeps } from './runRecovery'
import { normalizeRecoveryCode } from '@/lib/crypto/recovery-code'

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
    isCredentialFailure: () => false,
    isStaleVersionConflict: () => false,
    isDefinitelyUncommitted: () => false,
    onProgress: () => {},
    onStep: () => {},
    ...overrides,
  }
}

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
    const deps = makeDeps({
      release: vi.fn().mockRejectedValue(new Error('401')),
      isCredentialFailure: () => true,
    })
    const result = await runRecovery(deps, 'alice', 'code', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'credential', error: expect.any(Error) })
    expect(deps.completeRecovery).not.toHaveBeenCalled()
  })

  it('classifies a stale-version 409 at reset() as staleVersion, not resetResponseLost', async () => {
    const err = new Error('409')
    const deps = makeDeps({
      reset: vi.fn().mockRejectedValue(err),
      isStaleVersionConflict: (e) => e === err,
    })
    const result = await runRecovery(deps, 'alice', 'code', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'staleVersion', error: err })
  })

  it('classifies a provably-uncommitted 4xx at reset() as unreachable, not resetResponseLost', async () => {
    const err = new Error('400')
    const deps = makeDeps({
      reset: vi.fn().mockRejectedValue(err),
      isDefinitelyUncommitted: (e) => e === err,
    })
    const result = await runRecovery(deps, 'alice', 'code', 'new-password')
    expect(result).toEqual({ ok: false, kind: 'unreachable', error: err })
  })

  it('classifies a lost response (network failure or 5xx) at reset() as resetResponseLost', async () => {
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
