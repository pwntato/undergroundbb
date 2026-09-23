// Pins the recovery code's canonical KDF input by testing
// deriveRecoveryWrapKey/deriveRecoveryVerifier (recovery-code.ts) directly --
// round-2 review caught that an earlier version of this file only tested
// normalizeRecoveryCode/deriveKey in isolation, and a mutation that reverted
// worker.ts to deriving from the unnormalized form still passed all tests.
// These two functions always normalize internally (see their own doc
// comments), so worker.ts is protected only because it calls them -- there
// is no lower-level call worker.ts could make that would skip
// normalization, so this file cannot catch a regression at worker.ts's own
// call sites directly. Catching that would take a test of
// generateSignupMaterial itself (worker.ts), with params injectable.

import { describe, expect, it } from 'vitest'
import { bytesToHex } from './hex.js'
import { deriveRecoveryVerifier, deriveRecoveryWrapKey } from './recovery-code.js'

// Small, fast, arbitrary params -- this test only cares that derivations
// match/differ correctly, not about matching any real parameter set.
const TEST_PARAMS = { memoryKiB: 8, iterations: 1, parallelism: 1 }

describe('deriveRecoveryWrapKey / deriveRecoveryVerifier canonical form', () => {
  it('the wrap key over the hyphenated code equals the wrap key over the normalized code', async () => {
    const hyphenated = 'E1AP1-W4KGY-196Y7-QZFWW-RMMFRV'
    const bare = 'E1AP1W4KGY196Y7QZFWWRMMFRV'
    const salt = new Uint8Array(16).fill(7)

    const fromHyphenated = await deriveRecoveryWrapKey(hyphenated, salt, TEST_PARAMS)
    const fromBare = await deriveRecoveryWrapKey(bare, salt, TEST_PARAMS)

    expect(bytesToHex(fromHyphenated)).toBe(bytesToHex(fromBare))
  })

  it('the verifier over the hyphenated code equals the verifier over the normalized code', async () => {
    const hyphenated = 'E1AP1-W4KGY-196Y7-QZFWW-RMMFRV'
    const bare = 'E1AP1W4KGY196Y7QZFWWRMMFRV'
    const salt = new Uint8Array(16).fill(11)

    const fromHyphenated = await deriveRecoveryVerifier(hyphenated, salt, TEST_PARAMS)
    const fromBare = await deriveRecoveryVerifier(bare, salt, TEST_PARAMS)

    expect(bytesToHex(fromHyphenated)).toBe(bytesToHex(fromBare))
  })

  it('every grouping/whitespace/case variant of one code derives an identical wrap key', async () => {
    const salt = new Uint8Array(16).fill(3)
    const variants = [
      'E1AP1-W4KGY-196Y7-QZFWW-RMMFRV',
      'e1ap1-w4kgy-196y7-qzfww-rmmfrv',
      'E1AP1 W4KGY 196Y7 QZFWW RMMFRV',
      'E1AP1W4KGY196Y7QZFWWRMMFRV',
    ]

    const derived = await Promise.all(
      variants.map((v) => deriveRecoveryWrapKey(v, salt, TEST_PARAMS)),
    )
    const hexes = derived.map(bytesToHex)
    expect(new Set(hexes).size).toBe(1)
  })

  it('the wrap key and verifier derive independently under their own salts', async () => {
    // docs/DESIGN.md requires the wrap key and verifier to be independent
    // derivations "so that holding the verifier does not yield the
    // wrapper" -- register.go sends distinct RecoverySalt/
    // RecoveryVerifierSalt for exactly this reason, and worker.ts always
    // calls randomSalt() separately for each (never reuses one salt for
    // both). That salt is what keeps the two outputs from colliding in
    // practice; independence is a caller obligation, not a property this
    // pair enforces by construction -- so this only asserts the salts
    // actually diverge the output, not that a shared salt must collide
    // (a later hardening change, e.g. a context prefix on the verifier,
    // should be free to make even the shared-salt case diverge).
    const code = 'E1AP1-W4KGY-196Y7-QZFWW-RMMFRV'
    const sharedSalt = new Uint8Array(16).fill(5)
    const differentSalt = new Uint8Array(16).fill(6)

    const wrapKey = await deriveRecoveryWrapKey(code, sharedSalt, TEST_PARAMS)
    const verifierUnderOwnSalt = await deriveRecoveryVerifier(code, differentSalt, TEST_PARAMS)
    expect(bytesToHex(wrapKey)).not.toBe(bytesToHex(verifierUnderOwnSalt))
  })
})
