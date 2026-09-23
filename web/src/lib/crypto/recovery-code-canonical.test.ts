// Pins the recovery code's canonical KDF input by testing worker.ts's ACTUAL
// call sites, not just normalizeRecoveryCode/deriveKey in isolation --
// round-2 review caught that an earlier version of this file only tested
// the general shape of the property, and a mutation that reverted
// worker.ts to deriving from the unnormalized form still passed all tests.
// deriveRecoveryWrapKey/deriveRecoveryVerifier (recovery-code.ts) are what
// worker.ts actually calls, so testing them here means a regression in
// worker.ts's own call sites -- back to passing the hyphenated form, or to
// a hand-rolled deriveKey call that skips normalization -- fails a test.

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
    // both). Argon2id is deterministic and KEY_SIZE/VerifierLen are both
    // 32 bytes, so the ONLY thing that keeps these two outputs from
    // colliding in practice is that salt. Confirms that here: same salt
    // in, same bytes out (both are just deriveKey(canonical, salt, params,
    // 32) underneath) -- the two functions are not independently secure by
    // construction, independence is a caller obligation, not a property
    // this pair enforces.
    const code = 'E1AP1-W4KGY-196Y7-QZFWW-RMMFRV'
    const sharedSalt = new Uint8Array(16).fill(5)

    const wrapKey = await deriveRecoveryWrapKey(code, sharedSalt, TEST_PARAMS)
    const verifier = await deriveRecoveryVerifier(code, sharedSalt, TEST_PARAMS)
    expect(bytesToHex(wrapKey)).toBe(bytesToHex(verifier))

    const differentSalt = new Uint8Array(16).fill(6)
    const verifierUnderOwnSalt = await deriveRecoveryVerifier(code, differentSalt, TEST_PARAMS)
    expect(bytesToHex(wrapKey)).not.toBe(bytesToHex(verifierUnderOwnSalt))
  })
})
