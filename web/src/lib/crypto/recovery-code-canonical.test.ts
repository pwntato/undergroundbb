// Pins the recovery code's canonical KDF input -- see normalizeRecoveryCode's
// own doc comment: every Argon2id derivation of a recovery code, on both
// sides of the wire, must use the bare uppercase form it produces, never the
// hyphenated display form. worker.ts's recovery-key and verifier
// derivations both derive from normalizeRecoveryCode(recoveryCode) for this
// reason. This test exists so a future change to worker.ts (or a recovery
// screen that derives independently) cannot silently regress to the
// hyphenated form without a test failing here first.

import { describe, expect, it } from 'vitest'
import { deriveKey } from './argon2.js'
import { bytesToHex } from './hex.js'
import { normalizeRecoveryCode } from './recovery-code.js'

// Small, fast, arbitrary params -- this test only cares that two inputs
// derive to different keys, not about matching any real parameter set.
const TEST_PARAMS = { memoryKiB: 8, iterations: 1, parallelism: 1 }

describe('recovery code canonical KDF input', () => {
  it('the hyphenated and normalized forms of the same code derive to different keys', async () => {
    const hyphenated = 'E1AP1-W4KGY-196Y7-QZFWW-RMMFRV'
    const canonical = normalizeRecoveryCode(hyphenated)
    const salt = new Uint8Array(16).fill(7)

    const fromHyphenated = await deriveKey(hyphenated, salt, TEST_PARAMS)
    const fromCanonical = await deriveKey(canonical, salt, TEST_PARAMS)

    // If these ever matched, deriving from either form would be
    // interchangeable and this whole test would be moot -- they must not,
    // which is exactly why the canonical form has to be pinned and used
    // consistently rather than left to whichever form a caller happens to
    // pass.
    expect(bytesToHex(fromHyphenated)).not.toBe(bytesToHex(fromCanonical))
  })

  it('every grouping/whitespace variant of one code derives identically once normalized', async () => {
    const salt = new Uint8Array(16).fill(3)
    const variants = [
      'E1AP1-W4KGY-196Y7-QZFWW-RMMFRV',
      'e1ap1-w4kgy-196y7-qzfww-rmmfrv',
      'E1AP1 W4KGY 196Y7 QZFWW RMMFRV',
      'E1AP1W4KGY196Y7QZFWWRMMFRV',
    ]

    const derived = await Promise.all(
      variants.map((v) => deriveKey(normalizeRecoveryCode(v), salt, TEST_PARAMS)),
    )
    const hexes = derived.map(bytesToHex)
    expect(new Set(hexes).size).toBe(1)
  })
})
