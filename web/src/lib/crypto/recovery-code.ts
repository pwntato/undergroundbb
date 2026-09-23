// The client-generated recovery code, per docs/DESIGN.md: "The recovery code
// is 128 bits of CSPRNG output, rendered as 26 characters of Crockford base32
// in five hyphen-separated groups. The alphabet excludes I, L, O and U, so a
// transcribed code has no ambiguous characters." It is the one credential the
// system generates rather than the user (register.go's own doc comment), and
// the server never parses its structure -- CheckRecoveryVerifier
// (internal/crypto/recovery.go) takes it as an opaque string, so this
// encoding is a pure client convention with no Go counterpart to mirror.
//
// The grouping is 5-5-5-5-6, not 5-5-5-5-5-1 or an even split: 26 characters
// does not divide by 5, and internal/crypto/recovery_test.go's own example
// codes (e.g. "E1AP1-W4KGY-196Y7-QZFWW-RMMFRV") already fix this exact shape,
// so it is pinned here to match rather than chosen fresh.

import { deriveKey, type Argon2idParams } from './argon2.js'

/**
 * Crockford's base32 alphabet with U additionally excluded, per
 * docs/DESIGN.md. Index in this string is the value encoded by that
 * character; order must never change once a real code has been generated
 * under it.
 */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

/** 128 bits of entropy, per docs/DESIGN.md. */
const ENTROPY_BYTES = 16

/** Group sizes, left to right -- 5-5-5-5-6, matching the fixed test codes. */
const GROUP_SIZES = [5, 5, 5, 5, 6] as const

/** Total characters in a rendered code: ceil(128 / log2(32)) = 26. */
const CODE_LENGTH = GROUP_SIZES.reduce((sum, n) => sum + n, 0)

/**
 * Generates a fresh recovery code: 128 bits from the platform CSPRNG,
 * rendered as 26 base32 characters and grouped 5-5-5-5-6 with hyphens, e.g.
 * "E1AP1-W4KGY-196Y7-QZFWW-RMMFRV".
 *
 * The 128 bits produce only 130 bits of base32 symbol space (26 * 5), so the
 * final symbol carries 2 padding bits that are always zero-extended from the
 * real entropy -- normalizeRecoveryCode's round trip preserves them exactly
 * as generated here, it does not need to mask them separately, since they are
 * zero by construction and re-deriving from the same bytes reproduces them.
 */
export function generateRecoveryCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(ENTROPY_BYTES))
  const raw = encodeBase32(bytes)
  if (raw.length !== CODE_LENGTH) {
    throw new Error(
      `crypto: recovery code encoding produced ${raw.length} characters, expected ${CODE_LENGTH}`,
    )
  }
  return formatRecoveryCode(raw)
}

/**
 * Encodes bytes as Crockford base32 (this module's ALPHABET), padded on the
 * right with zero bits to CODE_LENGTH characters. Bit order matches standard
 * base32: bytes are read most-significant-bit first, five bits at a time.
 */
function encodeBase32(bytes: Uint8Array): string {
  let bitBuffer = 0
  let bitCount = 0
  let out = ''

  for (const byte of bytes) {
    bitBuffer = (bitBuffer << 8) | byte
    bitCount += 8
    while (bitCount >= 5) {
      bitCount -= 5
      const index = (bitBuffer >> bitCount) & 0x1f
      out += ALPHABET[index]
    }
  }
  if (bitCount > 0) {
    const index = (bitBuffer << (5 - bitCount)) & 0x1f
    out += ALPHABET[index]
  }
  return out
}

/** Splits a bare 26-character base32 string into hyphenated GROUP_SIZES groups. */
function formatRecoveryCode(raw: string): string {
  const groups: string[] = []
  let offset = 0
  for (const size of GROUP_SIZES) {
    groups.push(raw.slice(offset, offset + size))
    offset += size
  }
  return groups.join('-')
}

/**
 * Normalizes user-entered recovery code input for comparison/submission:
 * uppercases, strips hyphens and whitespace, and maps Crockford's
 * conventional misread substitutions (I/L -> 1, O -> 0) so a transcription
 * that used an excluded-but-visually-similar character still resolves to the
 * code that was actually generated. Does not validate shape -- the server is
 * the source of truth for whether a code is correct (CheckRecoveryVerifier),
 * and a too-short or too-long result here simply fails that check.
 *
 * This output -- bare, uppercase -- is the exact byte string every Argon2id
 * derivation of a recovery code must use, on both sides: worker.ts's
 * recovery-key and verifier derivations at signup, and the recovery
 * screen's own derivation (and the submission that
 * CheckRecoveryVerifier -- internal/crypto/recovery.go -- hashes against
 * with no normalization of its own) at recovery time. It must never change
 * once a real account's verifier exists under it -- doing so would make
 * every already-issued recovery code unverifiable.
 */
export function normalizeRecoveryCode(input: string): string {
  return input.toUpperCase().replace(/[\s-]/g, '').replace(/[IL]/g, '1').replace(/O/g, '0')
}

/** Argon2id output length for the recovery verifier, matching crypto.VerifierLen server-side. */
const RECOVERY_VERIFIER_LEN = 32

/**
 * Derives the recovery-code-derived wrap key from code and salt -- the
 * Argon2id derivation worker.ts's signup path and any future
 * recovery-screen path must agree on byte-for-byte. Always normalizes code
 * first (see normalizeRecoveryCode's own doc comment: this is the one
 * canonical KDF input, on both sides, forever), so a caller passing the
 * hyphenated display form or the bare form gets an identical result either
 * way -- there is deliberately no lower-level function that skips
 * normalization, so this one can't be called incorrectly.
 *
 * A sibling of deriveRecoveryVerifier, kept as two separate functions
 * rather than one combined call so worker.ts can still post a distinct
 * signupProgress event as each derivation finishes (issue #33's "honest
 * progress" -- see worker.ts's own comments on why each step fires only
 * once its own derivation has actually completed).
 *
 * recovery-code-canonical.test.ts calls this directly (not just
 * normalizeRecoveryCode/deriveKey independently) to pin that normalization
 * happens here. Because this function always normalizes internally, there
 * is no lower-level call worker.ts could make that would skip it -- so
 * worker.ts is protected only because it calls this function, not because
 * the test observes worker.ts's own call sites.
 */
export function deriveRecoveryWrapKey(
  code: string,
  salt: Uint8Array,
  params: Argon2idParams,
): Promise<Uint8Array> {
  return deriveKey(normalizeRecoveryCode(code), salt, params)
}

/**
 * Derives the recovery verifier from code and salt -- see
 * deriveRecoveryWrapKey's own doc comment for why this is a separate
 * function from it (progress granularity) and why normalization here is
 * non-optional (this is what CheckRecoveryVerifier -- internal/crypto/
 * recovery.go -- must be handed back, unnormalized, at recovery time for
 * the hash to ever match).
 */
export function deriveRecoveryVerifier(
  code: string,
  salt: Uint8Array,
  params: Argon2idParams,
): Promise<Uint8Array> {
  return deriveKey(normalizeRecoveryCode(code), salt, params, RECOVERY_VERIFIER_LEN)
}
