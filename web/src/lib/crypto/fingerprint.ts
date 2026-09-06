// User fingerprints via native SHA-256 + BigInt, matching
// internal/crypto/fingerprint.go byte-for-byte (see testdata/vectors.json's
// "fingerprint" section).

import { sha256 } from '@noble/hashes/sha2.js'
import { PUBLIC_KEY_SIZE as ED25519_PUBLIC_KEY_SIZE } from './ed25519.js'
import { KEY_LEN as X25519_KEY_SIZE } from './x25519.js'

/**
 * Domain-separation prefix folded into every fingerprint, so a fingerprint
 * can never collide with a hash computed for any other purpose over the
 * same two public keys. Must match Go's fingerprintDomain exactly.
 */
const FINGERPRINT_DOMAIN = 'underground-bb:fingerprint:v1'

/** Displayed length of a fingerprint: 60 decimal digits, per docs/DESIGN.md. */
const FINGERPRINT_DIGITS = 60

/**
 * Computes a user's fingerprint per docs/DESIGN.md: SHA-256 over a
 * domain-separation prefix followed by both of the user's current public
 * keys in a fixed order (Ed25519 signing key, then X25519 wrapping key),
 * displayed as 60 decimal digits in twelve groups of five.
 *
 * Only current keys are covered — a superseded Ed25519 key from a prior
 * rotation is never included, so rotating does not change a fingerprint a
 * counterparty already verified.
 */
export function fingerprint(signingPub: Uint8Array, wrappingPub: Uint8Array): string {
  if (signingPub.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new Error('crypto: invalid public key')
  }
  if (wrappingPub.length !== X25519_KEY_SIZE) {
    throw new Error('crypto: invalid public key')
  }

  const domainBytes = new TextEncoder().encode(FINGERPRINT_DOMAIN)
  const input = new Uint8Array(domainBytes.length + signingPub.length + wrappingPub.length)
  input.set(domainBytes, 0)
  input.set(signingPub, domainBytes.length)
  input.set(wrappingPub, domainBytes.length + signingPub.length)

  const digest = sha256(input)
  return formatFingerprint(digest)
}

/**
 * Renders a 32-byte digest as its decimal expansion zero-padded to 78
 * digits (2^256-1 needs at most 78 decimal digits), takes the low-order 60
 * of those digits, and groups them in fives separated by hyphens.
 */
function formatFingerprint(digest: Uint8Array): string {
  let n = 0n
  for (const byte of digest) {
    n = (n << 8n) | BigInt(byte)
  }
  const full = n.toString().padStart(78, '0')
  const digits = full.slice(full.length - FINGERPRINT_DIGITS)

  const groups: string[] = []
  for (let i = 0; i < digits.length; i += 5) {
    groups.push(digits.slice(i, i + 5))
  }
  return groups.join('-')
}
