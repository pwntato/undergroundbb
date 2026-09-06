// X25519 key wrapping via @noble/curves + @noble/hashes, matching
// internal/crypto/x25519.go byte-for-byte (see testdata/vectors.json's
// "wrapping" and "genkey_chain" sections).

import { x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { decrypt, encryptWithNonce, KEY_SIZE, NONCE_SIZE } from './aesgcm.js'

/**
 * Labels HKDF's info parameter with the operation deriving the key, so the
 * wrapping key for a key-wrap can never collide with a key derived for any
 * other purpose from the same ECDH shared secret. Must match Go's
 * hkdfInfo exactly.
 */
const HKDF_INFO = 'underground-bb:x25519-wrap:v1'

/** Length in bytes of an X25519 private or public key. */
export const KEY_LEN = 32

/**
 * Thrown when a public key byte string cannot be a point on the expected
 * curve — currently checked by length only. Matches Go's
 * ErrInvalidPublicKey, kept distinct from DecryptionFailedError so a caller
 * can tell a malformed wrap apart from one that failed authentication.
 */
export class InvalidPublicKeyError extends Error {
  constructor() {
    super('crypto: invalid public key')
    this.name = 'InvalidPublicKeyError'
  }
}

export interface WrappingKey {
  readonly privateKey: Uint8Array
  readonly publicKey: Uint8Array
}

export interface Wrapped {
  readonly ephemeralPub: Uint8Array
  readonly nonce: Uint8Array
  readonly ciphertext: Uint8Array
}

/** Generates a new X25519 keypair for wrapping and unwrapping group keys. */
export function generateWrappingKey(): WrappingKey {
  const privateKey = crypto.getRandomValues(new Uint8Array(KEY_LEN))
  const publicKey = x25519.getPublicKey(privateKey)
  return { privateKey, publicKey }
}

/**
 * Wraps plaintext (typically a group key or a generation key) to
 * recipientPub using ECIES: a fresh ephemeral X25519 keypair, ECDH against
 * the recipient's public key, HKDF-SHA256 to derive a wrapping key from the
 * shared secret, and AES-256-GCM to encrypt.
 *
 * aad is authenticated but not encrypted, and should bind the wrapped item
 * to its address per the AAD table in docs/DESIGN.md.
 *
 * Wrap provides confidentiality only — no sender authentication, for the
 * same reason documented on Go's Wrap: recipientPub is a public value
 * anyone can wrap to. Callers MUST authenticate a wrap independently before
 * trusting it (see docs/DESIGN.md's invite handshake).
 */
export async function wrap(
  recipientPub: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Wrapped> {
  const ephemeralPriv = crypto.getRandomValues(new Uint8Array(KEY_LEN))
  return wrapWithEphemeral(recipientPub, ephemeralPriv, plaintext, aad)
}

/**
 * wrap with an explicit, caller-supplied ephemeral private key. Exists ONLY
 * for generating and verifying fixed test vectors, where a reproducible
 * wrap requires a fixed ephemeral key. Every other caller MUST go through
 * wrap, which always generates a fresh ephemeral keypair.
 */
export async function wrapWithEphemeral(
  recipientPub: Uint8Array,
  ephemeralPriv: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Wrapped> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE))
  return wrapWithEphemeralAndNonce(recipientPub, ephemeralPriv, nonce, plaintext, aad)
}

/**
 * wrapWithEphemeral with the GCM nonce also fixed, for full byte-for-byte
 * reproducibility in generated test vectors. Same misuse warning, doubled:
 * this also reuses a nonce, which combined with a real key is the GCM break
 * documented on encrypt.
 */
export async function wrapWithEphemeralAndNonce(
  recipientPub: Uint8Array,
  ephemeralPriv: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Wrapped> {
  const ephemeralPub = x25519.getPublicKey(ephemeralPriv)
  const sharedSecret = x25519.getSharedSecret(ephemeralPriv, recipientPub)
  const wrappingKey = deriveWrappingKey(sharedSecret, ephemeralPub, recipientPub)

  const ciphertext = await encryptWithNonce(wrappingKey, nonce, plaintext, aad)

  return { ephemeralPub, nonce, ciphertext }
}

/**
 * Reverses wrap: performs ECDH between recipientPriv and the ephemeral
 * public key carried in w, derives the same wrapping key via HKDF-SHA256,
 * and decrypts. aad must match exactly what wrap authenticated.
 */
export async function unwrap(
  recipientPriv: Uint8Array,
  w: Wrapped,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (w.ephemeralPub.length !== KEY_LEN) {
    throw new InvalidPublicKeyError()
  }

  const recipientPub = x25519.getPublicKey(recipientPriv)
  const sharedSecret = x25519.getSharedSecret(recipientPriv, w.ephemeralPub)
  const wrappingKey = deriveWrappingKey(sharedSecret, w.ephemeralPub, recipientPub)
  return decrypt(wrappingKey, w.nonce, w.ciphertext, aad)
}

/**
 * Derives the AES-256-GCM key with HKDF-SHA256 from the ECDH shared secret,
 * binding both public keys involved in the exchange into the info
 * parameter (the HPKE DHKEM pattern) — matching Go's deriveWrappingKey
 * exactly, including its no-salt (undefined) HKDF-Extract step.
 *
 * The concatenation HKDF_INFO || ephemeralPub || recipientPub has no length
 * prefixes, unambiguous only because both public keys are always exactly 32
 * bytes. This derivation must never change once real data exists under it.
 */
function deriveWrappingKey(
  sharedSecret: Uint8Array,
  ephemeralPub: Uint8Array,
  recipientPub: Uint8Array,
): Uint8Array {
  const infoBytes = new TextEncoder().encode(HKDF_INFO)
  const info = new Uint8Array(infoBytes.length + ephemeralPub.length + recipientPub.length)
  info.set(infoBytes, 0)
  info.set(ephemeralPub, infoBytes.length)
  info.set(recipientPub, infoBytes.length + ephemeralPub.length)
  return hkdf(sha256, sharedSecret, undefined, info, KEY_SIZE)
}
