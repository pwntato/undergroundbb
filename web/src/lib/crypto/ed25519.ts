// Ed25519 signing via @noble/curves, matching internal/crypto/ed25519.go
// byte-for-byte (see testdata/vectors.json's "signing" and "signed_payload"
// sections).
//
// Key format note: Go's crypto/ed25519.PrivateKey is 64 bytes (a 32-byte
// seed followed by the 32-byte public key it derives). @noble/curves'
// secretKey is the bare 32-byte seed. This module's SigningKey always
// carries both the seed and the derived public key, mirroring Go's shape,
// and toGoPrivateKeyBytes()/fromGoPrivateKeyBytes() convert to and from
// Go's 64-byte encoding for anything crossing the wire or a test vector.

import { ed25519 } from '@noble/curves/ed25519.js'

/** Length in bytes of an Ed25519 seed (and @noble's secretKey). */
export const SEED_SIZE = 32

/** Length in bytes of an Ed25519 public key. */
export const PUBLIC_KEY_SIZE = 32

/** Length in bytes of a Go-encoded Ed25519 private key (seed || pubkey). */
export const GO_PRIVATE_KEY_SIZE = 64

/** Length in bytes of an Ed25519 signature. */
export const SIGNATURE_SIZE = 64

/**
 * Identifies which protocol a signature belongs to. Prepended to every
 * signed payload so a signature valid in one context can never be replayed
 * as valid in another. Must match internal/crypto/ed25519.go exactly.
 */
export const SigningContext = {
  LoginChallenge: 'underground-bb:login-challenge:v1',
  Post: 'underground-bb:post:v1',
  Comment: 'underground-bb:comment:v1',
  RoleGrant: 'underground-bb:role-grant:v1',
  Invite: 'underground-bb:invite:v1',
  TrustAnchor: 'underground-bb:trust-anchor:v1',
} as const

export type SigningContext = (typeof SigningContext)[keyof typeof SigningContext]

export interface SigningKey {
  readonly seed: Uint8Array
  readonly publicKey: Uint8Array
}

/** Generates a new Ed25519 keypair. */
export function generateSigningKey(): SigningKey {
  const seed = crypto.getRandomValues(new Uint8Array(SEED_SIZE))
  const { publicKey } = ed25519.keygen(seed)
  return { seed, publicKey }
}

/**
 * Reconstructs a SigningKey from Go's 64-byte private key encoding
 * (seed || pubkey), verifying the embedded public key matches what the seed
 * derives.
 */
export function fromGoPrivateKeyBytes(bytes: Uint8Array): SigningKey {
  if (bytes.length !== GO_PRIVATE_KEY_SIZE) {
    throw new Error('crypto: private key must be 64 bytes')
  }
  const seed = bytes.slice(0, SEED_SIZE)
  const claimedPublicKey = bytes.slice(SEED_SIZE)
  const { publicKey } = ed25519.keygen(seed)
  if (!bytesEqual(publicKey, claimedPublicKey)) {
    throw new Error('crypto: embedded public key does not match seed')
  }
  return { seed, publicKey }
}

/** Encodes a SigningKey as Go's 64-byte private key (seed || pubkey). */
export function toGoPrivateKeyBytes(key: SigningKey): Uint8Array {
  const out = new Uint8Array(GO_PRIVATE_KEY_SIZE)
  out.set(key.seed, 0)
  out.set(key.publicKey, SEED_SIZE)
  return out
}

/**
 * Signs message under the given context, binding the signature to that
 * context so it cannot be replayed as a signature over the same bytes in a
 * different protocol.
 */
export function sign(key: SigningKey, ctx: SigningContext, message: Uint8Array): Uint8Array {
  return ed25519.sign(contextualize(ctx, message), key.seed)
}

/**
 * Checks a signature produced by sign for the same context and message.
 * Returns false for a wrong context, a wrong message, a wrong key, or a
 * malformed signature — callers must not try to distinguish these.
 */
export function verify(
  publicKey: Uint8Array,
  ctx: SigningContext,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== PUBLIC_KEY_SIZE) {
    return false
  }
  try {
    return ed25519.verify(signature, contextualize(ctx, message), publicKey)
  } catch {
    return false
  }
}

function contextualize(ctx: SigningContext, message: Uint8Array): Uint8Array {
  const ctxBytes = new TextEncoder().encode(ctx)
  const out = new Uint8Array(ctxBytes.length + 1 + message.length)
  out.set(ctxBytes, 0)
  out[ctxBytes.length] = 0x00
  out.set(message, ctxBytes.length + 1)
  return out
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}
