// Key rotation primitives -- issue #62, docs/DESIGN.md "What a rotation writes".
// Mirrors internal/crypto/keyrotation.go and the roster helpers in
// internal/crypto/pin.go byte-for-byte (pinned by the shared vectors).
//
// A rotation is signed twice over one payload: by the OLD Ed25519 key (proves
// the caller holds the keys being replaced) and by the NEW one (proves the
// caller holds the new private key). Both sign under SigningContext.KeyRotation.

import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from './hex.js'
import { lengthPrefixedConcat } from './payload.js'

const encoder = new TextEncoder()

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length)
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i]! - b[i]!
  }
  return a.length - b.length
}

/**
 * The bytes both rotation signatures cover: user uuid, current signing and
 * wrapping public keys, new signing and wrapping public keys, UTC day
 * (YYYY-MM-DD), the current KeyEpoch (decimal) and the roster digest. Never
 * change this once a real rotation has been signed under it.
 */
export function keyRotationPayload(
  userUUID: string,
  oldSigning: Uint8Array,
  oldWrapping: Uint8Array,
  newSigning: Uint8Array,
  newWrapping: Uint8Array,
  utcDay: string,
  keyEpoch: number,
  rosterDigestBytes: Uint8Array,
): Uint8Array {
  return lengthPrefixedConcat([
    encoder.encode(userUUID),
    oldSigning,
    oldWrapping,
    newSigning,
    newWrapping,
    encoder.encode(utcDay),
    encoder.encode(String(keyEpoch)),
    rosterDigestBytes,
  ])
}

/**
 * The 16-byte id of one PIN# or VERIFIED# row in a rotation's roster:
 * SHA-256(SK || signature), truncated. sk is the row's sort key
 * ("PIN#<uuid>" or "VERIFIED#<uuid>"), so an entry is bound to its row.
 */
export function rosterEntryId(sk: string, signature: Uint8Array): Uint8Array {
  const skBytes = encoder.encode(sk)
  const buf = new Uint8Array(skBytes.length + signature.length)
  buf.set(skBytes, 0)
  buf.set(signature, skBytes.length)
  return sha256(buf).slice(0, 16)
}

/**
 * The digest of a rotation's roster: SHA-256 over the entry count (decimal)
 * and the entries sorted bytewise, length-prefixed. Order-independent; an
 * empty roster still has a digest.
 */
export function rosterDigest(entries: readonly Uint8Array[]): Uint8Array {
  const sorted = [...entries].sort(compareBytes)
  return sha256(lengthPrefixedConcat([encoder.encode(String(sorted.length)), ...sorted]))
}

/**
 * The AAD for a rotation handoff row's wrap of a group key to the user's NEW
 * X25519 key: user uuid, group id, generation (zero-padded to six digits) and
 * the public key it is wrapped to (hex). Row-specific on purpose, so a swapped
 * HANDOFF# row fails to open. Never change this once a real handoff row exists.
 */
export function handoffWrapAAD(
  userUUID: string,
  groupId: string,
  generation: number,
  newWrappingPublicKey: Uint8Array,
): Uint8Array {
  const gen = generation.toString().padStart(6, '0')
  return encoder.encode(
    `USER#${userUUID}:HANDOFF#${groupId}:GEN#${gen}:KEY#${bytesToHex(newWrappingPublicKey)}`,
  )
}
