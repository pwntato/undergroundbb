// The canonical signed payload for posts and comments, matching
// internal/crypto/payload.go byte-for-byte (see testdata/vectors.json's
// "signed_payload" section).

import { sha256 } from '@noble/hashes/sha2.js'

/**
 * Builds the canonical byte string a post or comment signature covers, per
 * docs/DESIGN.md "The cryptographic core": the author uuid, the group id,
 * the item's own sort key, the generation number, the UTC signing day, and
 * a hash of the ciphertext. Binding all of it — not just the plaintext
 * body — is what stops a genuinely-signed item from being relocated to a
 * different address with its signature still verifying.
 *
 * Encoding: each field is written as a 4-byte big-endian length prefix
 * followed by its bytes, concatenated in the field order above, with the
 * ciphertext hash computed as raw SHA-256 (32 bytes, no further encoding).
 * generation is encoded as its decimal string representation, matching
 * Go's strconv.FormatUint.
 *
 * This encoding must not change once real signed data exists: doing so
 * would stop every existing signature from verifying.
 */
export function signedPayload(
  authorUUID: string,
  groupID: string,
  sortKey: string,
  generation: bigint | number,
  utcDay: string,
  ciphertext: Uint8Array,
): Uint8Array {
  const ciphertextHash = sha256(ciphertext)
  const encoder = new TextEncoder()

  const fields = [
    encoder.encode(authorUUID),
    encoder.encode(groupID),
    encoder.encode(sortKey),
    encoder.encode(generation.toString()),
    encoder.encode(utcDay),
    ciphertextHash,
  ]

  let size = 0
  for (const f of fields) size += 4 + f.length

  const out = new Uint8Array(size)
  let offset = 0
  for (const f of fields) {
    offset = appendLengthPrefixed(out, offset, f)
  }
  return out
}

function appendLengthPrefixed(out: Uint8Array, offset: number, field: Uint8Array): number {
  const view = new DataView(out.buffer, out.byteOffset + offset, 4)
  view.setUint32(0, field.length, false)
  out.set(field, offset + 4)
  return offset + 4 + field.length
}
