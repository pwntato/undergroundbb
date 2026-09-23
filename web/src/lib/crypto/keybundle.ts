// The plaintext wrapped under WrappedPrivateKeys / RecoveryWrappedPrivateKeys,
// matching internal/crypto/keybundle.go byte-for-byte (see
// testdata/vectors.json's "key_bundle" section).

/** The only defined encoding of a KeyBundle so far. See encodeKeyBundle. */
export const KEY_BUNDLE_VERSION_1 = 1

/**
 * Thrown by decodeKeyBundle when the version byte is not one this build
 * knows how to parse — distinguished from a malformed blob (see
 * MalformedKeyBundleError) because a future version reading back an
 * old-format blob (or vice versa) is a defined, expected case, not
 * corruption.
 */
export class UnsupportedKeyBundleVersionError extends Error {
  constructor() {
    super('crypto: unsupported key bundle version')
    this.name = 'UnsupportedKeyBundleVersionError'
  }
}

/**
 * Thrown by decodeKeyBundle when a KeyBundleVersion1 blob's length fields
 * do not describe the bytes actually present — truncated, padded, or
 * otherwise not a value encodeKeyBundle could have produced.
 */
export class MalformedKeyBundleError extends Error {
  constructor() {
    super('crypto: malformed key bundle')
    this.name = 'MalformedKeyBundleError'
  }
}

/** ed25519.SeedSize / SEED_SIZE in ed25519.ts. */
const SIGNING_SEED_SIZE = 32
/** X25519's fixed private-scalar width, matching x25519.ts's KEY_LEN. */
const WRAPPING_KEY_SIZE = 32

/**
 * The plaintext a client wraps under the password- or
 * recovery-code-derived key at registration and unwraps at login,
 * change-password or recovery. Holds only the two PRIVATE scalars:
 *
 * - signingSeed: the 32-byte Ed25519 seed (ed25519.ts's SigningKey.seed) —
 *   NOT Go's 64-byte ed25519.PrivateKey encoding, which appends the public
 *   key the seed already determines.
 * - wrappingPrivateKey: the 32-byte X25519 private scalar
 *   (x25519.ts's WrappingKey.privateKey).
 *
 * Both public keys are deliberately excluded — they are already sent and
 * stored in plaintext separately (registerRequest.signingPublicKey /
 * wrappingPublicKey server-side) and are cheaply re-derivable from the
 * private scalars above besides, so carrying them here too would be
 * redundant ciphertext with no property it adds.
 */
export interface KeyBundle {
  readonly signingSeed: Uint8Array
  readonly wrappingPrivateKey: Uint8Array
}

/**
 * Serializes b as KeyBundleVersion1: a 1-byte version tag followed by each
 * field as a 4-byte big-endian length prefix and its bytes, in the field
 * order signingSeed then wrappingPrivateKey — the same length-prefixed
 * convention signedPayload uses (see payload.ts), chosen specifically so a
 * future version can add a field (a third keypair, key-rotation metadata)
 * without redefining what today's fixed-width bytes mean.
 *
 * This must be treated as append-only in exactly the sense DESIGN.md
 * already applies elsewhere (Argon2id parameters, the credential-wrap
 * AAD): once a real user's blob is encrypted under this encoding,
 * decodeKeyBundle must go on accepting KeyBundleVersion1 forever, even
 * after a KeyBundleVersion2 exists. Changing what version 1 means, rather
 * than introducing a version 2, is the unrecoverable mistake — every
 * existing wrap silently becomes unreadable with nothing on the server
 * (which never sees this plaintext at all) able to detect or repair it.
 *
 * Throws MalformedKeyBundleError if either field is not the exact length
 * decodeKeyBundle requires (SIGNING_SEED_SIZE, WRAPPING_KEY_SIZE) — caught
 * here rather than left to surface as a decode failure at the caller's next
 * login. This is not hypothetical: ed25519.ts's SigningKey doc comment
 * names toGoPrivateKeyBytes() (64 bytes, seed||pubkey) as what "cross[es]
 * the wire," and this bundle is the one place that deliberately wants the
 * bare 32-byte seed instead — signup code that reused the wrong helper
 * would otherwise wrap and register successfully, then fail every
 * subsequent login with no way for the server, which never sees this
 * plaintext, to detect or repair it.
 */
export function encodeKeyBundle(b: KeyBundle): Uint8Array {
  if (
    b.signingSeed.length !== SIGNING_SEED_SIZE ||
    b.wrappingPrivateKey.length !== WRAPPING_KEY_SIZE
  ) {
    throw new MalformedKeyBundleError()
  }

  const fields = [b.signingSeed, b.wrappingPrivateKey]

  let size = 1
  for (const f of fields) size += 4 + f.length

  const out = new Uint8Array(size)
  out[0] = KEY_BUNDLE_VERSION_1
  let offset = 1
  for (const f of fields) {
    offset = appendLengthPrefixed(out, offset, f)
  }
  return out
}

/**
 * Reverses encodeKeyBundle, validating the two fixed lengths
 * encodeKeyBundle always produces (SIGNING_SEED_SIZE and
 * WRAPPING_KEY_SIZE) rather than trusting whatever lengths the blob's own
 * prefixes claim — a wrapped blob only reaches this function after the
 * AEAD tag already verified, so a length mismatch here means an encoder
 * bug, not tampering, but callers are better served by a clear decode
 * error than a silent short read.
 */
export function decodeKeyBundle(data: Uint8Array): KeyBundle {
  if (data.length < 1) {
    throw new MalformedKeyBundleError()
  }
  const version = data[0]
  if (version !== KEY_BUNDLE_VERSION_1) {
    throw new UnsupportedKeyBundleVersionError()
  }

  let offset = 1
  const [signingSeed, afterSeed] = readLengthPrefixed(data, offset)
  if (signingSeed.length !== SIGNING_SEED_SIZE) {
    throw new MalformedKeyBundleError()
  }
  offset = afterSeed

  const [wrappingPrivateKey, afterWrap] = readLengthPrefixed(data, offset)
  if (wrappingPrivateKey.length !== WRAPPING_KEY_SIZE) {
    throw new MalformedKeyBundleError()
  }
  offset = afterWrap

  if (offset !== data.length) {
    throw new MalformedKeyBundleError()
  }

  return { signingSeed, wrappingPrivateKey }
}

function appendLengthPrefixed(out: Uint8Array, offset: number, field: Uint8Array): number {
  const view = new DataView(out.buffer, out.byteOffset + offset, 4)
  view.setUint32(0, field.length, false)
  out.set(field, offset + 4)
  return offset + 4 + field.length
}

/** Reads one encodeKeyBundle-style length-prefixed field starting at offset. */
function readLengthPrefixed(data: Uint8Array, offset: number): [Uint8Array, number] {
  if (data.length < offset + 4) {
    throw new MalformedKeyBundleError()
  }
  const view = new DataView(data.buffer, data.byteOffset + offset, 4)
  const n = view.getUint32(0, false)
  const fieldStart = offset + 4
  const fieldEnd = fieldStart + n
  if (fieldEnd > data.length) {
    throw new MalformedKeyBundleError()
  }
  return [data.slice(fieldStart, fieldEnd), fieldEnd]
}
