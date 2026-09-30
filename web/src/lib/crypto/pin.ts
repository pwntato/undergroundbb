// Signed key pins -- issue #63, docs/DESIGN.md "Key pinning and verification".
//
// A pin is the pinning user's own signed record of the key set they saw for
// another user: that user's current X25519 wrapping key and every Ed25519
// signing key they have held (current and superseded), as a SET. PIN# rows
// live on the server, so the signature is the only thing that makes them
// trustworthy: a pin that does not verify is not a pin.
//
// evaluatePin is pure and never throws on malformed input. It answers one
// question: does the key set the server serves for a user match what I signed
// earlier?
//
//   - first-sight: no pin. The caller may pin what it sees (trust on first
//     use), with the usual limit that a lie on the very first sighting is
//     undetectable here; fingerprint verification is the control for that.
//   - match: a valid pin exists and the served set equals it exactly.
//   - mismatch: a valid pin exists and the served set differs. HARD BLOCK.
//     This deliberately includes a set that only ADDS a key: a server that
//     invents a "superseded" key for someone would look exactly like that, so
//     an extension is not accepted on the pin alone. Accepting a legitimate
//     rotation needs a signed continuity link from the old key (#62).
//   - bad-signature: the pin does not verify under the caller's own key, or
//     is not a well-formed pin for this user pair. Treated as no pin AND as
//     tampering; never as first-sight, or the server could reset any pin by
//     corrupting it.
//   - stale-signer: the pin was signed under a key other than the caller's
//     current one (a rotation happened; #62 re-signs pins). It cannot be
//     verified here, so the caller must not treat the user as pinned.
//
// Absence is indistinguishable from first contact: the server can delete a pin
// and this returns first-sight. DESIGN.md states that limit; it is not closed
// here.

import { base64ToBytes } from './base64.js'
import { SigningContext, verify } from './ed25519.js'

const encoder = new TextEncoder()

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length)
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i]! - b[i]!
  }
  return a.length - b.length
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

function lengthPrefixedConcat(fields: readonly Uint8Array[]): Uint8Array {
  let size = 0
  for (const f of fields) size += 4 + f.length
  const out = new Uint8Array(size)
  let offset = 0
  for (const f of fields) {
    new DataView(out.buffer, out.byteOffset + offset, 4).setUint32(0, f.length, false)
    out.set(f, offset + 4)
    offset += 4 + f.length
  }
  return out
}

/**
 * Builds the canonical byte string a PIN# signature covers. Must match
 * internal/crypto/pin.go's PinPayload byte-for-byte (pinned by the shared
 * vectors). signingKeys is a set: it is sorted bytewise, so order does not
 * matter. Sign under SigningContext.Pin. Never change this once a real pin
 * exists.
 */
export function pinPayload(
  pinnerUUID: string,
  pinnedUUID: string,
  pinnerSigningPublicKey: Uint8Array,
  wrappingPublicKey: Uint8Array,
  signingKeys: readonly Uint8Array[],
): Uint8Array {
  const sorted = [...signingKeys].sort(compareBytes)
  return lengthPrefixedConcat([
    encoder.encode(pinnerUUID),
    encoder.encode(pinnedUUID),
    pinnerSigningPublicKey,
    wrappingPublicKey,
    encoder.encode(String(sorted.length)),
    ...sorted,
  ])
}

/** A pin as served by GET /api/pins (all keys base64). */
export interface PinRecord {
  readonly pinnedUserId: string
  readonly signingPublicKeys: readonly string[]
  readonly wrappingPublicKey: string
  readonly pinnerSigningPublicKey: string
  readonly signature: string
}

/** A user's keys as served by GET /api/users/{id}. */
export interface ServedUserKeys {
  readonly signingPublicKey: string
  readonly supersededSigningKeys: readonly { readonly publicKey: string }[]
  readonly wrappingPublicKey: string
}

export type PinVerdict = 'first-sight' | 'match' | 'mismatch' | 'bad-signature' | 'stale-signer'

function decode(b64: string): Uint8Array | null {
  try {
    return base64ToBytes(b64)
  } catch {
    return null
  }
}

/** Decodes and dedupes a key list; null if any entry is undecodable. */
function keySet(keys: readonly string[]): Uint8Array[] | null {
  const out: Uint8Array[] = []
  for (const k of keys) {
    const b = decode(k)
    if (!b) return null
    if (!out.some((o) => bytesEqual(o, b))) out.push(b)
  }
  return out
}

function sameSet(a: readonly Uint8Array[], b: readonly Uint8Array[]): boolean {
  return a.length === b.length && a.every((x) => b.some((y) => bytesEqual(x, y)))
}

/** The signing keys a served projection claims, current plus superseded. */
export function servedSigningKeySet(served: ServedUserKeys): string[] | null {
  const keys = [served.signingPublicKey, ...served.supersededSigningKeys.map((k) => k.publicKey)]
  return keySet(keys) ? keys : null
}

export interface EvaluatePinInput {
  /** The caller's own user id and CURRENT signing public key. */
  readonly pinnerUserId: string
  readonly pinnerSigningPublicKey: Uint8Array
  readonly pinnedUserId: string
  /** The caller's stored pin for pinnedUserId, if the server returned one. */
  readonly pin: PinRecord | undefined
  readonly served: ServedUserKeys
}

export function evaluatePin(input: EvaluatePinInput): PinVerdict {
  const { pinnerUserId, pinnerSigningPublicKey, pinnedUserId, pin, served } = input
  if (!pin) return 'first-sight'
  if (pin.pinnedUserId !== pinnedUserId) return 'bad-signature'

  const signer = decode(pin.pinnerSigningPublicKey)
  const wrapping = decode(pin.wrappingPublicKey)
  const signature = decode(pin.signature)
  const pinnedKeys = keySet(pin.signingPublicKeys)
  if (!signer || !wrapping || !signature || !pinnedKeys || pinnedKeys.length === 0) {
    return 'bad-signature'
  }
  if (!bytesEqual(signer, pinnerSigningPublicKey)) return 'stale-signer'

  const payload = pinPayload(pinnerUserId, pinnedUserId, signer, wrapping, pinnedKeys)
  if (!verify(signer, SigningContext.Pin, payload, signature)) return 'bad-signature'

  const servedKeys = keySet(servedSigningKeySet(served) ?? [])
  const servedWrapping = decode(served.wrappingPublicKey)
  if (!servedKeys || !servedWrapping) return 'mismatch'
  if (!sameSet(pinnedKeys, servedKeys) || !bytesEqual(wrapping, servedWrapping)) return 'mismatch'
  return 'match'
}
