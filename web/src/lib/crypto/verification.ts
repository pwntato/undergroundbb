// Signed fingerprint verifications -- issue #65, docs/DESIGN.md "Key pinning
// and verification".
//
// A verification is the verifying user's own signed record that they compared
// another user's fingerprint out of band and it matched. It signs the
// fingerprint string itself, which covers both of that user's current public
// keys, so it stops applying the moment either key changes. VERIFIED# rows live
// on the server, so the signature is the only thing that makes them
// trustworthy: a record that does not verify is not a verification.
//
// evaluateVerification is pure and never throws on malformed input. It answers
// one question: does the fingerprint of the keys the server serves for a user
// equal what I signed after comparing it?
//
//   - none: no record. The user is simply not verified; this is the normal case.
//   - verified: a valid record exists and the served keys' fingerprint equals it.
//   - changed: a valid record exists and the served fingerprint differs. The
//     keys the server now serves are not the ones this person compared. A
//     legitimate key change and a substituted key look identical here, so this
//     must be shown as a warning, never as "not verified".
//   - bad-signature: the record does not verify under the caller's own current
//     key, or is not a well-formed record for this user pair. Treated as
//     tampering; NEVER as none. Withholding or deleting a record is still
//     indistinguishable from never having verified, which only costs the badge.

import { base64ToBytes } from './base64.js'
import { SigningContext, verify } from './ed25519.js'
import { lengthPrefixedConcat } from './payload.js'
import { ownSignerAccepted, type OwnKeyHistory } from './own-history.js'
import { isUtcDay } from './pin.js'

const encoder = new TextEncoder()

/**
 * Builds the canonical byte string a VERIFIED# signature covers. Must match
 * internal/crypto/verification.go's VerificationPayload byte-for-byte (pinned
 * by the shared vectors). utcDay is the UTC day signed (YYYY-MM-DD, #62). Sign
 * under SigningContext.Verification (v2). Never change this once a real
 * verification exists.
 */
export function verificationPayload(
  verifierUUID: string,
  verifiedUUID: string,
  verifierSigningPublicKey: Uint8Array,
  fingerprint: string,
  utcDay: string,
): Uint8Array {
  return lengthPrefixedConcat([
    encoder.encode(verifierUUID),
    encoder.encode(verifiedUUID),
    verifierSigningPublicKey,
    encoder.encode(fingerprint),
    encoder.encode(utcDay),
  ])
}

/** A verification as served by GET /api/verifications (keys and signature base64). */
export interface VerificationRecord {
  readonly verifiedUserId: string
  readonly fingerprint: string
  readonly verifierSigningPublicKey: string
  readonly signature: string
  /** The UTC day signed (YYYY-MM-DD), inside the signed payload. */
  readonly signedDay: string
}

export type VerificationVerdict = 'none' | 'verified' | 'changed' | 'bad-signature'

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i])
}

function decode(b64: string): Uint8Array | null {
  try {
    return base64ToBytes(b64)
  } catch {
    return null
  }
}

export interface EvaluateVerificationInput {
  /** The caller's own user id and CURRENT signing public key. */
  readonly verifierUserId: string
  readonly verifierSigningPublicKey: Uint8Array
  /** The caller's verified key history; see EvaluatePinInput.pinnerHistory. */
  readonly verifierHistory?: OwnKeyHistory
  readonly verifiedUserId: string
  /** The caller's stored record for verifiedUserId, if the server returned one. */
  readonly record: VerificationRecord | undefined
  /**
   * The fingerprint of the keys the server serves for verifiedUserId now, or
   * null when it could not be computed (malformed served keys).
   */
  readonly servedFingerprint: string | null
}

export function evaluateVerification(input: EvaluateVerificationInput): VerificationVerdict {
  const { verifierUserId, verifierSigningPublicKey, verifiedUserId, record, servedFingerprint } =
    input
  if (!record) return 'none'
  if (record.verifiedUserId !== verifiedUserId) return 'bad-signature'

  const signer = decode(record.verifierSigningPublicKey)
  const signature = decode(record.signature)
  if (!signer || !signature) return 'bad-signature'
  if (!isUtcDay(record.signedDay)) return 'bad-signature'
  // The recorded signer is untrusted input: only the caller's own current key,
  // or a superseded one their verified history lists this very row under, may
  // verify a record, whatever the row claims.
  if (!bytesEqual(signer, verifierSigningPublicKey)) {
    const listed =
      input.verifierHistory !== undefined &&
      bytesEqual(input.verifierHistory.current, verifierSigningPublicKey) &&
      ownSignerAccepted(
        input.verifierHistory,
        signer,
        record.signedDay,
        `VERIFIED#${verifiedUserId}`,
        signature,
      )
    if (!listed) return 'bad-signature'
  }

  const payload = verificationPayload(
    verifierUserId,
    verifiedUserId,
    signer,
    record.fingerprint,
    record.signedDay,
  )
  if (!verify(signer, SigningContext.Verification, payload, signature)) return 'bad-signature'

  if (servedFingerprint === null || servedFingerprint !== record.fingerprint) return 'changed'
  return 'verified'
}
