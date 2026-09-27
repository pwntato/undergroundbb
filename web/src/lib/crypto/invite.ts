// Invite handshake's signed payloads, matching internal/crypto/invite.go
// byte-for-byte (see testdata/vectors.json's "invite_creation" and
// "invite_acceptance" sections).

import { hkdf } from '@noble/hashes/hkdf.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'

/**
 * Builds the canonical byte string the inviter signs at step 1 of the
 * invite handshake -- see docs/DESIGN.md, "Invites -- the signed handshake":
 * "Signs {invite_id, group_id, inviter_pubkey, expires_at}." Binding the
 * invite id and group id is what stops a genuinely-signed invite from being
 * replayed under a different id or into a different group; binding the
 * inviter's own current signing public key is what a later verifier checks
 * the signature against.
 *
 * expiresAt is an RFC 3339 (UTC) string, matching every other timestamp
 * this codebase signs or stores as a string field.
 *
 * ephemeral_pubkey does NOT appear here -- see docs/DESIGN.md's now-resolved
 * invite-handshake note: it was signed in an earlier draft, played no part
 * in verifying or completing the handshake, and has been dropped.
 *
 * Sign this payload under ed25519.SigningContext.Invite; verify it the same
 * way. Same length-prefixed encoding as trustAnchorPayload/roleGrantPayload,
 * matching internal/crypto/invite.go's InviteCreationPayload byte-for-byte.
 * This must never change once a real invite has been signed under it.
 */
export function inviteCreationPayload(
  inviteId: string,
  groupId: string,
  inviterPublicKey: Uint8Array,
  expiresAt: string,
): Uint8Array {
  const encoder = new TextEncoder()
  return lengthPrefixedConcat([
    encoder.encode(inviteId),
    encoder.encode(groupId),
    inviterPublicKey,
    encoder.encode(expiresAt),
  ])
}

/**
 * Builds the canonical byte string the invitee signs at step 2 of the
 * invite handshake -- see docs/DESIGN.md, "Invites -- the signed handshake":
 * "Verifies the inviter's signature, then signs {invite_id, ed25519_pub,
 * x25519_pub} with their own key." Binding the invite id ties this
 * acceptance to one specific invite; binding both of the invitee's own
 * current public keys is what step 3 verifies before ever wrapping the
 * group key to them.
 *
 * Sign this payload under ed25519.SigningContext.Invite (the same context
 * step 1 uses -- the two payloads have different field shapes and can never
 * be confused for one another); verify it the same way. Matches
 * internal/crypto/invite.go's InviteAcceptancePayload byte-for-byte. This
 * must never change once a real acceptance has been signed under it.
 */
export function inviteAcceptancePayload(
  inviteId: string,
  invitedEd25519PublicKey: Uint8Array,
  invitedX25519PublicKey: Uint8Array,
): Uint8Array {
  const encoder = new TextEncoder()
  return lengthPrefixedConcat([
    encoder.encode(inviteId),
    invitedEd25519PublicKey,
    invitedX25519PublicKey,
  ])
}

/**
 * Labels HKDF's info parameter (alongside inviteId) with the operation
 * deriving the key -- matches internal/crypto/invite.go's inviteMACInfo
 * exactly.
 */
const INVITE_MAC_INFO = 'underground-bb:invite-mac:v1'

/** Length in bytes of an Ed25519 seed -- deriveInviteMACKey's ikm. */
const SIGNING_SEED_SIZE = 32

/** Length in bytes of an HMAC-SHA256 tag / deriveInviteMACKey's output. */
const INVITE_MAC_KEY_SIZE = 32

/**
 * Derives the per-invite MAC key k that binds step 2's acceptance to
 * whoever holds the invite link -- see internal/crypto/invite.go's
 * DeriveInviteMACKey for the full reasoning this must match byte-for-byte.
 * Plain signature verification alone lets a malicious server mint its own
 * keypair, sign its own inviteAcceptancePayload, and pass: every value
 * step 3 checks arrives in the same response the server controls. k closes
 * that gap because it never crosses the server at all -- derived once at
 * creation from the inviter's own long-term Ed25519 seed, carried in the
 * link's URL fragment (which browsers never transmit), and re-derivable by
 * the inviter's client from (seed, inviteId) alone at step 3, on any
 * future login, with nothing stored.
 *
 * inviterSigningSeed is the bare 32-byte Ed25519 seed
 * (ed25519.SigningKey.seed on this side, the same value
 * signingKeyFromSeed accepts) -- never the derived public key, which
 * carries no entropy of its own.
 */
export function deriveInviteMACKey(inviterSigningSeed: Uint8Array, inviteId: string): Uint8Array {
  if (inviterSigningSeed.length !== SIGNING_SEED_SIZE) {
    throw new Error('crypto: invalid signing seed')
  }
  const info = new TextEncoder().encode(INVITE_MAC_INFO + inviteId)
  return hkdf(sha256, inviterSigningSeed, undefined, info, INVITE_MAC_KEY_SIZE)
}

/**
 * Computes MAC_k(payload) -- HMAC-SHA256 keyed by deriveInviteMACKey's
 * output, over the exact same inviteAcceptancePayload bytes the invitee's
 * Ed25519 signature already covers, so the MAC and the signature can never
 * be checked against inconsistent views of "which keys were accepted."
 * Matches internal/crypto/invite.go's ComputeInviteMAC byte-for-byte.
 */
export function computeInviteMAC(macKey: Uint8Array, payload: Uint8Array): Uint8Array {
  return hmac(sha256, macKey, payload)
}

/**
 * Verifies mac against computeInviteMAC(macKey, payload) in constant time
 * -- an early-exit comparison (e.g. `===` on two byte arrays, or a loop
 * that returns on the first mismatch) leaks, via timing, how many leading
 * bytes of an attacker-supplied mac happened to match, letting a forgery
 * be built one byte at a time. The XOR-accumulate loop below always
 * touches every byte of both inputs regardless of where they first
 * differ, matching Go's hmac.Equal on the other side of this same check.
 */
export function verifyInviteMAC(macKey: Uint8Array, payload: Uint8Array, mac: Uint8Array): boolean {
  const computed = computeInviteMAC(macKey, payload)
  if (computed.length !== mac.length) {
    return false
  }
  let diff = 0
  for (let i = 0; i < computed.length; i++) {
    diff |= (computed[i] ?? 0) ^ (mac[i] ?? 0)
  }
  return diff === 0
}

function lengthPrefixedConcat(fields: readonly Uint8Array[]): Uint8Array {
  let size = 0
  for (const f of fields) size += 4 + f.length
  const out = new Uint8Array(size)
  let offset = 0
  for (const f of fields) {
    const view = new DataView(out.buffer, out.byteOffset + offset, 4)
    view.setUint32(0, f.length, false)
    out.set(f, offset + 4)
    offset += 4 + f.length
  }
  return out
}
