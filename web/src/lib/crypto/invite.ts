// Invite handshake's signed payloads, matching internal/crypto/invite.go
// byte-for-byte (see testdata/vectors.json's "invite_creation" and
// "invite_acceptance" sections).

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
