package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
)

// InviteCreationPayload builds the canonical byte string the inviter signs
// at step 1 of the invite handshake -- see docs/DESIGN.md, "Invites -- the
// signed handshake": "Signs {invite_id, group_id, inviter_pubkey,
// expires_at}." Binding the invite id and group id is what stops a
// genuinely-signed invite from being replayed under a different id or into
// a different group; binding the inviter's own current signing public key is
// what a later verifier checks the signature against, so a copy of this
// payload cannot be replayed under a key the inviter no longer controls
// (or never did). expiresAt is signed too, so the server cannot extend or
// shorten an invite's lifetime after the fact without invalidating the
// signature -- see #38's own issue comments on why the stored TTL is set
// FROM this signed value rather than independently chosen.
//
// expiresAt is encoded as RFC 3339 (UTC), matching every other timestamp
// this codebase signs or stores as a string field, rather than a raw epoch
// integer -- consistent with docs/DESIGN.md's general preference for
// human-legible timestamps in signed/stored string fields, and avoiding a
// second binary-integer-encoding convention alongside the length-prefixed
// scheme this payload already uses for its other fields.
//
// ephemeral_pubkey does NOT appear here -- see docs/DESIGN.md's now-resolved
// invite-handshake note: it was signed in an earlier draft, played no part
// in verifying or completing the handshake, and has been dropped rather
// than carried forward as a field with no defined semantics.
//
// Sign this payload under ContextInvite; verify it the same way. Same
// length-prefixed encoding as TrustAnchorPayload/RoleGrantPayload, for the
// same reason, and the same permanent-lockout warning: this must never
// change once a real invite has been signed under it.
func InviteCreationPayload(inviteID, groupID string, inviterPublicKey []byte, expiresAt string) []byte {
	fields := [][]byte{
		[]byte(inviteID),
		[]byte(groupID),
		inviterPublicKey,
		[]byte(expiresAt),
	}
	return lengthPrefixedConcat(fields)
}

// InviteAcceptancePayload builds the canonical byte string the invitee signs
// at step 2 of the invite handshake -- see docs/DESIGN.md, "Invites -- the
// signed handshake": "Verifies the inviter's signature, then signs
// {invite_id, ed25519_pub, x25519_pub} with their own key." Binding the
// invite id is what ties this acceptance to one specific invite rather than
// any invite the same invitee might sign for; binding both of the invitee's
// own current public keys is what step 3 (the inviter's client) verifies
// before ever wrapping the group key to them -- see that step's own
// reasoning for why the wrap must go to the key that was SIGNED here, never
// a key the server offers unilaterally.
//
// Sign this payload under ContextInvite (the same context step 1 uses --
// the two payloads have different field shapes and can never be confused
// for one another regardless of sharing a context, since Verify checks the
// message bytes too); verify it the same way. Same length-prefixed
// encoding, same permanent-lockout warning.
func InviteAcceptancePayload(inviteID string, invitedEd25519PublicKey, invitedX25519PublicKey []byte) []byte {
	fields := [][]byte{
		[]byte(inviteID),
		invitedEd25519PublicKey,
		invitedX25519PublicKey,
	}
	return lengthPrefixedConcat(fields)
}

// inviteMACInfo labels HKDF's info parameter (alongside inviteID) with the
// operation deriving the key, matching hkdfInfo's own reasoning in
// x25519.go: without a label, a key derived here would collide with one
// derived from the same seed for any other purpose. Must match
// web/src/lib/crypto/invite.ts's INVITE_MAC_INFO exactly.
const inviteMACInfo = "underground-bb:invite-mac:v1"

// DeriveInviteMACKey derives the per-invite MAC key k that binds step 2's
// acceptance to whoever holds the invite link, closing the gap plain
// signature verification leaves open: InviteAcceptancePayload proves the
// invitee's Ed25519/X25519 keys are consistent with EACH OTHER, but every
// value the inviter's client checks it against (the keys and the
// signature) arrives in the same server response, so a malicious server
// can mint its own keypair, sign its own InviteAcceptancePayload, and pass
// that check without any real invitee involved at all.
//
// k is HKDF-SHA256(inviterSigningSeed, info = inviteMACInfo || inviteID,
// length 32), computed from the INVITER's own long-term Ed25519 seed --
// never stored anywhere, and re-derivable by the inviter's own client on
// any future login purely from (seed, inviteID), exactly like
// deriveWrappingKey's own no-storage reasoning. The invite link's URL
// fragment carries k itself (base64url, alongside the fingerprint) --
// browsers never transmit a URL fragment to any server, so the one party
// who can compute MAC_k is the one party who was actually handed the link.
// binding inviteID into HKDF's info parameter (rather than the ikm) is
// what makes k unique per invite despite deriving from the same
// long-term seed every time.
//
// inviterSigningSeed is the bare 32-byte Ed25519 seed (ed25519.PrivateKey's
// first 32 bytes, matching signingKeyFromSeed's own encoding on the
// TypeScript side) -- not the 64-byte Go-encoded private key, since the
// public half carries no entropy of its own and including it would only
// change the derivation for no benefit.
func DeriveInviteMACKey(inviterSigningSeed []byte, inviteID string) ([]byte, error) {
	info := inviteMACInfo + inviteID
	return hkdf.Key(sha256.New, inviterSigningSeed, nil, info, sha256.Size)
}

// ComputeInviteMAC computes MAC_k(payload) -- HMAC-SHA256 keyed by the
// per-invite key DeriveInviteMACKey derives, over the exact same
// InviteAcceptancePayload bytes the invitee's Ed25519 signature already
// covers. Reusing that payload rather than defining a third byte encoding
// means the MAC and the signature can never be checked against
// inconsistent views of "which keys were accepted."
func ComputeInviteMAC(macKey, payload []byte) []byte {
	mac := hmac.New(sha256.New, macKey)
	mac.Write(payload)
	return mac.Sum(nil)
}

// VerifyInviteMAC reports whether mac is ComputeInviteMAC(macKey, payload),
// using hmac.Equal for the constant-time comparison HMAC verification
// requires -- a plain byte comparison would leak timing information an
// attacker could use to forge a valid MAC one byte at a time.
func VerifyInviteMAC(macKey, payload, mac []byte) bool {
	return hmac.Equal(ComputeInviteMAC(macKey, payload), mac)
}
