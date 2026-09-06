package crypto

import (
	"crypto/ed25519"
)

// SigningContext identifies which protocol a signature belongs to. It is
// prepended to every signed payload so a signature valid in one context can
// never be replayed as valid in another — a signed login challenge must not
// verify as a signed post, and a signed post must not verify as a role grant,
// even if the remaining bytes happen to coincide.
type SigningContext string

const (
	// ContextLoginChallenge signs a server-issued login challenge nonce.
	ContextLoginChallenge SigningContext = "underground-bb:login-challenge:v1"
	// ContextPost signs a post's address-bound payload.
	ContextPost SigningContext = "underground-bb:post:v1"
	// ContextComment signs a comment's address-bound payload.
	ContextComment SigningContext = "underground-bb:comment:v1"
	// ContextRoleGrant signs a role grant in the group's chain of trust.
	ContextRoleGrant SigningContext = "underground-bb:role-grant:v1"
	// ContextInvite signs an invite handshake step.
	ContextInvite SigningContext = "underground-bb:invite:v1"
	// ContextTrustAnchor signs a group's creator-signed trust anchor.
	ContextTrustAnchor SigningContext = "underground-bb:trust-anchor:v1"
)

// GenerateSigningKey generates a new Ed25519 keypair.
func GenerateSigningKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// Sign signs message under the given context, binding the signature to that
// context so it cannot be replayed as a signature over the same bytes in a
// different protocol.
func Sign(priv ed25519.PrivateKey, ctx SigningContext, message []byte) []byte {
	return ed25519.Sign(priv, contextualize(ctx, message))
}

// Verify checks a signature produced by Sign for the same context and
// message. It returns false for a wrong context, a wrong message, a wrong
// key, or a malformed signature — callers must not try to distinguish these.
func Verify(pub ed25519.PublicKey, ctx SigningContext, message, signature []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, contextualize(ctx, message), signature)
}

func contextualize(ctx SigningContext, message []byte) []byte {
	out := make([]byte, 0, len(ctx)+1+len(message))
	out = append(out, ctx...)
	out = append(out, 0x00)
	out = append(out, message...)
	return out
}
