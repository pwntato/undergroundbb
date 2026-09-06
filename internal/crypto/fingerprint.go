package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
)

// fingerprintDomain is the domain-separation prefix folded into every
// fingerprint, so a fingerprint can never collide with a hash computed for
// any other purpose over the same two public keys.
const fingerprintDomain = "underground-bb:fingerprint:v1"

// fingerprintDigits is the displayed length of a fingerprint: 60 decimal
// digits in twelve groups of five, per docs/DESIGN.md.
const fingerprintDigits = 60

// Fingerprint computes a user's fingerprint per docs/DESIGN.md: SHA-256 over
// a domain-separation prefix followed by both of the user's current public
// keys in a fixed order (Ed25519 signing key, then X25519 wrapping key),
// displayed as 60 decimal digits in twelve groups of five.
//
// Both keys are covered because the X25519 key is what substitution attacks
// actually target (group keys wrap to it); covering only the signing key
// would let an operator swap the wrapping key while a fingerprint comparison
// still passed. Only current keys are covered — a superseded Ed25519 key
// from a prior rotation is never included, so rotating does not change a
// fingerprint a counterparty already verified.
//
// Decimal digits rather than hex are what make reading the whole value aloud
// realistic, which is the only fingerprint comparison worth anything. A
// 256-bit digest needs up to 78 decimal digits to represent in full; taking
// only the LOW-ORDER 60 digits of that decimal expansion (zero-padded on the
// left to a full 78 digits first, so the cut point is always the same
// position regardless of the digest's magnitude) is an arbitrary but fixed
// and collision-resistant-enough truncation — the two keys already
// determine a random 256-bit value, and 60 decimal digits (~199 bits) is far
// beyond what grinding a preimage match at both ends of a comparison could
// feasibly attack.
func Fingerprint(signingPub ed25519.PublicKey, wrappingPub []byte) (string, error) {
	if len(signingPub) != ed25519.PublicKeySize {
		return "", ErrInvalidPublicKey
	}
	if len(wrappingPub) != 32 {
		return "", ErrInvalidPublicKey
	}

	h := sha256.New()
	h.Write([]byte(fingerprintDomain))
	h.Write(signingPub)
	h.Write(wrappingPub)
	digest := h.Sum(nil)

	return formatFingerprint(digest), nil
}

// formatFingerprint renders a 32-byte digest as its decimal expansion
// zero-padded to 78 digits (2^256-1 needs at most 78 decimal digits), takes
// the low-order 60 of those digits, and groups them in fives separated by
// hyphens.
func formatFingerprint(digest []byte) string {
	n := new(big.Int).SetBytes(digest)
	full := fmt.Sprintf("%078s", n.String())
	digits := full[len(full)-fingerprintDigits:]

	var b strings.Builder
	b.Grow(fingerprintDigits + fingerprintDigits/5 - 1)
	for i := 0; i < len(digits); i += 5 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(digits[i : i+5])
	}
	return b.String()
}
