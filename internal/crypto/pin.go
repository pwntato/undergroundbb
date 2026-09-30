package crypto

import (
	"bytes"
	"sort"
	"strconv"
)

// PinPayload builds the canonical byte string a PIN# signature covers -- see
// docs/DESIGN.md, "Key pinning and verification." A pin is the pinning user's
// signed record of the key set they saw for another user: the pinned user's
// current X25519 wrapping key and every Ed25519 signing key that user has
// held (current and superseded), as a set.
//
// The pinner's own uuid and the pinned uuid are both signed, so a pin cannot
// be copied to a different pinned user's row or into someone else's
// partition. pinnerSigningPublicKey is the key the pin is signed under: it is
// what the "interval of the pinning key" in the design reduces to. It is a
// server-served field and untrusted: a client verifies a pin only under its own
// current key and treats any other recorded signer as tampering, never as a
// stale pin, until #62 adds a signed continuity link.
//
// signingKeys is a set: it is sorted bytewise before encoding, so the same
// keys in any order sign identically, and the caller need not agree on an
// order with the verifier. The count is signed explicitly, ahead of the keys,
// so a set cannot be re-cut into a different number of fields with the same
// concatenation.
//
// Sign this payload under ContextPin; verify it the same way. Same
// length-prefixed encoding as the other payloads in this package, and the same
// warning: this must never change once a real pin has been signed under it.
func PinPayload(pinnerUUID, pinnedUUID string, pinnerSigningPublicKey, wrappingPublicKey []byte, signingKeys [][]byte) []byte {
	sorted := make([][]byte, len(signingKeys))
	copy(sorted, signingKeys)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })

	fields := [][]byte{
		[]byte(pinnerUUID),
		[]byte(pinnedUUID),
		pinnerSigningPublicKey,
		wrappingPublicKey,
		[]byte(strconv.Itoa(len(sorted))),
	}
	fields = append(fields, sorted...)
	return lengthPrefixedConcat(fields)
}
