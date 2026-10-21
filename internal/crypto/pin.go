package crypto

import (
	"bytes"
	"crypto/sha256"
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
// current key. Checking it against the key that was current on the signed day
// comes with the key-history lookup (#62, later slice).
//
// signingKeys is a set: it is sorted bytewise before encoding, so the same
// keys in any order sign identically, and the caller need not agree on an
// order with the verifier. The count is signed explicitly, ahead of the keys,
// so a set cannot be re-cut into a different number of fields with the same
// concatenation.
//
// utcDay is the UTC day the pin was signed ("2006-01-02"), so a later slice can
// check it against the key that was current that day (#62) and nothing needs
// re-signing when the pinner rotates. pinnedKeyEpoch is the pinned user's
// KeyEpoch as the pinner saw it: a served epoch below it is a rollback.
//
// Field order: pinner uuid, pinned uuid, pinner signing key, wrapping key,
// day, epoch (decimal), key count (decimal), then the sorted keys.
//
// Sign this payload under ContextPin (v2); verify it the same way. Same
// length-prefixed encoding as the other payloads in this package, and the same
// warning: this must never change once a real pin has been signed under it.
func PinPayload(pinnerUUID, pinnedUUID string, pinnerSigningPublicKey, wrappingPublicKey []byte, signingKeys [][]byte, pinnedKeyEpoch uint64, utcDay string) []byte {
	sorted := make([][]byte, len(signingKeys))
	copy(sorted, signingKeys)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })

	fields := [][]byte{
		[]byte(pinnerUUID),
		[]byte(pinnedUUID),
		pinnerSigningPublicKey,
		wrappingPublicKey,
		[]byte(utcDay),
		[]byte(strconv.FormatUint(pinnedKeyEpoch, 10)),
		[]byte(strconv.Itoa(len(sorted))),
	}
	fields = append(fields, sorted...)
	return lengthPrefixedConcat(fields)
}

// RosterEntryID is the 16-byte identifier of one PIN# or VERIFIED# row in a
// key rotation's roster: SHA-256(SK || signature), truncated -- see
// docs/DESIGN.md, "What a key change looks like to others." sk is the row's
// sort key ("PIN#<uuid>" or "VERIFIED#<uuid>"), so the entry is bound to the
// row it signs and a signature cannot be listed under another row.
func RosterEntryID(sk string, signature []byte) []byte {
	h := sha256.New()
	h.Write([]byte(sk))
	h.Write(signature)
	return h.Sum(nil)[:16]
}

// RosterDigest is the digest of a rotation's roster: SHA-256 over the entry
// count (decimal) and the entries sorted bytewise, length-prefixed like every
// payload here. The set is order-independent, and an empty roster still has a
// digest, so a rotation by a user with no pins is distinguishable from a
// payload that omitted the field.
func RosterDigest(entries [][]byte) []byte {
	sorted := make([][]byte, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })
	fields := append([][]byte{[]byte(strconv.Itoa(len(sorted)))}, sorted...)
	sum := sha256.Sum256(lengthPrefixedConcat(fields))
	return sum[:]
}
