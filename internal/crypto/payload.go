package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"
)

// SignedPayload builds the canonical byte string a post or comment signature
// covers, per docs/DESIGN.md "The cryptographic core": the author uuid, the
// group id, the item's own sort key, the generation number, the UTC signing
// day, and a hash of the ciphertext. Binding all of it — not just the
// plaintext body — is what stops a genuinely-signed item from being
// relocated to a different address with its signature still verifying.
//
// The signing day is redundant for a post, whose sort key already carries
// it, and load-bearing for a comment, whose sort key does not — callers
// still pass it for both, since the payload format itself does not vary
// between the two, only whether the field duplicates information available
// elsewhere.
//
// Encoding: each field is written as a 4-byte big-endian length prefix
// followed by its bytes, concatenated in the field order above, with the
// ciphertext hash computed as raw SHA-256 (32 bytes, no further encoding).
// Length-prefixing avoids the ambiguity a bare separator has — a field
// containing the separator byte — at the cost of 4 bytes per field, which is
// immaterial next to an Ed25519 signature. generation is encoded as its
// decimal string representation, not raw bytes, so the payload is stable
// under any future change to how generation numbers are stored.
//
// This encoding must not change once real signed data exists: doing so is
// the same permanent-lockout class of mistake #20 and DESIGN.md describe for
// key derivation, applied here to signature verification instead — every
// existing signature would stop verifying under a re-encoded payload.
func SignedPayload(authorUUID, groupID, sortKey string, generation uint64, utcDay string, ciphertext []byte) []byte {
	ciphertextHash := sha256.Sum256(ciphertext)

	fields := [][]byte{
		[]byte(authorUUID),
		[]byte(groupID),
		[]byte(sortKey),
		[]byte(strconv.FormatUint(generation, 10)),
		[]byte(utcDay),
		ciphertextHash[:],
	}

	var size int
	for _, f := range fields {
		size += 4 + len(f)
	}

	out := make([]byte, 0, size)
	for _, f := range fields {
		out = appendLengthPrefixed(out, f)
	}
	return out
}

func appendLengthPrefixed(out, field []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(field)))
	out = append(out, lenBuf[:]...)
	out = append(out, field...)
	return out
}
