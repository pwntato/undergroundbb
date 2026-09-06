package crypto

import (
	"bytes"
	"testing"
)

func TestSignedPayloadDeterministic(t *testing.T) {
	p1 := SignedPayload("author-1", "group-1", "POST#2026-09-06#abcd", 3, "2026-09-06", []byte("ciphertext"))
	p2 := SignedPayload("author-1", "group-1", "POST#2026-09-06#abcd", 3, "2026-09-06", []byte("ciphertext"))
	if !bytes.Equal(p1, p2) {
		t.Fatal("SignedPayload is not deterministic")
	}
}

func TestSignedPayloadDistinguishesEveryField(t *testing.T) {
	base := SignedPayload("author-1", "group-1", "POST#2026-09-06#abcd", 3, "2026-09-06", []byte("ciphertext"))

	cases := map[string][]byte{
		"authorUUID": SignedPayload("author-2", "group-1", "POST#2026-09-06#abcd", 3, "2026-09-06", []byte("ciphertext")),
		"groupID":    SignedPayload("author-1", "group-2", "POST#2026-09-06#abcd", 3, "2026-09-06", []byte("ciphertext")),
		"sortKey":    SignedPayload("author-1", "group-1", "POST#2026-09-06#zzzz", 3, "2026-09-06", []byte("ciphertext")),
		"generation": SignedPayload("author-1", "group-1", "POST#2026-09-06#abcd", 4, "2026-09-06", []byte("ciphertext")),
		"utcDay":     SignedPayload("author-1", "group-1", "POST#2026-09-06#abcd", 3, "2026-09-07", []byte("ciphertext")),
		"ciphertext": SignedPayload("author-1", "group-1", "POST#2026-09-06#abcd", 3, "2026-09-06", []byte("different")),
	}

	for name, other := range cases {
		if bytes.Equal(base, other) {
			t.Errorf("changing %s did not change the payload", name)
		}
	}
}

// TestSignedPayloadFieldBoundariesAreUnambiguous exercises the reason for
// length-prefixing: two different field splits that would concatenate to the
// same bytes under a bare separator must still produce different payloads.
func TestSignedPayloadFieldBoundariesAreUnambiguous(t *testing.T) {
	// "ab" + "c" vs "a" + "bc" as authorUUID/groupID would collide under
	// naive concatenation without length prefixes.
	p1 := SignedPayload("ab", "c", "SK", 1, "2026-09-06", []byte("x"))
	p2 := SignedPayload("a", "bc", "SK", 1, "2026-09-06", []byte("x"))
	if bytes.Equal(p1, p2) {
		t.Fatal("field boundary is ambiguous: (\"ab\",\"c\") and (\"a\",\"bc\") produced the same payload")
	}
}

// TestSignedPayloadSignsUnderContext verifies the payload is meant to be
// signed with ContextPost or ContextComment, not used unsigned.
func TestSignedPayloadSignsUnderContext(t *testing.T) {
	pub, priv, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	payload := SignedPayload("author-1", "group-1", "POST#2026-09-06#abcd", 3, "2026-09-06", []byte("ciphertext"))

	sig, err := Sign(priv, ContextPost, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, ContextPost, payload, sig) {
		t.Fatal("signature over SignedPayload failed to verify")
	}

	// A signature for a comment's payload must not verify as a post's, even
	// with byte-identical payload contents — that's ContextPost/ContextComment
	// domain separation, already covered in ed25519_test.go, exercised here
	// specifically against a real SignedPayload rather than an arbitrary message.
	commentSig, err := Sign(priv, ContextComment, payload)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(pub, ContextPost, payload, commentSig) {
		t.Fatal("a comment signature verified as a post signature over the same payload bytes")
	}
}
