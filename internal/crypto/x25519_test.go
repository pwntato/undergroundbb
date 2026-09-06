package crypto

import (
	"bytes"
	"testing"
)

func TestX25519WrapRoundTrip(t *testing.T) {
	recipientPriv, err := GenerateWrappingKey()
	if err != nil {
		t.Fatal(err)
	}
	groupKey := make([]byte, KeySize)
	for i := range groupKey {
		groupKey[i] = byte(i)
	}
	aad := []byte("GROUP#g1:GENKEY#000004")

	wrapped, err := Wrap(recipientPriv.PublicKey(), groupKey, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	got, err := Unwrap(recipientPriv, wrapped, aad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, groupKey) {
		t.Fatalf("got %x, want %x", got, groupKey)
	}
}

func TestX25519UnwrapWrongRecipientFails(t *testing.T) {
	recipientPriv, err := GenerateWrappingKey()
	if err != nil {
		t.Fatal(err)
	}
	otherPriv, err := GenerateWrappingKey()
	if err != nil {
		t.Fatal(err)
	}

	wrapped, err := Wrap(recipientPriv.PublicKey(), []byte("group key bytes here"), nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Unwrap(otherPriv, wrapped, nil); err != ErrDecryptionFailed {
		t.Fatalf("Unwrap with wrong recipient key: got err %v, want ErrDecryptionFailed", err)
	}
}

func TestX25519UnwrapWrongAADFails(t *testing.T) {
	recipientPriv, err := GenerateWrappingKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := Wrap(recipientPriv.PublicKey(), []byte("group key bytes"), []byte("GROUP#g1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unwrap(recipientPriv, wrapped, []byte("GROUP#g2")); err != ErrDecryptionFailed {
		t.Fatalf("Unwrap with wrong AAD: got err %v, want ErrDecryptionFailed", err)
	}
}

func TestX25519EachWrapUsesFreshEphemeralKey(t *testing.T) {
	recipientPriv, err := GenerateWrappingKey()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("same plaintext wrapped twice")

	w1, err := Wrap(recipientPriv.PublicKey(), plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := Wrap(recipientPriv.PublicKey(), plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(w1.EphemeralPub, w2.EphemeralPub) {
		t.Fatal("two Wrap calls reused the same ephemeral public key")
	}
	if bytes.Equal(w1.Nonce, w2.Nonce) {
		t.Fatal("two Wrap calls reused the same nonce")
	}
	if bytes.Equal(w1.Ciphertext, w2.Ciphertext) {
		t.Fatal("two Wrap calls of the same plaintext produced identical ciphertext")
	}
}

// TestX25519WrappingKeyBindsBothPublicKeys is the regression test for the
// HKDF-binding fix: deriveWrappingKey must not collapse to a function of the
// shared secret alone, and swapping which key played which role must change
// the output. Without this, a future refactor could silently revert to the
// pre-binding derivation and every other test here would still pass.
func TestX25519WrappingKeyBindsBothPublicKeys(t *testing.T) {
	sharedSecret := bytes.Repeat([]byte{7}, 32)
	ephemeralPub := bytes.Repeat([]byte{1}, 32)
	recipientPub := bytes.Repeat([]byte{2}, 32)

	bound, err := deriveWrappingKey(sharedSecret, ephemeralPub, recipientPub)
	if err != nil {
		t.Fatal(err)
	}
	swapped, err := deriveWrappingKey(sharedSecret, recipientPub, ephemeralPub)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(bound, swapped) {
		t.Fatal("wrapping key does not bind the ephemeral/recipient key roles")
	}

	unbound, err := deriveWrappingKey(sharedSecret, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(bound, unbound) {
		t.Fatal("wrapping key is derived from the shared secret alone")
	}
}
