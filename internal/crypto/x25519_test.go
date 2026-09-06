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
