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

// TestX25519GenerationChainDirection is the negative vector issue #20 calls
// out by name: a member holding generation N must not be able to derive
// generation N+1 from it. Chaining wraps gen N under gen N+1's key (an
// N+1 holder can unwrap backward to N), so a holder of only gen N has no
// path forward — modeled here as gen N's key sharing no relationship with
// gen N+1's key that would let it unwrap a wrap performed with gen N+1.
func TestX25519GenerationChainDirection(t *testing.T) {
	genNPriv, err := GenerateWrappingKey()
	if err != nil {
		t.Fatal(err)
	}
	genNPlus1Priv, err := GenerateWrappingKey()
	if err != nil {
		t.Fatal(err)
	}

	// The chain link: gen N wrapped under gen N+1's public key.
	genNKey := []byte("generation N group key material")
	aad := []byte("GROUP#g1:GENKEY#000001")
	link, err := Wrap(genNPlus1Priv.PublicKey(), genNKey, aad)
	if err != nil {
		t.Fatal(err)
	}

	// A holder of gen N+1 unwraps backward to gen N. This must succeed.
	got, err := Unwrap(genNPlus1Priv, link, aad)
	if err != nil {
		t.Fatalf("gen N+1 holder failed to unwrap gen N: %v", err)
	}
	if !bytes.Equal(got, genNKey) {
		t.Fatal("gen N+1 holder unwrapped the wrong plaintext")
	}

	// A holder of only gen N must not be able to derive gen N+1: attempting
	// to unwrap the same link with gen N's own private key must fail, since
	// the link was encrypted to gen N+1's public key, not gen N's.
	if _, err := Unwrap(genNPriv, link, aad); err != ErrDecryptionFailed {
		t.Fatalf("gen N holder unwrapped a link meant for gen N+1: got err %v, want ErrDecryptionFailed", err)
	}
}
