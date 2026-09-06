package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestAESGCMRoundTrip(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("the group key rotates on member removal")
	aad := []byte("GROUP#g1:GENKEY#000003")

	nonce, ciphertext, err := Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(nonce) != NonceSize {
		t.Fatalf("nonce length = %d, want %d", len(nonce), NonceSize)
	}

	got, err := Decrypt(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
}

func TestAESGCMWrongAADFails(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := Encrypt(key, []byte("payload"), []byte("POST#p1"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Decrypt(key, nonce, ciphertext, []byte("POST#p2")); err != ErrDecryptionFailed {
		t.Fatalf("Decrypt with wrong AAD: got err %v, want ErrDecryptionFailed", err)
	}
}

func TestAESGCMTamperedCiphertextFails(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := Encrypt(key, []byte("payload"), nil)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(ciphertext)
	tampered[0] ^= 0x01

	if _, err := Decrypt(key, nonce, tampered, nil); err != ErrDecryptionFailed {
		t.Fatalf("Decrypt with tampered ciphertext: got err %v, want ErrDecryptionFailed", err)
	}
}

func TestAESGCMWrongKeyFails(t *testing.T) {
	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	if _, err := rand.Read(key1); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatal(err)
	}
	nonce, ciphertext, err := Encrypt(key1, []byte("payload"), nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Decrypt(key2, nonce, ciphertext, nil); err != ErrDecryptionFailed {
		t.Fatalf("Decrypt with wrong key: got err %v, want ErrDecryptionFailed", err)
	}
}

func TestAESGCMNoncesAreFresh(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("same plaintext, same key, must not reuse a nonce")

	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		nonce, _, err := Encrypt(key, plaintext, nil)
		if err != nil {
			t.Fatal(err)
		}
		key := string(nonce)
		if seen[key] {
			t.Fatalf("nonce reused after %d encryptions", i)
		}
		seen[key] = true
	}
}

// TestGenerationChainDirection is the negative vector issue #20 calls out by
// name: a member holding generation N must not be able to derive generation
// N+1. Per docs/DESIGN.md, GENKEY#<n> holds generation n — itself a symmetric
// AES-256 group key — encrypted under generation n+1's key. A holder of gen
// N+1 decrypts GENKEY#<n> to walk backward to gen N; a holder of only gen N
// has no key material that decrypts anything encrypted under gen N+1.
func TestGenerationChainDirection(t *testing.T) {
	genN := make([]byte, KeySize)
	genNPlus1 := make([]byte, KeySize)
	if _, err := rand.Read(genN); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(genNPlus1); err != nil {
		t.Fatal(err)
	}

	// The chain link: GENKEY#<n> = gen N encrypted under gen N+1.
	aad := []byte("GROUP#g1:GENKEY#000001")
	nonce, link, err := Encrypt(genNPlus1, genN, aad)
	if err != nil {
		t.Fatal(err)
	}

	// A holder of gen N+1 walks backward and recovers gen N. This must succeed.
	got, err := Decrypt(genNPlus1, nonce, link, aad)
	if err != nil {
		t.Fatalf("gen N+1 holder failed to decrypt GENKEY#<n>: %v", err)
	}
	if !bytes.Equal(got, genN) {
		t.Fatal("gen N+1 holder decrypted the wrong plaintext")
	}

	// A holder of only gen N must not be able to derive gen N+1: gen N is not
	// the key GENKEY#<n> was encrypted under, so decrypting the same link
	// with gen N itself must fail.
	if _, err := Decrypt(genN, nonce, link, aad); err != ErrDecryptionFailed {
		t.Fatalf("gen N holder decrypted a link encrypted under gen N+1: got err %v, want ErrDecryptionFailed", err)
	}
}

func TestAESGCMRejectsWrongKeySize(t *testing.T) {
	if _, _, err := Encrypt(make([]byte, 16), []byte("x"), nil); err == nil {
		t.Fatal("Encrypt with a 16-byte key: want error, got nil")
	}
	if _, err := Decrypt(make([]byte, 16), make([]byte, NonceSize), []byte("x"), nil); err == nil {
		t.Fatal("Decrypt with a 16-byte key: want error, got nil")
	}
}
