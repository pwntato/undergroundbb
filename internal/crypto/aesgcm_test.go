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

func TestAESGCMRejectsWrongKeySize(t *testing.T) {
	if _, _, err := Encrypt(make([]byte, 16), []byte("x"), nil); err == nil {
		t.Fatal("Encrypt with a 16-byte key: want error, got nil")
	}
	if _, err := Decrypt(make([]byte, 16), make([]byte, NonceSize), []byte("x"), nil); err == nil {
		t.Fatal("Decrypt with a 16-byte key: want error, got nil")
	}
}
