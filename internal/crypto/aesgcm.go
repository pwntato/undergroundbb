package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// NonceSize is the length in bytes of a GCM nonce (96 bits).
const NonceSize = 12

// KeySize is the length in bytes of an AES-256 key.
const KeySize = 32

// ErrDecryptionFailed is returned when a ciphertext fails authentication —
// wrong key, wrong AAD, or tampered ciphertext. It never distinguishes which,
// since doing so would hand an attacker an oracle.
var ErrDecryptionFailed = errors.New("crypto: decryption failed")

// ErrInvalidPublicKey is returned when a public key byte string cannot be
// parsed as a point on the expected curve.
var ErrInvalidPublicKey = errors.New("crypto: invalid public key")

// Encrypt encrypts plaintext with AES-256-GCM under key, authenticating aad
// alongside it. It generates a fresh random 96-bit nonce from a CSPRNG for
// every call and returns it alongside the ciphertext — callers must never
// reuse a nonce with the same key, and must never derive one from an item's
// identity rather than generating it fresh.
//
// The returned ciphertext has the authentication tag appended, as
// cipher.AEAD.Seal produces.
func Encrypt(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	if len(key) != KeySize {
		return nil, nil, errors.New("crypto: key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// Decrypt decrypts ciphertext with AES-256-GCM under key and nonce,
// authenticating aad against it. It fails if the key, nonce, aad, or
// ciphertext have been altered in any way relative to what Encrypt produced.
func Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("crypto: key must be 32 bytes")
	}
	if len(nonce) != NonceSize {
		return nil, errors.New("crypto: nonce must be 12 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}
