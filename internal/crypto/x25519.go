package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// hkdfInfo labels HKDF's info parameter with the operation deriving the key,
// so the wrapping key for a key-wrap can never collide with a key derived
// for any other purpose from the same ECDH shared secret.
const hkdfInfo = "underground-bb:x25519-wrap:v1"

// GenerateWrappingKey generates a new X25519 keypair for wrapping and
// unwrapping group keys.
func GenerateWrappingKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// Wrap wraps plaintext (typically a group key or a generation key) to
// recipientPub using ECIES: a fresh ephemeral X25519 keypair, ECDH against
// the recipient's public key, HKDF-SHA256 to derive a wrapping key from the
// shared secret, and AES-256-GCM to encrypt.
//
// aad is authenticated but not encrypted, and should bind the wrapped item
// to its address per the AAD table in docs/DESIGN.md (e.g. group id and
// generation number).
//
// The returned Wrapped value carries the ephemeral public key alongside the
// nonce and ciphertext — it is everything Unwrap needs and nothing the
// recipient's private key isn't required to use.
func Wrap(recipientPub *ecdh.PublicKey, plaintext, aad []byte) (*Wrapped, error) {
	ephemeralPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := ephemeralPriv.ECDH(recipientPub)
	if err != nil {
		return nil, err
	}

	wrappingKey, err := deriveWrappingKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext, err := Encrypt(wrappingKey, plaintext, aad)
	if err != nil {
		return nil, err
	}

	return &Wrapped{
		EphemeralPub: ephemeralPriv.PublicKey().Bytes(),
		Nonce:        nonce,
		Ciphertext:   ciphertext,
	}, nil
}

// Unwrap reverses Wrap: it performs ECDH between recipientPriv and the
// ephemeral public key carried in w, derives the same wrapping key via
// HKDF-SHA256, and decrypts. aad must match exactly what Wrap authenticated.
func Unwrap(recipientPriv *ecdh.PrivateKey, w *Wrapped, aad []byte) ([]byte, error) {
	ephemeralPub, err := ecdh.X25519().NewPublicKey(w.EphemeralPub)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}

	sharedSecret, err := recipientPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	wrappingKey, err := deriveWrappingKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	return Decrypt(wrappingKey, w.Nonce, w.Ciphertext, aad)
}

// Wrapped is the output of Wrap: an ephemeral public key plus a GCM nonce
// and ciphertext, sufficient for the holder of the matching private key to
// recover the wrapped plaintext via Unwrap.
type Wrapped struct {
	EphemeralPub []byte
	Nonce        []byte
	Ciphertext   []byte
}

func deriveWrappingKey(sharedSecret []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, sharedSecret, nil, []byte(hkdfInfo))
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}
