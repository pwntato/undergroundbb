package crypto

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
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
// Wrap provides confidentiality only — no sender authentication. recipientPub
// is a public value by definition (the server stores and serves it), so
// anyone can construct a Wrapped that Unwrap accepts; nothing here proves the
// plaintext came from a trusted source. Under this project's threat model,
// where the server is untrusted and can write to the table, an unauthenticated
// wrap is forgeable: a malicious server could substitute a GENKEY# chain link
// or a member's wrapped group key with one it generated itself, and the
// recipient would unwrap it successfully.
//
// Callers MUST authenticate a wrap independently before trusting it — e.g.
// the invite handshake in docs/DESIGN.md only wraps to an X25519 key that was
// itself Ed25519-signed in an earlier step. Do not treat Wrap/Unwrap as
// sufficient on their own for any value an attacker could have chosen.
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

	ephemeralPubBytes := ephemeralPriv.PublicKey().Bytes()
	wrappingKey, err := deriveWrappingKey(sharedSecret, ephemeralPubBytes, recipientPub.Bytes())
	if err != nil {
		return nil, err
	}

	nonce, ciphertext, err := Encrypt(wrappingKey, plaintext, aad)
	if err != nil {
		return nil, err
	}

	return &Wrapped{
		EphemeralPub: ephemeralPubBytes,
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

	wrappingKey, err := deriveWrappingKey(sharedSecret, w.EphemeralPub, recipientPriv.PublicKey().Bytes())
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

// deriveWrappingKey derives the AES-256-GCM key HKDF-SHA256 from the ECDH
// shared secret, binding both public keys involved in the exchange into the
// info parameter (the pattern HPKE's DHKEM uses). Without this, the derived
// key is a pure function of the shared secret and says nothing about which
// exchange produced it — the ephemeral public key travels in Wrapped
// otherwise unauthenticated by the KDF itself.
//
// The concatenation hkdfInfo || ephemeralPub || recipientPub has no length
// prefixes or separators, which is unambiguous only because both public keys
// are always exactly 32 bytes (X25519's fixed width) — there is no encoding
// under which a byte could migrate between the two fields. This must not be
// copied to bind variable-length inputs without adding delimiters. This
// derivation must also never change once real data exists under it: doing so
// is the permanent-lockout scenario #20 and DESIGN.md describe for a
// silently changed key derivation.
func deriveWrappingKey(sharedSecret, ephemeralPub, recipientPub []byte) ([]byte, error) {
	info := string(hkdfInfo) + string(ephemeralPub) + string(recipientPub)
	return hkdf.Key(sha256.New, sharedSecret, nil, info, KeySize)
}
