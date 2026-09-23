package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
)

// KeyBundleVersion1 is the only defined encoding of a KeyBundle so far. A
// future format bump (see EncodeKeyBundle's own doc comment) would add a
// KeyBundleVersion2 and a version switch in DecodeKeyBundle, never reinterpret
// this constant's meaning.
const KeyBundleVersion1 byte = 1

// ErrUnsupportedKeyBundleVersion is returned when DecodeKeyBundle reads a
// version byte this build does not know how to parse -- see that function's
// own doc comment for why this is distinguished from a garbled/corrupt blob
// rather than folded into a generic decode error.
var ErrUnsupportedKeyBundleVersion = errors.New("crypto: unsupported key bundle version")

// ErrMalformedKeyBundle is returned when a KeyBundleVersion1 blob's length
// fields do not describe the bytes actually present -- truncated, padded, or
// otherwise not a value EncodeKeyBundle could have produced.
var ErrMalformedKeyBundle = errors.New("crypto: malformed key bundle")

// KeyBundle is the plaintext a client wraps under the password- or
// recovery-code-derived key (WrappedPrivateKeys /
// RecoveryWrappedPrivateKeys) at registration and unwraps at login,
// change-password or recovery. It holds only the two PRIVATE scalars:
//
//   - SigningSeed: the 32-byte Ed25519 seed (matching ed25519.SeedSize, NOT
//     Go's 64-byte ed25519.PrivateKey encoding, which appends the public key
//     the seed already determines).
//   - WrappingPrivateKey: the 32-byte X25519 private scalar.
//
// Both public keys are deliberately excluded. They are already transmitted
// and stored in plaintext (registerRequest.SigningPublicKey/WrappingPublicKey,
// models.User.SigningPublicKey/WrappingPublicKey) and are cheaply
// re-derivable from the private scalars above besides -- carrying them here
// too would be redundant ciphertext with no property it adds, since a public
// key is not a secret this wrap needs to protect.
type KeyBundle struct {
	SigningSeed        []byte
	WrappingPrivateKey []byte
}

// EncodeKeyBundle serializes b as KeyBundleVersion1: a 1-byte version tag
// followed by each field as a 4-byte big-endian length prefix and its bytes,
// in the field order SigningSeed then WrappingPrivateKey -- the same
// length-prefixed convention SignedPayload uses (see payload.go) rather than
// a bare concatenation, chosen specifically so a future version can add a
// field (a third keypair, key-rotation metadata) without redefining what
// today's fixed-width bytes mean.
//
// This must be treated as append-only in exactly the sense DESIGN.md already
// applies elsewhere (Argon2id parameters, the credential-wrap AAD): once a
// real user's blob is encrypted under this encoding, DecodeKeyBundle must go
// on accepting KeyBundleVersion1 forever, even after a KeyBundleVersion2
// exists. Changing what version 1 means, rather than introducing a version
// 2, is the unrecoverable mistake -- every existing wrap silently becomes
// unreadable with nothing on the server (which never sees this plaintext at
// all) able to detect or repair it.
func EncodeKeyBundle(b KeyBundle) []byte {
	fields := [][]byte{b.SigningSeed, b.WrappingPrivateKey}

	size := 1
	for _, f := range fields {
		size += 4 + len(f)
	}

	out := make([]byte, 0, size)
	out = append(out, KeyBundleVersion1)
	for _, f := range fields {
		out = appendLengthPrefixed(out, f)
	}
	return out
}

// DecodeKeyBundle reverses EncodeKeyBundle, validating the two fixed lengths
// EncodeKeyBundle always produces (ed25519.SeedSize and X25519's 32-byte
// scalar) rather than trusting whatever lengths the blob's own prefixes
// claim -- a wrapped blob only reaches this function after the AEAD tag
// already verified, so a length mismatch here means a version 1 encoder that
// itself had a bug, not tampering, but a fixed-size caller (register's own
// unwrap-and-verify path, once it exists) is better served by a clear
// decode error than a silent short read.
//
// An unrecognized version byte returns ErrUnsupportedKeyBundleVersion rather
// than ErrMalformedKeyBundle -- ONLY version 1 is defined today, so this
// branch is unreachable from any blob this build itself produced, but it is
// the distinction a future version 2 reader will need on day one: a
// version 2 client reading back a version 1 blob (an account that has not
// logged in since the format changed) must fall into a defined, named case,
// not the same bucket as a corrupt one.
func DecodeKeyBundle(data []byte) (KeyBundle, error) {
	if len(data) < 1 {
		return KeyBundle{}, ErrMalformedKeyBundle
	}
	version := data[0]
	if version != KeyBundleVersion1 {
		return KeyBundle{}, ErrUnsupportedKeyBundleVersion
	}
	rest := data[1:]

	signingSeed, rest, err := readLengthPrefixed(rest)
	if err != nil {
		return KeyBundle{}, err
	}
	if len(signingSeed) != ed25519.SeedSize {
		return KeyBundle{}, ErrMalformedKeyBundle
	}

	wrappingPriv, rest, err := readLengthPrefixed(rest)
	if err != nil {
		return KeyBundle{}, err
	}
	if len(wrappingPriv) != x25519PrivateKeySize {
		return KeyBundle{}, ErrMalformedKeyBundle
	}

	if len(rest) != 0 {
		return KeyBundle{}, ErrMalformedKeyBundle
	}

	return KeyBundle{SigningSeed: signingSeed, WrappingPrivateKey: wrappingPriv}, nil
}

// x25519PrivateKeySize mirrors register.go's x25519PublicKeySize -- crypto
// cannot import handlers (the reverse dependency already exists), so this is
// a second copy of the same fixed width. crypto/ecdh has no exported size
// constant for X25519 either way.
const x25519PrivateKeySize = 32

// readLengthPrefixed reads one EncodeKeyBundle-style length-prefixed field
// from the front of data, returning the field and the remaining bytes.
func readLengthPrefixed(data []byte) (field, rest []byte, err error) {
	if len(data) < 4 {
		return nil, nil, ErrMalformedKeyBundle
	}
	n := binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	if uint64(n) > uint64(len(data)) {
		return nil, nil, ErrMalformedKeyBundle
	}
	return data[:n], data[n:], nil
}

// SigningKey reconstructs the ed25519.PrivateKey (Go's 64-byte
// seed||pubkey encoding) from b.SigningSeed, for callers that need Go's
// standard-library key type rather than the bare seed.
func (b KeyBundle) SigningKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(b.SigningSeed)
}

// WrappingKey reconstructs the *ecdh.PrivateKey from b.WrappingPrivateKey,
// for callers that need crypto/ecdh's type rather than the bare scalar.
func (b KeyBundle) WrappingKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(b.WrappingPrivateKey)
}
