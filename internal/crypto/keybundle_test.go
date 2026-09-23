package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func fixedTestKeyBundle(t *testing.T) KeyBundle {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	wrapPriv, err := GenerateWrappingKey()
	if err != nil {
		t.Fatalf("GenerateWrappingKey: %v", err)
	}
	return KeyBundle{
		SigningSeed:        priv.Seed(),
		WrappingPrivateKey: wrapPriv.Bytes(),
	}
}

// mustEncode is EncodeKeyBundle for tests that already know b is
// well-formed and want to fail loudly, rather than via a silent nil slice,
// if that assumption is ever wrong.
func mustEncode(t *testing.T, b KeyBundle) []byte {
	t.Helper()
	encoded, err := EncodeKeyBundle(b)
	if err != nil {
		t.Fatalf("EncodeKeyBundle: %v", err)
	}
	return encoded
}

func TestKeyBundleRoundTrip(t *testing.T) {
	want := fixedTestKeyBundle(t)
	encoded := mustEncode(t, want)

	got, err := DecodeKeyBundle(encoded)
	if err != nil {
		t.Fatalf("DecodeKeyBundle: %v", err)
	}
	if !bytes.Equal(got.SigningSeed, want.SigningSeed) {
		t.Errorf("SigningSeed = %x, want %x", got.SigningSeed, want.SigningSeed)
	}
	if !bytes.Equal(got.WrappingPrivateKey, want.WrappingPrivateKey) {
		t.Errorf("WrappingPrivateKey = %x, want %x", got.WrappingPrivateKey, want.WrappingPrivateKey)
	}
}

func TestKeyBundleEncodingStartsWithVersion(t *testing.T) {
	b := fixedTestKeyBundle(t)
	encoded := mustEncode(t, b)
	if len(encoded) == 0 || encoded[0] != KeyBundleVersion1 {
		t.Fatalf("encoded[0] = %v, want KeyBundleVersion1 (%d)", encoded[:min(1, len(encoded))], KeyBundleVersion1)
	}
}

func TestKeyBundleReconstructsUsableKeys(t *testing.T) {
	b := fixedTestKeyBundle(t)

	signKey := b.SigningKey()
	msg := []byte("test message")
	sig := ed25519.Sign(signKey, msg)
	if !ed25519.Verify(signKey.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatal("signature from reconstructed signing key failed to verify")
	}

	wrapKey, err := b.WrappingKey()
	if err != nil {
		t.Fatalf("WrappingKey: %v", err)
	}
	if !bytes.Equal(wrapKey.Bytes(), b.WrappingPrivateKey) {
		t.Errorf("WrappingKey().Bytes() = %x, want %x", wrapKey.Bytes(), b.WrappingPrivateKey)
	}
}

func TestDecodeKeyBundleUnsupportedVersion(t *testing.T) {
	b := fixedTestKeyBundle(t)
	encoded := mustEncode(t, b)
	encoded[0] = KeyBundleVersion1 + 1 // a version this build does not know

	_, err := DecodeKeyBundle(encoded)
	if err != ErrUnsupportedKeyBundleVersion {
		t.Fatalf("err = %v, want ErrUnsupportedKeyBundleVersion", err)
	}
}

func TestDecodeKeyBundleMalformed(t *testing.T) {
	valid := mustEncode(t, fixedTestKeyBundle(t))

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"version byte only", valid[:1]},
		{"truncated length prefix", valid[:3]},
		{"truncated first field", valid[:10]},
		{"length prefix claims more than present", func() []byte {
			d := append([]byte(nil), valid...)
			// Bump the first field's length prefix (bytes 1-4) past what's
			// actually there.
			d[4] = 0xff
			return d
		}()},
		{"trailing garbage", append(append([]byte(nil), valid...), 0x00)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeKeyBundle(tc.data)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if err != ErrMalformedKeyBundle {
				t.Fatalf("err = %v, want ErrMalformedKeyBundle", err)
			}
		})
	}
}

// TestEncodeKeyBundleRejectsWrongSizeFields covers the guard added after
// review found EncodeKeyBundle would happily accept a SigningSeed of the
// wrong size -- e.g. Go's own 64-byte ed25519.PrivateKey encoding
// (seed||pubkey), which ed25519.ts's SigningKey doc comment specifically
// names as what "cross[es] the wire" elsewhere in this codebase, making it
// a plausible mistake for whatever signup code eventually calls this.
// Before this guard, that value would wrap and register successfully and
// then fail every subsequent login, undetectably, since the server never
// sees this plaintext to catch the mismatch.
func TestEncodeKeyBundleRejectsWrongSizeFields(t *testing.T) {
	valid := fixedTestKeyBundle(t)

	cases := []struct {
		name string
		b    KeyBundle
	}{
		{
			"64-byte Go-style signing key instead of the 32-byte seed",
			KeyBundle{SigningSeed: append(append([]byte(nil), valid.SigningSeed...), valid.SigningSeed...), WrappingPrivateKey: valid.WrappingPrivateKey},
		},
		{
			"empty signing seed",
			KeyBundle{SigningSeed: nil, WrappingPrivateKey: valid.WrappingPrivateKey},
		},
		{
			"short wrapping key",
			KeyBundle{SigningSeed: valid.SigningSeed, WrappingPrivateKey: valid.WrappingPrivateKey[:16]},
		},
		{
			"empty wrapping key",
			KeyBundle{SigningSeed: valid.SigningSeed, WrappingPrivateKey: nil},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := EncodeKeyBundle(tc.b)
			if err != ErrMalformedKeyBundle {
				t.Fatalf("err = %v, want ErrMalformedKeyBundle", err)
			}
		})
	}
}

// TestDecodeKeyBundleReturnsIndependentCopies covers the aliasing bug review
// found: DecodeKeyBundle used to return sub-slices of its input, so zeroing
// the input buffer -- the ordinary thing to do with an unwrapped plaintext
// once its keys are extracted -- silently zeroed the decoded KeyBundle too.
// Now it returns copies, matching the TypeScript port (Uint8Array.slice()
// always copies).
func TestDecodeKeyBundleReturnsIndependentCopies(t *testing.T) {
	want := fixedTestKeyBundle(t)
	encoded := mustEncode(t, want)

	decoded, err := DecodeKeyBundle(encoded)
	if err != nil {
		t.Fatalf("DecodeKeyBundle: %v", err)
	}

	// Zero the input buffer, as a caller done with an unwrapped plaintext
	// would.
	for i := range encoded {
		encoded[i] = 0
	}

	if !bytes.Equal(decoded.SigningSeed, want.SigningSeed) {
		t.Fatalf("decoded.SigningSeed changed after zeroing the input buffer: got %x, want %x", decoded.SigningSeed, want.SigningSeed)
	}
	if !bytes.Equal(decoded.WrappingPrivateKey, want.WrappingPrivateKey) {
		t.Fatalf("decoded.WrappingPrivateKey changed after zeroing the input buffer: got %x, want %x", decoded.WrappingPrivateKey, want.WrappingPrivateKey)
	}
}

// TestKeyBundleSwapIsUndetectableByLength documents a limitation rather than
// guarding against one: an Ed25519 seed and an X25519 scalar are both 32
// bytes, so encoding the two KeyBundle fields swapped decodes successfully
// -- DecodeKeyBundle's length checks cannot tell seed and scalar apart. The
// real guard belongs at the login/unwrap call site (#33): re-derive both
// public keys from the decoded scalars and compare them against the
// account's stored SigningPublicKey/WrappingPublicKey.
func TestKeyBundleSwapIsUndetectableByLength(t *testing.T) {
	b := fixedTestKeyBundle(t)
	swapped := KeyBundle{
		SigningSeed:        b.WrappingPrivateKey,
		WrappingPrivateKey: b.SigningSeed,
	}
	encoded := mustEncode(t, swapped)
	decoded, err := DecodeKeyBundle(encoded)
	// Both fields are 32 bytes, so this decodes without error -- the point
	// of this test is documenting that DecodeKeyBundle cannot detect a swap
	// by length alone, and callers must not rely on it to.
	if err != nil {
		t.Fatalf("DecodeKeyBundle: %v", err)
	}
	if !bytes.Equal(decoded.SigningSeed, b.WrappingPrivateKey) {
		t.Fatal("expected the swap to round-trip byte-for-byte, proving no size-based detection occurs")
	}
}
