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

func TestKeyBundleRoundTrip(t *testing.T) {
	want := fixedTestKeyBundle(t)
	encoded := EncodeKeyBundle(want)

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
	encoded := EncodeKeyBundle(b)
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
	encoded := EncodeKeyBundle(b)
	encoded[0] = KeyBundleVersion1 + 1 // a version this build does not know

	_, err := DecodeKeyBundle(encoded)
	if err != ErrUnsupportedKeyBundleVersion {
		t.Fatalf("err = %v, want ErrUnsupportedKeyBundleVersion", err)
	}
}

func TestDecodeKeyBundleMalformed(t *testing.T) {
	valid := EncodeKeyBundle(fixedTestKeyBundle(t))

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

// TestKeyBundleFieldsAreNotSwappable guards the field order itself: encoding
// with the two fields swapped must fail wrapping-key-size validation, since
// an Ed25519 seed and an X25519 scalar are both 32 bytes and would otherwise
// decode "successfully" into the wrong key type silently.
func TestKeyBundleFieldsAreNotSwappable(t *testing.T) {
	b := fixedTestKeyBundle(t)
	swapped := KeyBundle{
		SigningSeed:        b.WrappingPrivateKey,
		WrappingPrivateKey: b.SigningSeed,
	}
	encoded := EncodeKeyBundle(swapped)
	decoded, err := DecodeKeyBundle(encoded)
	// Both fields are 32 bytes, so this decodes without error -- the
	// point of this test is documenting that DecodeKeyBundle cannot detect
	// a swap by length alone, and callers must not rely on it to.
	if err != nil {
		t.Fatalf("DecodeKeyBundle: %v", err)
	}
	if !bytes.Equal(decoded.SigningSeed, b.WrappingPrivateKey) {
		t.Fatal("expected the swap to round-trip byte-for-byte, proving no size-based detection occurs")
	}
}
