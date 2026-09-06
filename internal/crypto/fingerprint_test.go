package crypto

import (
	"strings"
	"testing"
)

func TestFingerprintShape(t *testing.T) {
	pub, _, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	wpriv, err := GenerateWrappingKey()
	if err != nil {
		t.Fatal(err)
	}

	fp, err := Fingerprint(pub, wpriv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	groups := strings.Split(fp, "-")
	if len(groups) != 12 {
		t.Fatalf("got %d groups, want 12", len(groups))
	}
	digitCount := 0
	for _, g := range groups {
		if len(g) != 5 {
			t.Fatalf("group %q has length %d, want 5", g, len(g))
		}
		for _, c := range g {
			if c < '0' || c > '9' {
				t.Fatalf("group %q contains non-digit %q", g, c)
			}
		}
		digitCount += len(g)
	}
	if digitCount != 60 {
		t.Fatalf("got %d digits, want 60", digitCount)
	}
}

func TestFingerprintDeterministic(t *testing.T) {
	pub, _, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	wpriv, err := GenerateWrappingKey()
	if err != nil {
		t.Fatal(err)
	}
	wpub := wpriv.PublicKey().Bytes()

	fp1, err := Fingerprint(pub, wpub)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := Fingerprint(pub, wpub)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Fatalf("Fingerprint is not deterministic: %q != %q", fp1, fp2)
	}
}

func TestFingerprintBindsBothKeys(t *testing.T) {
	pub1, _, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	wpriv1, err := GenerateWrappingKey()
	if err != nil {
		t.Fatal(err)
	}
	wpriv2, err := GenerateWrappingKey()
	if err != nil {
		t.Fatal(err)
	}

	base, err := Fingerprint(pub1, wpriv1.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// Changing only the signing key must change the fingerprint — otherwise
	// an operator could swap the Ed25519 key undetected.
	diffSigning, err := Fingerprint(pub2, wpriv1.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if base == diffSigning {
		t.Fatal("fingerprint did not change when the signing key changed")
	}

	// Changing only the wrapping key must change the fingerprint — this is
	// the substitution DESIGN.md calls out: group keys wrap to this key, so
	// a fingerprint that ignored it would let an operator swap it silently.
	diffWrapping, err := Fingerprint(pub1, wpriv2.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if base == diffWrapping {
		t.Fatal("fingerprint did not change when the wrapping key changed")
	}
}

func TestFingerprintRejectsMalformedKeys(t *testing.T) {
	pub, _, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	wpriv, err := GenerateWrappingKey()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Fingerprint(make([]byte, 10), wpriv.PublicKey().Bytes()); err != ErrInvalidPublicKey {
		t.Fatalf("got err %v, want ErrInvalidPublicKey", err)
	}
	if _, err := Fingerprint(pub, make([]byte, 10)); err != ErrInvalidPublicKey {
		t.Fatalf("got err %v, want ErrInvalidPublicKey", err)
	}
}
