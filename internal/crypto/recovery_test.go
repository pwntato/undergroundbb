package crypto

import (
	"testing"

	"golang.org/x/crypto/argon2"
)

// testVerifierParams is a fixed, cheap Argon2id parameter set for these
// tests -- what the client would in practice generate per docs/DESIGN.md,
// but small enough that the test suite doesn't pay real Argon2id cost for
// every case. CheckRecoveryVerifier reads whatever params it's given, so
// nothing about the function under test cares that these are lighter than
// a real deployment's.
var testVerifierParams = Argon2IDParams{MemoryKiB: 64, Iterations: 1, Parallelism: 1}

func TestRecoveryVerifierRoundTrip(t *testing.T) {
	code := "E1AP1-W4KGY-196Y7-QZFWW-RMMFRV"
	salt := []byte("0123456789abcdef")

	verifier := deriveVerifierForTest(t, code, salt, testVerifierParams)

	if !CheckRecoveryVerifier(code, salt, testVerifierParams, verifier) {
		t.Fatal("CheckRecoveryVerifier: the code that produced this verifier was rejected")
	}
}

func TestRecoveryVerifierWrongCodeFails(t *testing.T) {
	salt := []byte("0123456789abcdef")
	verifier := deriveVerifierForTest(t, "E1AP1-W4KGY-196Y7-QZFWW-RMMFRV", salt, testVerifierParams)

	if CheckRecoveryVerifier("X9EY7-CXQYC-J9GYS-C48DX-8HCD5A", salt, testVerifierParams, verifier) {
		t.Fatal("CheckRecoveryVerifier: an unrelated code verified successfully")
	}
}

func TestRecoveryVerifierWrongSaltFails(t *testing.T) {
	code := "E1AP1-W4KGY-196Y7-QZFWW-RMMFRV"
	verifier := deriveVerifierForTest(t, code, []byte("0123456789abcdef"), testVerifierParams)

	if CheckRecoveryVerifier(code, []byte("fedcba9876543210"), testVerifierParams, verifier) {
		t.Fatal("CheckRecoveryVerifier: the right code verified against the wrong salt")
	}
}

func TestRecoveryVerifierWrongParamsFails(t *testing.T) {
	code := "E1AP1-W4KGY-196Y7-QZFWW-RMMFRV"
	salt := []byte("0123456789abcdef")
	verifier := deriveVerifierForTest(t, code, salt, testVerifierParams)

	otherParams := Argon2IDParams{MemoryKiB: 128, Iterations: 1, Parallelism: 1}
	if CheckRecoveryVerifier(code, salt, otherParams, verifier) {
		t.Fatal("CheckRecoveryVerifier: verified under a different parameter set than produced it")
	}
}

// TestRecoveryVerifierNilOrEmptyVerifierFails is the direct regression test
// for PR #118's blocking finding: a nil verifier is exactly what a legacy
// RECOVERY item (registered before this field existed, or before
// register.go's zero-byte-decode fix) unmarshals to, and this must be a
// clean rejection, not the nil-pointer panic inside BLAKE2b that
// argon2.IDKey(..., keyLen=0) produced before VerifierLen was pinned.
func TestRecoveryVerifierNilOrEmptyVerifierFails(t *testing.T) {
	code := "E1AP1-W4KGY-196Y7-QZFWW-RMMFRV"
	salt := []byte("0123456789abcdef")

	cases := []struct {
		name     string
		verifier []byte
	}{
		{"nil verifier (unmarshaled legacy RECOVERY item)", nil},
		{"zero-length verifier", []byte{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if CheckRecoveryVerifier(code, salt, testVerifierParams, tc.verifier) {
				t.Fatal("CheckRecoveryVerifier: accepted against a nil/empty verifier")
			}
		})
	}
}

// TestRecoveryVerifierShortVerifierFails covers the second consequence PR
// #118 review measured directly: before VerifierLen was pinned, a
// short-but-nonempty verifier shrank the comparison width, accepting a
// wrong code at roughly 1/256 for a 1-byte verifier. A wrong-length
// verifier must now be rejected outright, regardless of what it contains.
func TestRecoveryVerifierShortVerifierFails(t *testing.T) {
	code := "E1AP1-W4KGY-196Y7-QZFWW-RMMFRV"
	salt := []byte("0123456789abcdef")
	fullVerifier := deriveVerifierForTest(t, code, salt, testVerifierParams)

	if CheckRecoveryVerifier(code, salt, testVerifierParams, fullVerifier[:1]) {
		t.Fatal("CheckRecoveryVerifier: accepted the right code against a truncated 1-byte verifier")
	}
	if CheckRecoveryVerifier(code, salt, testVerifierParams, fullVerifier[:len(fullVerifier)-1]) {
		t.Fatal("CheckRecoveryVerifier: accepted the right code against a verifier one byte short of VerifierLen")
	}
}

// TestRecoveryVerifierEmptySaltFails covers the same "decodes to zero
// bytes" route on Salt rather than Verifier -- CheckRecoveryVerifier rejects
// it directly, on top of decodeBase64Field's fix at the field-validation
// layer, since this function has no way to know its caller validated
// anything.
func TestRecoveryVerifierEmptySaltFails(t *testing.T) {
	code := "E1AP1-W4KGY-196Y7-QZFWW-RMMFRV"
	verifier := deriveVerifierForTest(t, code, []byte{}, testVerifierParams)

	if CheckRecoveryVerifier(code, []byte{}, testVerifierParams, verifier) {
		t.Fatal("CheckRecoveryVerifier: accepted against an empty salt")
	}
	if CheckRecoveryVerifier(code, nil, testVerifierParams, verifier) {
		t.Fatal("CheckRecoveryVerifier: accepted against a nil salt")
	}
}

// deriveVerifierForTest computes what a client would send as Verifier --
// its own call to argon2.IDKey, duplicated deliberately rather than
// calling into CheckRecoveryVerifier's implementation, so a bug in that
// derivation can't cancel itself out against the same bug here.
func deriveVerifierForTest(t *testing.T, code string, salt []byte, params Argon2IDParams) []byte {
	t.Helper()
	const verifierLen = 32
	return argon2.IDKey([]byte(code), salt, uint32(params.Iterations), uint32(params.MemoryKiB), uint8(params.Parallelism), verifierLen)
}
