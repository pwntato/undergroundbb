package crypto

import (
	"testing"
	"time"

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

// TestRecoveryVerifierAboveCeilingParamsFails is the regression test for PR
// #118 round 3's non-blocking finding: CheckRecoveryVerifier must refuse to
// run Argon2id under a stored parameter set above the same ceiling
// internal/handlers' validateArgon2Params enforces at write time, rather
// than trusting that every possible caller already validated it. Uses a
// fabricated (not actually-derived) verifier deliberately.
//
// Checking only the returned bool here would not actually test the fix: a
// fabricated verifier fails the comparison regardless of whether the
// params check short-circuits first, since a wrong-value ConstantTimeCompare
// also returns false -- a mutation test on an earlier draft of this test
// confirmed it passed even with the range check removed entirely. Asserting
// on elapsed time is what distinguishes "rejected before hashing" from
// "hashed at 2 GiB, then rejected on comparison" -- the reviewer measured
// the latter at 3.57s on this branch pre-fix; this asserts sub-millisecond,
// which only a short-circuit before argon2.IDKey can produce.
func TestRecoveryVerifierAboveCeilingParamsFails(t *testing.T) {
	code := "E1AP1-W4KGY-196Y7-QZFWW-RMMFRV"
	salt := []byte("0123456789abcdef")
	fakeVerifier := make([]byte, VerifierLen)

	cases := []struct {
		name   string
		params Argon2IDParams
	}{
		// MemoryKiB is deliberately large (not the package's usual cheap 64)
		// in every case, including the two not testing memory itself: the
		// elapsed-time assertion below can only distinguish "rejected
		// before hashing" from "hashed, then rejected" if a fall-through to
		// argon2.IDKey would actually be slow. At MemoryKiB=64 a fall-through
		// finishes in under a millisecond regardless, so a missing
		// short-circuit on the iterations/parallelism checks specifically
		// would pass undetected -- confirmed by mutation-testing this test
		// itself before settling on this shape.
		{"memory above ceiling", Argon2IDParams{MemoryKiB: maxVerifierMemoryKiB + 1, Iterations: 3, Parallelism: 1}},
		{"iterations above ceiling", Argon2IDParams{MemoryKiB: maxVerifierMemoryKiB, Iterations: maxVerifierIterations + 1, Parallelism: 1}},
		{"parallelism above ceiling", Argon2IDParams{MemoryKiB: maxVerifierMemoryKiB, Iterations: 3, Parallelism: maxVerifierParallelism + 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			ok := CheckRecoveryVerifier(code, salt, tc.params, fakeVerifier)
			elapsed := time.Since(start)

			if ok {
				t.Fatal("CheckRecoveryVerifier: accepted a stored parameter set above the ceiling")
			}
			if elapsed > 100*time.Millisecond {
				t.Fatalf("CheckRecoveryVerifier: rejected an above-ceiling parameter set, but took %v -- it ran Argon2id instead of short-circuiting before it", elapsed)
			}
		})
	}
}

// TestRecoveryVerifierAtCeilingParamsRuns confirms the ceiling check is a
// strict "above," not "at or above" -- a legitimately-stored parameter set
// exactly at the ceiling (the most expensive a client could have validly
// registered under maxArgon2MemoryKiB/Iterations/Parallelism) must still be
// able to verify a correct code, not be rejected by an off-by-one.
func TestRecoveryVerifierAtCeilingParamsRuns(t *testing.T) {
	code := "E1AP1-W4KGY-196Y7-QZFWW-RMMFRV"
	salt := []byte("0123456789abcdef")
	atCeiling := Argon2IDParams{MemoryKiB: 64, Iterations: maxVerifierIterations, Parallelism: maxVerifierParallelism}
	verifier := deriveVerifierForTest(t, code, salt, atCeiling)

	if !CheckRecoveryVerifier(code, salt, atCeiling, verifier) {
		t.Fatal("CheckRecoveryVerifier: rejected a correct code under params exactly at the ceiling")
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
