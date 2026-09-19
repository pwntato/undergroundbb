package session

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func testSigner() *Signer {
	return NewSigner([]byte("test-session-secret-32-bytes-ok"))
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	s := testSigner()
	token := s.Issue("user-123", time.Hour)

	got, err := s.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != "user-123" {
		t.Errorf("Verify() = %q, want %q", got, "user-123")
	}
}

func TestVerifyExpired(t *testing.T) {
	s := testSigner()
	// A negative TTL issues a token already in the past.
	token := s.Issue("user-123", -time.Hour)

	if _, err := s.Verify(token); !errors.Is(err, ErrInvalid) {
		t.Errorf("Verify() error = %v, want ErrInvalid", err)
	}
}

func TestVerifyWrongKeyFails(t *testing.T) {
	a := NewSigner([]byte("key-a"))
	b := NewSigner([]byte("key-b"))
	token := a.Issue("user-123", time.Hour)

	if _, err := b.Verify(token); !errors.Is(err, ErrInvalid) {
		t.Errorf("Verify() with wrong key error = %v, want ErrInvalid", err)
	}
}

func TestVerifyTamperedUserID(t *testing.T) {
	s := testSigner()
	token := s.Issue("user-123", time.Hour)

	// Substitute a different user id but keep the original MAC -- this must
	// not verify as the substituted id, or the signature buys nothing.
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("unexpected token shape: %q", token)
	}
	tampered := "user-456." + parts[1] + "." + parts[2]

	if _, err := s.Verify(tampered); !errors.Is(err, ErrInvalid) {
		t.Errorf("Verify() with tampered user id error = %v, want ErrInvalid", err)
	}
}

func TestVerifyTamperedExpiry(t *testing.T) {
	s := testSigner()
	// Issue a token that's about to expire, then try to extend it by
	// substituting a far-future expiry with the original MAC still attached.
	token := s.Issue("user-123", time.Second)
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("unexpected token shape: %q", token)
	}
	tampered := parts[0] + ".9999999999." + parts[2]

	if _, err := s.Verify(tampered); !errors.Is(err, ErrInvalid) {
		t.Errorf("Verify() with tampered expiry error = %v, want ErrInvalid", err)
	}
}

func TestVerifyMalformedTokenShapes(t *testing.T) {
	s := testSigner()

	cases := []string{
		"",
		"not-a-token-at-all",
		"only.two",
		"a.b.c.d",
		"user-123.notanumber.abc",
		"user-123.123456.not-valid-base64!!",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if _, err := s.Verify(tc); !errors.Is(err, ErrInvalid) {
				t.Errorf("Verify(%q) error = %v, want ErrInvalid", tc, err)
			}
		})
	}
}

func TestIssueIsFreshEachCall(t *testing.T) {
	s := testSigner()
	a := s.Issue("user-123", time.Hour)
	b := s.Issue("user-123", time.Hour)

	// Both should verify to the same user, but the tokens themselves are not
	// asserted equal -- this documents that Issue is a function of the
	// current time (expiresAt), not deterministic output for a fixed input,
	// which matters if a caller were ever tempted to cache/compare tokens.
	for _, tok := range []string{a, b} {
		if got, err := s.Verify(tok); err != nil || got != "user-123" {
			t.Errorf("Verify(%q) = (%q, %v), want (user-123, nil)", tok, got, err)
		}
	}
}
