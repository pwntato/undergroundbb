// Package session implements the login session cookie -- see
// docs/DESIGN.md, "The session cookie authenticates; it decrypts nothing."
//
// There is deliberately no session store: the cookie is a short-lived
// HMAC-SHA256-signed token the server can verify by recomputing the MAC,
// not a random id the server looks up. This matches the architecture's
// stated constraint ("no session store and no key material" -- the same
// sentence that rules out a server-side session table also rules out
// treating this package's secret as key material for anything else).
//
// docs/DESIGN.md pins the cookie's transport properties (HttpOnly, Secure,
// SameSite=Lax) and its authority (it "names the user to the API and
// nothing more") but not its lifetime or its exact construction -- those
// are this package's implementation choices, documented here rather than
// left silent.
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

// ErrInvalid is returned for any malformed, mis-signed, or expired token.
// Deliberately undifferentiated -- see Verify.
var ErrInvalid = errors.New("session: invalid or expired token")

// tokenContext is HMAC's domain separator, following the same pattern as
// crypto.SigningContext: a session token must never verify as anything
// else this server might someday HMAC, and vice versa.
const tokenContext = "underground-bb:session:v1"

// Signer issues and verifies session tokens under a single server-held
// HMAC key. Stateless: two Signers built from the same key produce and
// accept each other's tokens interchangeably, which is what lets any warm
// Lambda instance verify a cookie any other instance issued.
type Signer struct {
	key []byte
}

// NewSigner builds a Signer from key. key is the deployment's SESSION_SECRET
// (see config.Config) -- treat it as a credential: anyone who holds it can
// mint a valid session for any user id without ever touching the database,
// since there is no server-side record of an issued token to invalidate or
// cross-check against.
func NewSigner(key []byte) *Signer {
	return &Signer{key: key}
}

// Issue builds a signed token naming userID, valid for ttl from now.
func (s *Signer) Issue(userID string, ttl time.Duration) string {
	expiresAt := time.Now().Add(ttl).Unix()
	return s.sign(userID, expiresAt)
}

// Verify checks token's signature and expiry and returns the user id it
// names. It returns ErrInvalid for every failure mode (malformed, wrong
// signature, expired) without distinguishing which -- a cookie is an
// unauthenticated input, and which way it failed is not information a
// caller should get to use to probe the signing key or the clock.
func (s *Signer) Verify(token string) (userID string, err error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", ErrInvalid
	}
	userID, expiresAtStr, macB64 := parts[0], parts[1], parts[2]

	expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64)
	if err != nil {
		return "", ErrInvalid
	}

	wantMAC, err := base64.RawURLEncoding.DecodeString(macB64)
	if err != nil {
		return "", ErrInvalid
	}
	gotMAC := s.mac(userID, expiresAt)
	// subtle.ConstantTimeCompare over a length check first: ConstantTimeCompare
	// itself returns 0 (not constant-time-false, just false) on a length
	// mismatch, and HMAC-SHA256 output is always 32 bytes here, so the only
	// way lengths differ is a corrupted token -- checking length up front
	// costs nothing but avoids relying on that behavior implicitly.
	if len(wantMAC) != len(gotMAC) || subtle.ConstantTimeCompare(wantMAC, gotMAC) != 1 {
		return "", ErrInvalid
	}

	if time.Now().Unix() > expiresAt {
		return "", ErrInvalid
	}
	return userID, nil
}

func (s *Signer) sign(userID string, expiresAt int64) string {
	expiresAtStr := strconv.FormatInt(expiresAt, 10)
	mac := s.mac(userID, expiresAt)
	return userID + "." + expiresAtStr + "." + base64.RawURLEncoding.EncodeToString(mac)
}

// mac computes HMAC-SHA256 over the context, the user id, and the expiry,
// each length-delimited by a NUL separator so no field can migrate into
// another -- the same construction crypto.contextualize uses for signed
// payloads, applied here since a userID is not fixed-width the way a public
// key is and a bare concatenation would be ambiguous.
func (s *Signer) mac(userID string, expiresAt int64) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(tokenContext))
	h.Write([]byte{0})
	h.Write([]byte(userID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(expiresAt, 10)))
	return h.Sum(nil)
}
