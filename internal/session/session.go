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
// The token also carries the user's session generation, a counter on the
// user's PROFILE item. The server compares it with the stored value on each
// authenticated request and bumps the stored value on logout, so a token copied
// elsewhere stops working at logout instead of at its expiry. That is one
// counter on an existing item, not a session table: the server still keeps no
// record of individual tokens, and a bump ends every session of that user.
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
const tokenContext = "underground-bb:session:v2"

// Signer issues and verifies session tokens under a single server-held
// HMAC key. Stateless: two Signers built from the same key produce and
// accept each other's tokens interchangeably, which is what lets any warm
// Lambda instance verify a cookie any other instance issued.
type Signer struct {
	key []byte
}

// NewSigner builds a Signer from key. key is the deployment's SESSION_SECRET
// (see config.Config) -- treat it as a credential: anyone who holds it can
// mint a valid session for any user id at any generation without ever
// touching the database, since there is no server-side record of an issued
// token to cross-check against.
func NewSigner(key []byte) *Signer {
	return &Signer{key: key}
}

// Issue builds a signed token naming userID at session generation gen (the
// value on the user's PROFILE when the token is issued), valid for ttl from
// now. The signature covers gen, so a holder cannot raise or lower it.
func (s *Signer) Issue(userID string, gen int64, ttl time.Duration) string {
	expiresAt := time.Now().Add(ttl).Unix()
	return s.sign(userID, gen, expiresAt)
}

// Verify checks token's signature and expiry and returns the user id it
// names. It returns ErrInvalid for every failure mode (malformed, wrong
// signature, expired) without distinguishing which -- a cookie is an
// unauthenticated input, and which way it failed is not information a
// caller should get to use to probe the signing key or the clock.
func (s *Signer) Verify(token string) (userID string, gen int64, err error) {
	parts := strings.SplitN(token, ".", 4)
	if len(parts) != 4 {
		return "", 0, ErrInvalid
	}
	userID, genStr, expiresAtStr, macB64 := parts[0], parts[1], parts[2], parts[3]

	gen, err = strconv.ParseInt(genStr, 10, 64)
	if err != nil {
		return "", 0, ErrInvalid
	}
	expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64)
	if err != nil {
		return "", 0, ErrInvalid
	}

	wantMAC, err := base64.RawURLEncoding.DecodeString(macB64)
	if err != nil {
		return "", 0, ErrInvalid
	}
	gotMAC := s.mac(userID, gen, expiresAt)
	// subtle.ConstantTimeCompare over a length check first: ConstantTimeCompare
	// itself returns 0 (not constant-time-false, just false) on a length
	// mismatch, and HMAC-SHA256 output is always 32 bytes here, so the only
	// way lengths differ is a corrupted token -- checking length up front
	// costs nothing but avoids relying on that behavior implicitly.
	if len(wantMAC) != len(gotMAC) || subtle.ConstantTimeCompare(wantMAC, gotMAC) != 1 {
		return "", 0, ErrInvalid
	}

	if time.Now().Unix() > expiresAt {
		return "", 0, ErrInvalid
	}
	return userID, gen, nil
}

func (s *Signer) sign(userID string, gen, expiresAt int64) string {
	genStr := strconv.FormatInt(gen, 10)
	expiresAtStr := strconv.FormatInt(expiresAt, 10)
	mac := s.mac(userID, gen, expiresAt)
	return userID + "." + genStr + "." + expiresAtStr + "." + base64.RawURLEncoding.EncodeToString(mac)
}

// mac computes HMAC-SHA256 over the context, the user id, the generation, and the expiry,
// each length-delimited by a NUL separator so no field can migrate into
// another -- the same construction crypto.contextualize uses for signed
// payloads, applied here since a userID is not fixed-width the way a public
// key is and a bare concatenation would be ambiguous.
func (s *Signer) mac(userID string, gen, expiresAt int64) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(tokenContext))
	h.Write([]byte{0})
	h.Write([]byte(userID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(gen, 10)))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(expiresAt, 10)))
	return h.Sum(nil)
}
