package handlers

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// challengeNonceSize is the login challenge nonce's length in bytes. Large
// enough that guessing it is not a viable substitute for holding the
// private key -- the nonce is not a secret in the sense a key is (the
// server itself stores and later reveals it), but the signature over it is
// what step 4 checks, so a short nonce would not weaken that; this size is
// chosen for comfortable margin rather than because a shorter one is known
// insecure.
const challengeNonceSize = 32

// challengeTTL bounds how long an issued challenge remains valid --
// docs/DESIGN.md: "The TTL is short (a minute or two, enough for a slow
// Argon2id derivation on a phone)."
const challengeTTL = 2 * time.Minute

// lockThreshold and lockDuration implement docs/DESIGN.md's
// "five-attempts-in-five-minutes" lockout exactly as named -- not
// configurable, since the design pins both numbers rather than leaving them
// as deployment policy the way, say, SessionTTL is.
const (
	lockThreshold = 5
	lockDuration  = 5 * time.Minute
)

// sessionCookieName is the login session cookie's name.
const sessionCookieName = "ubb_session"

// challengeRequest is POST /api/auth/challenge's request body.
type challengeRequest struct {
	Username string `json:"username"`
}

// challengeResponse hands back everything the client needs to attempt step
// 3 of docs/DESIGN.md's login sequence: derive the password key, unwrap the
// private keys, and sign Nonce. This is deliberately the same
// offline-crackable material register's client already generated --
// serving it back is not a new exposure, see docs/THREAT_MODEL.md's "Login
// material" section, which this endpoint IS the subject of.
//
// UserID closes issue #125: the client needs the uuid to build
// CredentialWrapAAD before it can unwrap WrappedPrivateKeys, and this is the
// first (and for a fresh device with no prior session, only) response that
// hands it one -- verifyResponse's copy comes back too late, after the
// client has already had to sign the challenge. See challenge's own doc
// comment for why the unknown-username branch returns a decoy uuid here
// rather than omitting the field.
type challengeResponse struct {
	Nonce              string       `json:"nonce"`
	UserID             string       `json:"userId"`
	Salt               string       `json:"salt"`
	Argon2Params       argon2Params `json:"argon2Params"`
	WrappedPrivateKeys wrappedBlob  `json:"wrappedPrivateKeys"`
}

// challenge implements POST /api/auth/challenge -- login step 1-2, see
// issue #27 and docs/DESIGN.md "Login". Unauthenticated and rate-limited by
// terraform/waf.tf's /api/auth/* rule; that rate limit is load-bearing for
// availability, not just for operator spend or harvesting -- see issue
// #27's round-24 comment.
//
// Always responds 200 with a nonce, whether or not the username exists.
// Returning a distinct status/shape for an unknown username would add a
// second enumeration channel shaped differently from the sanctioned one
// (username-available) rather than closing anything -- see docs/DESIGN.md
// on usernames being "confirmable one at a time through the signup
// availability check." The nonce returned for an unknown username signs and
// verifies against nothing real: no CHALLENGE item is ever written for a
// lookup miss (PutChallenge's key requires a real userID), so a client that
// somehow reached this branch cannot complete a login with the result no
// matter what it signs. The same reasoning applies to UserID (issue #125):
// a freshly random decoy uuid, not a distinguishable zero value or omitted
// field, so the unknown-username branch stays shaped exactly like the real
// one.
func (h *Handler) challenge(w http.ResponseWriter, r *http.Request) {
	var req challengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}

	nonce := make([]byte, challengeNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		WriteError(w, http.StatusInternalServerError, "could not generate challenge")
		return
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)

	user, err := h.db.LookupUserByUsername(r.Context(), strings.ToLower(req.Username))
	if err != nil {
		if !errors.Is(err, db.ErrUserNotFound) {
			WriteError(w, http.StatusInternalServerError, "could not process challenge")
			return
		}
		// Unknown username -- see doc comment above. minArgon2* are register.go's
		// own documented floor, reused here only as plausible-shaped filler,
		// not because they mean anything for a nonexistent account. The fake
		// salt and wrapped-key nonce are freshly random, not reused/truncated
		// from the challenge nonce -- a shared byte source across fields
		// would be an odd, needless correlation for no benefit, since none
		// of this needs to be reproducible or tied to anything.
		fakeSalt := make([]byte, 16)
		_, _ = rand.Read(fakeSalt)
		fakeWrapNonce := make([]byte, crypto.NonceSize)
		_, _ = rand.Read(fakeWrapNonce)
		fakeCiphertext := make([]byte, 48)
		_, _ = rand.Read(fakeCiphertext)
		decoyUserID, err := idgen.UUID()
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "could not generate challenge")
			return
		}
		WriteJSON(w, http.StatusOK, challengeResponse{
			Nonce:        nonceB64,
			UserID:       decoyUserID,
			Salt:         base64.StdEncoding.EncodeToString(fakeSalt),
			Argon2Params: argon2Params{MemoryKiB: minArgon2MemoryKiB, Iterations: minArgon2Iterations, Parallelism: minArgon2Parallelism},
			WrappedPrivateKeys: wrappedBlob{
				Nonce:      base64.StdEncoding.EncodeToString(fakeWrapNonce),
				Ciphertext: base64.StdEncoding.EncodeToString(fakeCiphertext),
			},
		})
		return
	}
	userID := user.PK[len("USER#"):]

	if err := h.db.PutChallenge(r.Context(), userID, nonce, challengeTTL); err != nil {
		WriteError(w, http.StatusInternalServerError, "could not issue challenge")
		return
	}

	WriteJSON(w, http.StatusOK, challengeResponse{
		Nonce:        nonceB64,
		UserID:       userID,
		Salt:         base64.StdEncoding.EncodeToString(user.Salt),
		Argon2Params: toWireParams(user.Argon2Params),
		WrappedPrivateKeys: wrappedBlob{
			Nonce:      base64.StdEncoding.EncodeToString(user.WrappedPrivateKeys.Nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(user.WrappedPrivateKeys.Ciphertext),
		},
	})
}

// verifyRequest is POST /api/auth/verify's request body. Nonce is the
// value the client received from POST /api/auth/challenge and signed --
// sent back explicitly rather than having the server re-read it from
// storage, so ConsumeChallenge can be one atomic conditional delete
// (Nonce = the value both sides already agree on) instead of a read
// followed by a separate conditional write with a TOCTOU gap between them.
// The nonce is not a secret the server is protecting by omitting it here
// (the server already handed it to the client in plaintext); what the
// conditional delete protects is single-use, not confidentiality.
type verifyRequest struct {
	Username  string `json:"username"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// verifyErrorChallengeInvalid is returned when there is no outstanding
// challenge matching what the client presented (missing, replayed, or
// overwritten by a newer challenge/flood) -- distinguishable from a bad
// signature specifically so a client can back off rather than immediately
// re-deriving Argon2id into the same losing race. See issue #27's round-24
// comment: "The error returned to the client should be distinguishable from
// a bad password."
const verifyErrorChallengeInvalid = "challenge expired or already used; request a new one"

// verify implements POST /api/auth/verify -- login step 4, see issue #27
// and docs/DESIGN.md "Login". Order of operations here is deliberate and
// each step's failure mode is handled distinctly per the issue's review
// comments:
//
//  1. Look up the user. Unknown username -> the same verifyErrorChallengeInvalid
//     as a missing challenge, not a distinct "no such user" -- a real
//     CHALLENGE item never exists for an unknown user either, so the two
//     cases are naturally indistinguishable without deliberately making
//     them so, and enumeration already has its sanctioned channel.
//  2. Consume the challenge: one conditional delete keyed on the client-
//     supplied nonce matching what's stored. A failed consume is NOT a
//     signature failure -- no lockout counter touch, see ConsumeChallenge's
//     own doc comment.
//  3. Check LockUntil. A locked account is rejected without attempting
//     signature verification -- see docs/DESIGN.md, "the lock is enforced
//     at step 4 only," which this endpoint IS step 4.
//  4. Verify the signature against the stored public key. Failure
//     increments the lockout counter; success clears it and issues a
//     session cookie.
func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil || len(nonce) != challengeNonceSize {
		WriteError(w, http.StatusBadRequest, "nonce: must be valid base64 of the correct length")
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		WriteError(w, http.StatusBadRequest, "signature: must be valid base64 of the correct length")
		return
	}

	user, err := h.db.LookupUserByUsername(r.Context(), strings.ToLower(req.Username))
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			WriteError(w, http.StatusUnauthorized, verifyErrorChallengeInvalid)
			return
		}
		WriteError(w, http.StatusInternalServerError, "could not process verification")
		return
	}
	userID := user.PK[len("USER#"):]

	if err := h.db.ConsumeChallenge(r.Context(), userID, nonce); err != nil {
		if errors.Is(err, db.ErrChallengeMismatch) {
			// Not a signature failure -- see ConsumeChallenge's own doc
			// comment and issue #27's round-24 review comment. No lockout
			// counter touch.
			WriteError(w, http.StatusUnauthorized, verifyErrorChallengeInvalid)
			return
		}
		WriteError(w, http.StatusInternalServerError, "could not process verification")
		return
	}

	if user.LockUntil != "" {
		if lockedUntil, err := time.Parse(time.RFC3339, user.LockUntil); err == nil && time.Now().Before(lockedUntil) {
			// Locked: rejected without attempting signature verification --
			// docs/DESIGN.md, "the lock is enforced at step 4 only," and
			// this check IS that enforcement. Deliberately does not touch
			// FailedVerifyCount either direction: this request never
			// verified anything, successfully or not, and the challenge is
			// already spent regardless of the lock (consuming it first is
			// what closes the replay window even for a locked account).
			WriteError(w, http.StatusForbidden, "account temporarily locked; try again later")
			return
		}
		// A parse failure or an expired lock both fall through to normal
		// verification -- a corrupt LockUntil must not itself become a
		// denial-of-service, and an expired lock is simply no longer
		// locked (RecordFailedVerify overwrites LockUntil on the next
		// failure rather than clearing it on expiry, since nothing reads
		// it again until this check does).
	}

	if !crypto.Verify(user.SigningPublicKey, crypto.ContextLoginChallenge, nonce, sig) {
		if err := h.db.RecordFailedVerify(r.Context(), userID, lockThreshold, lockDuration); err != nil {
			WriteError(w, http.StatusInternalServerError, "could not process verification")
			return
		}
		WriteError(w, http.StatusUnauthorized, "signature verification failed")
		return
	}

	if err := h.db.ClearFailedVerify(r.Context(), userID); err != nil {
		WriteError(w, http.StatusInternalServerError, "could not process verification")
		return
	}

	token := h.sessions.Issue(userID, h.cfg.SessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.cfg.SessionTTL.Seconds()),
	})
	WriteJSON(w, http.StatusOK, verifyResponse{
		UserID:            userID,
		CredentialVersion: user.CredentialVersion,
	})
}

// verifyResponse is POST /api/auth/verify's response body on success. Beyond
// confirming identity, it carries CredentialVersion -- otherwise there is no
// route by which an authenticated client (one that just logged in, as
// opposed to a recovery, which gets its own copy from
// recoveryReleaseResponse) ever learns this value, and PUT
// /api/account/password's ExpectedCredentialVersion has nothing else to read
// it from. This is the moment the client holds the freshly-unwrapped private
// keys and is expected to hold this alongside them for the session's
// lifetime (see issue #32/#33's worker), the same way login already hands
// back Salt/Argon2Params/WrappedPrivateKeys via challengeResponse -- this
// just closes the one field that response shape left out because nothing
// needed it before #30.
type verifyResponse struct {
	UserID            string `json:"userId"`
	CredentialVersion int64  `json:"credentialVersion"`
}

// toWireParams converts models.Argon2Params to the wire shape -- the
// inverse of toModelParams in register.go.
func toWireParams(p models.Argon2Params) argon2Params {
	return argon2Params{
		MemoryKiB:   p.MemoryKiB,
		Iterations:  p.Iterations,
		Parallelism: p.Parallelism,
	}
}
