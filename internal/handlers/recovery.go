package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/models"
)

// maxRecoveryCodeLen bounds the recovery code field on an unauthenticated
// endpoint. docs/DESIGN.md's code is 30 bytes as rendered (26 characters
// plus 4 hyphens); this is generous relative to that real shape for the
// same reason maxSaltLen is generous relative to a real salt -- turning an
// oversized value into a 400 here rather than feeding an unbounded string
// into Argon2id.
const maxRecoveryCodeLen = 256

// errRecoveryCodeInvalid is the uniform response for every way a recovery
// release/reset attempt can fail to authenticate: unknown username, wrong
// code, or a user with no RECOVERY item at all. See docs/DESIGN.md's
// enumeration reasoning for /auth/challenge (verifyErrorChallengeInvalid
// in login.go) -- the same logic applies here: distinguishing "no such
// user" from "wrong code" would hand an attacker a free username oracle on
// top of the one usernameAvailable already grants deliberately, for no
// benefit to a legitimate caller.
const errRecoveryCodeInvalid = "invalid username or recovery code"

// idempotencyTokenLen is recoveryResetRequest's IdempotencyToken's required
// decoded length -- 16 bytes (128 bits), generous entropy for a value whose
// only job is to distinguish one reset attempt from any other the same
// client might make, not to resist any cryptographic attack the way a real
// credential field must. See recoveryCodeReset's own doc comment; issue
// #130.
const idempotencyTokenLen = 16

// errInvalidRecoveryAttempt is resolveRecovery's internal sentinel for
// every uniform-response failure mode -- callers map it to
// errRecoveryCodeInvalid at the HTTP layer rather than comparing against a
// message string.
var errInvalidRecoveryAttempt = errors.New("handlers: invalid username or recovery code")

// resolveRecovery looks up username, then that user's RECOVERY item, and
// checks code against its stored verifier. Shared by recoveryCodeRelease
// and recoveryCodeReset -- see docs/DESIGN.md, "That verifier is also what
// authorizes the recovery reset's write to PROFILE and RECOVERY," i.e. both
// endpoints re-derive this same check rather than one trusting a token
// minted by the other. There is deliberately no intermediate token linking
// a release call to a later reset call: docs/DESIGN.md names the verifier
// itself, re-checked, as what authorizes the write.
//
// Returns the resolved userID and RECOVERY item on success. Every failure
// -- unknown username, missing RECOVERY, a currently-locked RECOVERY item,
// or a verifier mismatch -- comes back as the single errInvalidRecoveryAttempt
// sentinel; only a genuine infrastructure error is returned distinctly, for
// a 500 rather than a 401 at the HTTP layer. A locked RECOVERY item is
// deliberately indistinguishable from a wrong code in the response, for the
// same enumeration-resistance reason as every other case here: a
// distinguishable "locked" response would be a new oracle this endpoint
// doesn't otherwise grant.
//
// Consults and updates RECOVERY's own FailedVerifyCount/LockUntil (issue
// #136) -- deliberately NOT User.FailedVerifyCount/LockUntil, the counter
// PR #118 round 2 review scoped to /auth/challenge's step-4 signature
// failures (DESIGN.md:193, "bounding credential stuffing"). Reusing that
// counter here would corrupt its meaning (a wrong recovery code is not the
// failure it counts) and would let a recovery-guessing attacker lock a
// user out of logging in, a worse outcome than intended. Before #136, this
// path had no application-side bound on guessing at all -- the recovery
// code (THREAT_MODEL.md: "equivalent to the password, not a lesser factor")
// was the one credential that never reached any counter, unlike the
// password, which never reaches the server to be guessed against in the
// first place. terraform/waf.tf's rate-limit-auth rule remains the only
// bound in front of this path that's keyed by anything other than the
// account itself, and it's IP-keyed -- see that rule's own comment for why
// that doesn't close a distributed attempt against one account; #136's
// counter is what closes the account-keyed half.
//
// A lost-response retry of recoveryCodeReset (issue #130) necessarily
// re-presents the same, now-superseded code and so always fails the
// verifier check below and counts as one failed attempt here, before
// recoveryCodeReset's own IsOwnRewrap fallback ever runs -- a deliberate
// choice (issue #136) over threading retry-awareness into this shared,
// security-sensitive check: a legitimate retry costs one of five attempts,
// not a lockout by itself.
func (h *Handler) resolveRecovery(ctx context.Context, usernameLower, code string) (userID string, recovery *models.Recovery, err error) {
	user, err := h.db.LookupUserByUsername(ctx, usernameLower)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			return "", nil, errInvalidRecoveryAttempt
		}
		return "", nil, err
	}
	uid := user.PK[len("USER#"):]

	rec, err := h.db.GetRecovery(ctx, uid)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			// A PROFILE without a RECOVERY item -- docs/DESIGN.md names the
			// transaction in Register as what forecloses this in the normal
			// case, but this endpoint doesn't get to assume that transaction
			// is the only writer forever, same reasoning as
			// LookupUserByUsername's own doc comment. Same uniform error.
			return "", nil, errInvalidRecoveryAttempt
		}
		return "", nil, err
	}

	if rec.LockUntil != "" {
		if lockedUntil, err := time.Parse(time.RFC3339, rec.LockUntil); err == nil && time.Now().Before(lockedUntil) {
			// Locked: rejected without attempting the verifier check, same
			// shape as login.go's verify -- "the lock is enforced at step 4
			// only" there, this is the equivalent enforcement point here.
			// Does not touch FailedVerifyCount either direction.
			return "", nil, errInvalidRecoveryAttempt
		}
		// A parse failure or an expired lock both fall through to the
		// verifier check -- same reasoning as login.go's verify: a corrupt
		// LockUntil must not itself become a denial-of-service, and an
		// expired lock is simply no longer locked (RecordFailedRecoveryVerify
		// overwrites LockUntil on the next failure rather than clearing it
		// on expiry, since nothing reads it again until this check does).
	}

	if !crypto.CheckRecoveryVerifier(code, rec.VerifierSalt, crypto.Argon2IDParams{
		MemoryKiB:   rec.VerifierArgon2Params.MemoryKiB,
		Iterations:  rec.VerifierArgon2Params.Iterations,
		Parallelism: rec.VerifierArgon2Params.Parallelism,
	}, rec.Verifier) {
		if recErr := h.db.RecordFailedRecoveryVerify(ctx, uid, lockThreshold, lockDuration); recErr != nil {
			return "", nil, recErr
		}
		return "", nil, errInvalidRecoveryAttempt
	}

	if err := h.db.ClearFailedRecoveryVerify(ctx, uid); err != nil {
		return "", nil, err
	}

	return uid, rec, nil
}

// recoveryReleaseRequest is POST /api/account/recovery-code/release's
// request body.
type recoveryReleaseRequest struct {
	Username     string `json:"username"`
	RecoveryCode string `json:"recoveryCode"`
}

// recoveryReleaseResponse hands back what the client needs to unwrap the
// private keys with the presented code -- see docs/DESIGN.md, "unwrapping
// is a read: the client needs the blob and the recovery salt." Also
// carries CredentialVersion, so the client's subsequent
// PUT /api/account/recovery-code can supply ExpectedCredentialVersion
// without a second read.
//
// UserID closes issue #125, the recovery-side twin of challengeResponse's
// same addition: the client needs the uuid to build CredentialWrapAAD
// before it can unwrap WrappedPrivateKeys. Unlike challenge, there is no
// decoy branch to match here -- every failure mode (unknown username, wrong
// code, missing RECOVERY item) already returns the single uniform
// errRecoveryCodeInvalid error rather than a fabricated success body, so
// this field is only ever populated once resolveRecovery has confirmed a
// real user and a correct code.
type recoveryReleaseResponse struct {
	CredentialVersion  int64        `json:"credentialVersion"`
	UserID             string       `json:"userId"`
	Salt               string       `json:"salt"`
	Argon2Params       argon2Params `json:"argon2Params"`
	WrappedPrivateKeys wrappedBlob  `json:"wrappedPrivateKeys"`
}

// recoveryCodeRelease implements POST /api/account/recovery-code/release --
// issue #31's code-gated release endpoint. Unauthenticated (a user
// recovering has no session, docs/DESIGN.md: "a user recovering has no
// session and no password, so no authenticated route could hand it over
// either") but gated on resolveRecovery's verifier check rather than open
// like /auth/challenge -- see docs/DESIGN.md's "weaker than 'no read path'
// and meaningfully stronger than the login blob."
func (h *Handler) recoveryCodeRelease(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRegisterBodyBytes)
	var req recoveryReleaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if len(req.RecoveryCode) == 0 || len(req.RecoveryCode) > maxRecoveryCodeLen {
		WriteError(w, http.StatusBadRequest, "recoveryCode: must be 1-"+strconv.Itoa(maxRecoveryCodeLen)+" characters")
		return
	}

	userID, rec, err := h.resolveRecovery(r.Context(), strings.ToLower(req.Username), req.RecoveryCode)
	if err != nil {
		if errors.Is(err, errInvalidRecoveryAttempt) {
			WriteError(w, http.StatusUnauthorized, errRecoveryCodeInvalid)
			return
		}
		WriteError(w, http.StatusInternalServerError, "could not process recovery")
		return
	}

	WriteJSON(w, http.StatusOK, recoveryReleaseResponse{
		CredentialVersion: rec.CredentialVersion,
		UserID:            userID,
		Salt:              base64.StdEncoding.EncodeToString(rec.Salt),
		Argon2Params:      toWireParams(rec.Argon2Params),
		WrappedPrivateKeys: wrappedBlob{
			Nonce:      base64.StdEncoding.EncodeToString(rec.WrappedPrivateKeys.Nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(rec.WrappedPrivateKeys.Ciphertext),
		},
	})
}

// recoveryResetRequest is PUT /api/account/recovery-code's request body --
// the mirror of changePasswordRequest, authenticated by the recovery code
// instead of a session. See docs/DESIGN.md, "The client unwraps the
// private keys with the code, sets a new password, and re-wraps both
// copies... It also issues a new recovery code."
type recoveryResetRequest struct {
	Username                  string `json:"username"`
	RecoveryCode              string `json:"recoveryCode"`
	ExpectedCredentialVersion int64  `json:"expectedCredentialVersion"`

	// IdempotencyToken is a random value the client generates once per
	// reset attempt (not per submission -- runRecovery.ts keeps it across a
	// manual retry) and resends unchanged only when retrying an attempt
	// whose response it never saw. Optional: an empty string disables
	// recoveryCodeReset's retry fallback entirely (every ambiguous failure
	// is reported as-is, exactly as before issue #130) -- a client that
	// hasn't adopted the retry flow yet is unaffected.
	IdempotencyToken string `json:"idempotencyToken"`

	credentialRewrapFields
}

// recoveryCodeReset implements PUT /api/account/recovery-code -- issue #31.
// Re-checks the presented code against the verifier itself (resolveRecovery
// again, independent of any earlier call to recoveryCodeRelease) since
// docs/DESIGN.md states the verifier is what authorizes this write, not a
// token minted by the release call. Re-wraps PROFILE and RECOVERY together
// via db.RewrapCredentials, exactly like changePassword.
//
// Handles issue #130's retry case: once a reset has landed, its own retry
// -- necessarily presenting the same, now-superseded code, since the client
// never learned the new one -- fails resolveRecovery's check like any wrong
// code would, before ever reaching RewrapCredentials. If the request also
// carries a matching IdempotencyToken, that failure is treated as this
// caller's own earlier write landing late rather than a real authentication
// failure: db.IsOwnRewrap confirms RECOVERY is at exactly the version this
// request would itself have produced, with the token to match, and the
// original success response is replayed rather than a spurious 401. See
// db.IsOwnRewrap's own doc comment for the full sequence and why this check
// cannot live inside RewrapCredentials the way Register's #124 fix does.
func (h *Handler) recoveryCodeReset(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRegisterBodyBytes)
	var req recoveryResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if len(req.RecoveryCode) == 0 || len(req.RecoveryCode) > maxRecoveryCodeLen {
		WriteError(w, http.StatusBadRequest, "recoveryCode: must be 1-"+strconv.Itoa(maxRecoveryCodeLen)+" characters")
		return
	}
	if req.ExpectedCredentialVersion <= 0 {
		WriteError(w, http.StatusBadRequest, "expectedCredentialVersion: must be positive")
		return
	}
	var idempotencyToken []byte
	if req.IdempotencyToken != "" {
		// wantLen is idempotencyTokenLen, not 0 -- a caller that sets this
		// field at all must send a real token, not an arbitrary-length value
		// that happens to be non-empty.
		token, err := decodeBase64Field(req.IdempotencyToken, idempotencyTokenLen, idempotencyTokenLen)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "idempotencyToken: "+err.Error())
			return
		}
		idempotencyToken = token
	}
	// Decoded once, up front -- both the normal write below and the retry
	// fallback need it: the fallback compares it against what's already
	// stored (db.IsOwnRewrap's own doc comment on why a token+version match
	// alone is not enough, PR #133 round 1's lesson applied here too),
	// rather than trusting the token match alone.
	decoded, err := decodeCredentialRewrapFields(req.credentialRewrapFields)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	newVersion := req.ExpectedCredentialVersion + 1
	usernameLower := strings.ToLower(req.Username)

	userID, _, err := h.resolveRecovery(r.Context(), usernameLower, req.RecoveryCode)
	if err != nil {
		if !errors.Is(err, errInvalidRecoveryAttempt) {
			WriteError(w, http.StatusInternalServerError, "could not process recovery")
			return
		}
		// The uniform failure resolveRecovery returns for every cause --
		// unknown username, missing RECOVERY, or (the retry case this
		// fallback exists for) a code that no longer matches because this
		// caller's own earlier reset already rotated it. Only worth a
		// second lookup at all when a token was presented; otherwise this is
		// definitely just a failed attempt.
		if len(idempotencyToken) == 0 {
			WriteError(w, http.StatusUnauthorized, errRecoveryCodeInvalid)
			return
		}
		user, lookupErr := h.db.LookupUserByUsername(r.Context(), usernameLower)
		if lookupErr != nil {
			if errors.Is(lookupErr, db.ErrUserNotFound) {
				WriteError(w, http.StatusUnauthorized, errRecoveryCodeInvalid)
				return
			}
			WriteError(w, http.StatusInternalServerError, "could not process recovery")
			return
		}
		retryUserID := user.PK[len("USER#"):]
		isRetry, checkErr := h.db.IsOwnRewrap(r.Context(), retryUserID, idempotencyToken, newVersion, db.RewrapMaterial{
			RecoverySalt:               decoded.RecoverySalt,
			RecoveryArgon2Params:       decoded.RecoveryArgon2Params,
			RecoveryWrappedPrivateKeys: decoded.RecoveryWrappedPrivateKeys,

			RecoveryVerifierSalt:   decoded.RecoveryVerifierSalt,
			RecoveryVerifierParams: decoded.RecoveryVerifierParams,
			RecoveryVerifier:       decoded.RecoveryVerifier,
		})
		if checkErr != nil {
			WriteError(w, http.StatusInternalServerError, "could not process recovery")
			return
		}
		if !isRetry {
			WriteError(w, http.StatusUnauthorized, errRecoveryCodeInvalid)
			return
		}
		// Confirmed: RECOVERY is already at exactly the version this
		// request's own write would have produced, under this same token,
		// with this same material. Nothing left to write -- replay the
		// success this caller never saw.
		WriteJSON(w, http.StatusOK, changePasswordResponse{CredentialVersion: newVersion})
		return
	}

	err = h.db.RewrapCredentials(r.Context(), db.RewrapCredentialsInput{
		UserID:                    userID,
		ExpectedCredentialVersion: req.ExpectedCredentialVersion,
		NewCredentialVersion:      newVersion,
		IdempotencyToken:          idempotencyToken,

		Salt:               decoded.Salt,
		Argon2Params:       decoded.Argon2Params,
		WrappedPrivateKeys: decoded.WrappedPrivateKeys,

		RecoverySalt:               decoded.RecoverySalt,
		RecoveryArgon2Params:       decoded.RecoveryArgon2Params,
		RecoveryWrappedPrivateKeys: decoded.RecoveryWrappedPrivateKeys,

		RecoveryVerifierSalt:   decoded.RecoveryVerifierSalt,
		RecoveryVerifierParams: decoded.RecoveryVerifierParams,
		RecoveryVerifier:       decoded.RecoveryVerifier,
	})
	if err != nil {
		if errors.Is(err, db.ErrCredentialVersionStale) {
			WriteError(w, http.StatusConflict, errCredentialVersionStale)
			return
		}
		WriteError(w, http.StatusInternalServerError, "could not reset credentials")
		return
	}

	WriteJSON(w, http.StatusOK, changePasswordResponse{CredentialVersion: newVersion})
}
