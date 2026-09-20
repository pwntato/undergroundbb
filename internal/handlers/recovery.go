package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

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
// -- unknown username, missing RECOVERY, or a verifier mismatch -- comes
// back as the single errInvalidRecoveryAttempt sentinel; only a genuine
// infrastructure error is returned distinctly, for a 500 rather than a 401
// at the HTTP layer.
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

	if !crypto.CheckRecoveryVerifier(code, rec.VerifierSalt, crypto.Argon2IDParams{
		MemoryKiB:   rec.VerifierArgon2Params.MemoryKiB,
		Iterations:  rec.VerifierArgon2Params.Iterations,
		Parallelism: rec.VerifierArgon2Params.Parallelism,
	}, rec.Verifier) {
		return "", nil, errInvalidRecoveryAttempt
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
type recoveryReleaseResponse struct {
	CredentialVersion  int64        `json:"credentialVersion"`
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

	_, rec, err := h.resolveRecovery(r.Context(), strings.ToLower(req.Username), req.RecoveryCode)
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

	credentialRewrapFields
}

// recoveryCodeReset implements PUT /api/account/recovery-code -- issue #31.
// Re-checks the presented code against the verifier itself (resolveRecovery
// again, independent of any earlier call to recoveryCodeRelease) since
// docs/DESIGN.md states the verifier is what authorizes this write, not a
// token minted by the release call. Re-wraps PROFILE and RECOVERY together
// via db.RewrapCredentials, exactly like changePassword.
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

	userID, _, err := h.resolveRecovery(r.Context(), strings.ToLower(req.Username), req.RecoveryCode)
	if err != nil {
		if errors.Is(err, errInvalidRecoveryAttempt) {
			WriteError(w, http.StatusUnauthorized, errRecoveryCodeInvalid)
			return
		}
		WriteError(w, http.StatusInternalServerError, "could not process recovery")
		return
	}

	decoded, err := decodeCredentialRewrapFields(req.credentialRewrapFields)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	newVersion := req.ExpectedCredentialVersion + 1
	err = h.db.RewrapCredentials(r.Context(), db.RewrapCredentialsInput{
		UserID:                    userID,
		ExpectedCredentialVersion: req.ExpectedCredentialVersion,
		NewCredentialVersion:      newVersion,

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
