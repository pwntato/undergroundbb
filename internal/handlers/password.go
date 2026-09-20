package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/pwntato/undergroundbb/internal/db"
)

// changePasswordRequest is PUT /api/account/password's request body. The
// client has already unwrapped the private keys with the old password
// (proven only by whether that unwrap succeeds -- there is no server-side
// check of the old password at all, see changePassword's own doc comment)
// and re-wrapped them under the new one, plus generated a fresh recovery
// code and re-wrapped that copy too -- see docs/DESIGN.md, "Changing a
// password does not change keys... It does, however, issue a new recovery
// code and re-wrap the recovery copy under it, invalidating the old."
type changePasswordRequest struct {
	// ExpectedCredentialVersion is the CredentialVersion the client last
	// read (from its own login, or GET /api/auth/session) before deriving
	// these wraps -- see db.RewrapCredentialsInput's own doc comment on why
	// the caller computes this rather than the transaction re-deriving it
	// blind.
	ExpectedCredentialVersion int64 `json:"expectedCredentialVersion"`

	credentialRewrapFields
}

// changePasswordResponse confirms the re-wrap and carries the new
// CredentialVersion, so the client can tell what version its own write
// landed as without a separate read.
type changePasswordResponse struct {
	CredentialVersion int64 `json:"credentialVersion"`
}

// errCredentialVersionStale is the message returned for a
// db.ErrCredentialVersionStale conflict -- see docs/DESIGN.md's "the user
// is told their code is stale rather than being left holding one that
// silently is." Named as a const, matching login.go's
// verifyErrorChallengeInvalid, so the handler and its tests share the
// exact string.
const errCredentialVersionStale = "credentials were changed by another request; reload and try again"

// changePassword implements PUT /api/account/password -- issue #30.
// Authenticated by requireSession (wired in RegisterRoutes), which is this
// endpoint's *only* proof of identity: there is deliberately no
// server-side check of the old password, because the server never has
// anything to check it against -- Argon2id and the private-key unwrap
// happen entirely client-side, and a wrong old password simply produces a
// WrappedPrivateKeys blob that decrypts to garbage on every subsequent
// login, not a rejected request here. See docs/DESIGN.md, "The server
// never receives the password."
//
// Re-wraps PROFILE and RECOVERY together via db.RewrapCredentials, one
// TransactWriteItems conditional on CredentialVersion -- see that
// function's own doc comment and docs/DESIGN.md's contested-write
// paragraph this implements.
func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		// Unreachable via RegisterRoutes' wiring (requireSession always sets
		// this before calling through) -- guarded anyway rather than trusting
		// that wiring never changes under a future edit.
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRegisterBodyBytes)
	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if req.ExpectedCredentialVersion <= 0 {
		WriteError(w, http.StatusBadRequest, "expectedCredentialVersion: must be positive")
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
		WriteError(w, http.StatusInternalServerError, "could not change password")
		return
	}

	WriteJSON(w, http.StatusOK, changePasswordResponse{CredentialVersion: newVersion})
}
