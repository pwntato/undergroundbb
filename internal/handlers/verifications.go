package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

const (
	maxVerificationBodyBytes    = 4 * 1024
	defaultVerificationPageSize = 100
	maxVerificationPageSize     = 200
)

// verificationRequest is the wire shape of PUT /api/verifications/{userId}. The
// client signs crypto.VerificationPayload(verifierUUID, verifiedUUID,
// verifierSigningPublicKey, fingerprint) under crypto.ContextVerification with
// its own current signing key. Keys and the signature are base64.
type verificationRequest struct {
	Fingerprint              string `json:"fingerprint"`
	VerifierSigningPublicKey string `json:"verifierSigningPublicKey"`
	Signature                string `json:"signature"`
}

// verificationEntry is one record as served by GET /api/verifications.
type verificationEntry struct {
	VerifiedUserID           string `json:"verifiedUserId"`
	Fingerprint              string `json:"fingerprint"`
	VerifierSigningPublicKey string `json:"verifierSigningPublicKey"`
	Signature                string `json:"signature"`
}

type listVerificationsResponse struct {
	Verifications []verificationEntry `json:"verifications"`
	NextCursor    string              `json:"nextCursor,omitempty"`
}

// putVerification implements PUT /api/verifications/{userId} -- issue #65. It
// stores the caller's signed record that they compared another user's
// fingerprint and it matched, replacing any earlier one.
//
// The server checks the signature against the caller's CURRENT signing key, and
// that the fingerprint is the one it would compute for the other user's current
// keys right now; both are hygiene, not the trust boundary. The second one
// turns "their keys changed while you were comparing" into a clear 409 instead
// of a record that never applies. The party that must verify a record is the
// client reading it back, because the server is who verification protects
// against.
func (h *Handler) putVerification(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	verifiedID := r.PathValue("userId")
	if !idgen.ValidUUID(verifiedID) {
		userNotFound(w)
		return
	}
	if verifiedID == userID {
		WriteError(w, http.StatusBadRequest, "you cannot verify yourself")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxVerificationBodyBytes)
	var req verificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	dec := base64.StdEncoding.DecodeString
	signer, err := dec(req.VerifierSigningPublicKey)
	if err != nil || len(signer) != ed25519.PublicKeySize {
		WriteError(w, http.StatusBadRequest, "verifierSigningPublicKey: must be a base64 32-byte key")
		return
	}
	sig, err := dec(req.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		WriteError(w, http.StatusBadRequest, "signature: must be a base64 64-byte signature")
		return
	}
	if !validFingerprintShape(req.Fingerprint) {
		WriteError(w, http.StatusBadRequest, "fingerprint: must be 12 hyphen-separated groups of 5 digits")
		return
	}

	// Every read happens before any 404 branch, as elsewhere.
	verifier, err := h.db.GetUserByID(r.Context(), userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not save verification")
		return
	}
	verified, verifiedErr := h.db.GetUserByID(r.Context(), verifiedID)
	if errors.Is(verifiedErr, db.ErrUserNotFound) {
		userNotFound(w)
		return
	}
	if verifiedErr != nil {
		WriteInternalError(w, r, verifiedErr, "could not save verification")
		return
	}

	if string(signer) != string(verifier.SigningPublicKey) {
		WriteErrorWithCode(w, http.StatusConflict, "verification is not signed under your current key; re-sign", "verification_signer_stale")
		return
	}
	payload := crypto.VerificationPayload(userID, verifiedID, signer, req.Fingerprint)
	if !crypto.Verify(verifier.SigningPublicKey, crypto.ContextVerification, payload, sig) {
		WriteError(w, http.StatusBadRequest, "signature: does not verify")
		return
	}
	current, err := crypto.Fingerprint(verified.SigningPublicKey, verified.WrappingPublicKey)
	if err != nil {
		WriteInternalError(w, r, err, "could not save verification")
		return
	}
	if current != req.Fingerprint {
		WriteErrorWithCode(w, http.StatusConflict, "that user's keys changed; compare their fingerprint again", "fingerprint_stale")
		return
	}
	if err := h.db.PutVerification(r.Context(), userID, verifiedID, req.Fingerprint, signer, sig); err != nil {
		WriteInternalError(w, r, err, "could not save verification")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteVerification implements DELETE /api/verifications/{userId} -- issue
// #65: the caller withdraws their own record. Deleting one that is not there is
// still 204: the end state is what the caller asked for.
func (h *Handler) deleteVerification(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	verifiedID := r.PathValue("userId")
	if !idgen.ValidUUID(verifiedID) {
		userNotFound(w)
		return
	}
	if err := h.db.DeleteVerification(r.Context(), userID, verifiedID); err != nil {
		WriteInternalError(w, r, err, "could not remove verification")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listVerifications implements GET /api/verifications -- issue #65. It serves
// the caller's OWN records, paginated by verified uuid. The server verifies
// nothing on read: the client must check every signature before trusting one.
func (h *Handler) listVerifications(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	limit := defaultVerificationPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxVerificationPageSize {
			WriteError(w, http.StatusBadRequest, "limit: must be between 1 and "+strconv.Itoa(maxVerificationPageSize))
			return
		}
		limit = n
	}
	cursor := r.URL.Query().Get("cursor")
	if cursor != "" && !idgen.ValidUUID(cursor) {
		WriteError(w, http.StatusBadRequest, "cursor: malformed")
		return
	}
	vs, next, err := h.db.ListVerifications(r.Context(), userID, cursor, limit)
	if err != nil {
		WriteInternalError(w, r, err, "could not list verifications")
		return
	}
	enc := base64.StdEncoding.EncodeToString
	entries := make([]verificationEntry, 0, len(vs))
	for _, v := range vs {
		entries = append(entries, verificationEntry{
			VerifiedUserID:           v.SK[len("VERIFIED#"):],
			Fingerprint:              v.Fingerprint,
			VerifierSigningPublicKey: enc(v.VerifierSigningPublicKey),
			Signature:                enc(v.Signature),
		})
	}
	WriteJSON(w, http.StatusOK, listVerificationsResponse{Verifications: entries, NextCursor: next})
}

// validFingerprintShape reports whether s looks like what crypto.Fingerprint
// returns: twelve groups of five digits joined by hyphens. Shape only;
// whether it is the right fingerprint is the stale-keys check.
func validFingerprintShape(s string) bool {
	if len(s) != 12*5+11 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if i%6 == 5 {
			if s[i] != '-' {
				return false
			}
		} else if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
