package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// readmitRequest is an admin's or ambassador's fresh admission of a current
// member (#178). It is the same record an invite's completion stores, signed
// over the member's CURRENT keys, which the server reads itself.
type readmitRequest struct {
	// InviteID is a client-chosen UUID signed into the record in the invite
	// slot. There is no invite; nothing looks it up.
	InviteID string `json:"inviteId"`
	// Generation must equal the caller's own entry-point generation.
	Generation int64 `json:"generation"`
	// InviterGrantRef must be the caller's own current grant.
	InviterGrantRef string `json:"inviterGrantRef"`
	// Day is the UTC date (YYYY-MM-DD) the verifier judges the caller's role
	// and key on, held to the same clock tolerance as a grant's.
	Day       string `json:"day"`
	Signature string `json:"signature"`
}

// readmitMember implements POST /api/groups/{groupId}/members/{userId}/readmit
// (#178, docs/DESIGN.md "Re-admitting a member"): replaces a member's
// admission with the caller's fresh signed one. This exists for a member whose
// inviter's keys cannot be read, or whose inviter's grants changed on the
// admission's own day, so the stored record can never verify and every rotation
// pauses on them.
//
// The server cannot tell WHO is safe to re-admit: a member a removal named
// looks the same as one the inviter lost. That is decided by the client, which
// verifies the removal history and never offers it for a removed member; those
// return only through a fresh invite. The server checks what it can: the caller
// is a current admin or ambassador holding the generation and grant they signed,
// the signature covers the member's stored keys, and the member still exists.
func (h *Handler) readmitMember(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	groupID := r.PathValue("groupId")
	subjectID := r.PathValue("userId")
	if !idgen.ValidUUID(groupID) {
		groupNotFound(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxChangeRoleBodyBytes)
	var req readmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	// Same rule as changeMemberRole: every read happens before any 404 branch.
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not re-admit")
		return
	}
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not re-admit")
		return
	}
	if caller == nil || group == nil {
		groupNotFound(w)
		return
	}
	if caller.Role != models.RoleAdmin && caller.Role != models.RoleAmbassador {
		WriteError(w, http.StatusForbidden, "only a group admin or ambassador can re-admit a member")
		return
	}
	if !idgen.ValidUUID(subjectID) {
		WriteError(w, http.StatusNotFound, "member not found")
		return
	}
	if subjectID == userID {
		WriteError(w, http.StatusBadRequest, "you cannot re-admit yourself")
		return
	}
	subject, err := h.db.GetMembership(r.Context(), groupID, subjectID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not re-admit")
		return
	}
	if subject == nil {
		WriteError(w, http.StatusNotFound, "member not found")
		return
	}
	if !idgen.ValidUUID(req.InviteID) {
		WriteError(w, http.StatusBadRequest, "inviteId: must be a UUID")
		return
	}
	if req.Generation != caller.Generation {
		WriteError(w, http.StatusBadRequest, "generation: does not match the caller's current generation")
		return
	}
	currentRef, hasStored := currentGrantRef(caller, group, userID)
	if currentRef == "" {
		WriteErrorWithCode(w, http.StatusConflict, "your own grant is not on record", "grantor_grant_missing")
		return
	}
	if req.InviterGrantRef != currentRef {
		WriteErrorWithCode(w, http.StatusConflict, "inviterGrantRef is not your current grant; reload and re-sign", "grantor_ref_stale")
		return
	}
	admissionDay, err := time.Parse("2006-01-02", req.Day)
	if err != nil || admissionDay.Format("2006-01-02") != req.Day {
		WriteError(w, http.StatusBadRequest, "day: must be a YYYY-MM-DD date")
		return
	}
	if skew := time.Since(admissionDay.UTC()); skew < -grantDaySkewTolerance || skew > 24*time.Hour+grantDaySkewTolerance {
		WriteError(w, http.StatusBadRequest, "day: not within tolerance of the current UTC day")
		return
	}
	sig, err := decodeBase64Field(req.Signature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "signature: "+err.Error())
		return
	}
	// Both keys come from PROFILEs, never from the request: the signature must
	// cover the keys the server serves for the member, and verify under the
	// caller's current key.
	signer, err := h.db.GetUserByID(r.Context(), userID)
	if err != nil || signer == nil {
		WriteError(w, http.StatusInternalServerError, "could not re-admit")
		return
	}
	member, err := h.db.GetUserByID(r.Context(), subjectID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not re-admit")
		return
	}
	if member == nil {
		WriteError(w, http.StatusNotFound, "member not found")
		return
	}
	payload := crypto.AdmissionPayload(groupID, userID, subjectID, member.SigningPublicKey, member.WrappingPublicKey, req.InviteID, currentRef, req.Day, req.Generation)
	if !crypto.Verify(signer.SigningPublicKey, crypto.ContextAdmission, payload, sig) {
		WriteErrorWithCode(w, http.StatusBadRequest, "signature: does not verify against the caller's current signing key and the member's current keys", "bad_signature")
		return
	}

	err = h.db.ReadmitMember(r.Context(), db.ReadmitMemberInput{
		GroupID:              groupID,
		SubjectUserID:        subjectID,
		SubjectEd25519:       member.SigningPublicKey,
		SubjectX25519:        member.WrappingPublicKey,
		CallerUserID:         userID,
		CallerGeneration:     caller.Generation,
		CallerGrantRef:       currentRef,
		CallerHasStoredGrant: hasStored,
		InviteID:             req.InviteID,
		Day:                  req.Day,
		Signature:            sig,
	})
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, db.ErrReadmitCallerChanged):
		WriteErrorWithCode(w, http.StatusConflict, "your role, generation or grant changed; reload and re-sign", "grantor_changed")
	case errors.Is(err, db.ErrNotMember):
		WriteError(w, http.StatusNotFound, "member not found")
	case errors.Is(err, db.ErrSubjectDeleted):
		WriteErrorWithCode(w, http.StatusGone, "that member's account was deleted", "subject_deleted")
	case errors.Is(err, db.ErrGroupGone):
		WriteErrorWithCode(w, http.StatusGone, "this group no longer exists", "group_gone")
	case errors.Is(err, db.ErrRoleChangeConflict):
		WriteErrorWithCode(w, http.StatusConflict, "another change was in progress; retry", "conflict_retry")
	default:
		WriteError(w, http.StatusInternalServerError, "could not re-admit")
	}
}
