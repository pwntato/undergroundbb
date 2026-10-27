package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// approveRewrapRequest is the body of POST /api/groups/{groupId}/rewrap/{userId}:
// the group's current key wrapped to the member's new key.
type approveRewrapRequest struct {
	Generation int64      `json:"generation"`
	WrappedKey wrappedKey `json:"wrappedKey"`
	// KeyEpoch is the member's keyEpoch (as served by GET /api/users) the key
	// was wrapped to; the server checks it is still their current epoch.
	KeyEpoch uint64 `json:"keyEpoch"`
	wrapRecordFields
}

// approveRewrap implements POST /api/groups/{groupId}/rewrap/{userId}, the
// write behind approving a dormant member's new key when no generation needs
// minting (docs/DESIGN.md, "Approval: what the admin does, and when it
// mints"). Admin or ambassador. The server enforces the mint rule: in a
// Rotating group the member's entry must be behind the approver's generation,
// otherwise 409 rekey_required sends the admin to the re-key.
func (h *Handler) approveRewrap(w http.ResponseWriter, r *http.Request) {
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
	r.Body = http.MaxBytesReader(w, r.Body, maxRewrapBodyBytes)
	var req approveRewrapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	// Every read happens before any 404 branch, as in readmitMember.
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not approve the key change")
		return
	}
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not approve the key change")
		return
	}
	if caller == nil || group == nil {
		groupNotFound(w)
		return
	}
	if caller.Role != models.RoleAdmin && caller.Role != models.RoleAmbassador {
		WriteError(w, http.StatusForbidden, "only a group admin or ambassador can approve a key change")
		return
	}
	if !idgen.ValidUUID(subjectID) {
		WriteError(w, http.StatusNotFound, "member not found")
		return
	}
	if subjectID == userID {
		WriteError(w, http.StatusBadRequest, "you cannot approve your own key change")
		return
	}
	if req.Generation != caller.Generation {
		WriteError(w, http.StatusBadRequest, "generation: does not match the caller's current generation")
		return
	}
	wk, err := decodeWrappedKey(req.WrappedKey)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "wrappedKey: "+err.Error())
		return
	}
	rec, problem, err := h.wrapRecord(r, req.wrapRecordFields, groupID, userID, subjectID, req.Generation, req.KeyEpoch, crypto.RekeyReasonApproval)
	if err != nil {
		WriteInternalError(w, r, err, "could not approve the key change")
		return
	}
	if problem != nil {
		problem.write(w)
		return
	}
	err = h.db.ApproveRewrap(r.Context(), db.ApproveRewrapInput{
		GroupID:        groupID,
		ApproverUserID: userID,
		MemberUserID:   subjectID,
		Generation:     req.Generation,
		Wrapped:        wk,
		KeyEpoch:       req.KeyEpoch,
		Open:           group.RevocationMode == models.RevocationOpen,
		WrapRecord:     rec,
	})
	switch {
	case errors.Is(err, db.ErrRekeyRequired):
		WriteErrorWithCode(w, http.StatusConflict, "the member's entry is at the current generation; the old keys still read the group, so approving needs a re-key", "rekey_required")
	case errors.Is(err, db.ErrMemberNotDormant):
		WriteErrorWithCode(w, http.StatusConflict, "the member's entry is already wrapped to their current key", "member_not_dormant")
	case errors.Is(err, db.ErrRewrapMemberChanged):
		WriteError(w, http.StatusNotFound, "member not found")
	default:
		if !h.writeRotationErr(w, r, err, "could not approve the key change") {
			w.WriteHeader(http.StatusNoContent)
		}
	}
}
