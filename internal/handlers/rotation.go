package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

const maxRewrapBodyBytes = 64 * 1024

// rewrapMembersRequest is the body of PUT /api/groups/{groupId}/rotation/members:
// up to db.MaxRewrapBatch members' entry points wrapped for the rotation's
// generation. The client minted the key and does the wrapping; the server only
// stores. Resume is state-driven (members whose generation is behind the
// marker's), so there is no cursor here to get wrong.
type rewrapMembersRequest struct {
	Generation int64            `json:"generation"`
	Wraps      []memberRewrapIn `json:"wraps"`
}

type memberRewrapIn struct {
	UserID     string     `json:"userId"`
	WrappedKey wrappedKey `json:"wrappedKey"`
}

// rewrapMembers implements PUT /api/groups/{groupId}/rotation/members. Admin
// only, and the caller must already hold the rotation's generation (their own
// entry point is at it), since that is the only way to be wrapping its key.
// All-or-nothing: a member who left or moved on fails the batch (409
// member_changed) and the client re-lists and resends.
func (h *Handler) rewrapMembers(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	groupID := r.PathValue("groupId")
	if !idgen.ValidUUID(groupID) {
		groupNotFound(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRewrapBodyBytes)
	var req rewrapMembersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if len(req.Wraps) == 0 || len(req.Wraps) > db.MaxRewrapBatch {
		WriteError(w, http.StatusBadRequest, fmt.Sprintf("wraps: must hold between 1 and %d entries", db.MaxRewrapBatch))
		return
	}
	in := db.RewrapMembersInput{GroupID: groupID, CallerUserID: userID, Generation: req.Generation}
	seen := map[string]bool{}
	for _, w2 := range req.Wraps {
		if !idgen.ValidUUID(w2.UserID) {
			WriteError(w, http.StatusBadRequest, "wraps: malformed userId")
			return
		}
		if w2.UserID == userID || seen[w2.UserID] {
			WriteError(w, http.StatusBadRequest, "wraps: duplicate userId, or the caller's own (already at the generation)")
			return
		}
		seen[w2.UserID] = true
		wk, err := decodeWrappedKey(w2.WrappedKey)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "wraps: wrappedKey: "+err.Error())
			return
		}
		in.Wraps = append(in.Wraps, db.MemberRewrap{UserID: w2.UserID, Wrapped: wk})
	}

	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not re-wrap members")
		return
	}
	if caller == nil {
		groupNotFound(w)
		return
	}
	if caller.Role != models.RoleAdmin {
		WriteError(w, http.StatusForbidden, "only a group admin can re-wrap members")
		return
	}

	if !h.writeRotationErr(w, h.db.RewrapMembers(r.Context(), in), "could not re-wrap members") {
		w.WriteHeader(http.StatusNoContent)
	}
}

type completeRotationRequest struct {
	Generation int64 `json:"generation"`
}

// completeRotation implements POST /api/groups/{groupId}/rotation/complete:
// clears the marker once every member's entry point is at its generation.
// 409 rotation_not_active also covers "someone already finished it", which the
// client treats as done.
func (h *Handler) completeRotation(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	groupID := r.PathValue("groupId")
	if !idgen.ValidUUID(groupID) {
		groupNotFound(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxChangeRoleBodyBytes)
	var req completeRotationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not complete rotation")
		return
	}
	if caller == nil {
		groupNotFound(w)
		return
	}
	if caller.Role != models.RoleAdmin {
		WriteError(w, http.StatusForbidden, "only a group admin can complete a rotation")
		return
	}
	if !h.writeRotationErr(w, h.db.CompleteRotation(r.Context(), groupID, userID, req.Generation), "could not complete rotation") {
		w.WriteHeader(http.StatusNoContent)
	}
}

// writeRotationErr maps the shared rotation errors; it reports whether it
// wrote a response (true for any non-nil err).
func (h *Handler) writeRotationErr(w http.ResponseWriter, err error, fallback string) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, db.ErrRotationNotActive):
		WriteErrorWithCode(w, http.StatusConflict, "no key rotation for that generation is in progress", "rotation_not_active")
	case errors.Is(err, db.ErrRewrapCallerBehind):
		WriteErrorWithCode(w, http.StatusConflict, "your own key is not at the rotation's generation; reload", "rotation_caller_behind")
	case errors.Is(err, db.ErrRewrapMemberChanged):
		WriteErrorWithCode(w, http.StatusConflict, "a member in the batch left or changed; re-list members and resend", "member_changed")
	case errors.Is(err, db.ErrMembersBehind):
		WriteErrorWithCode(w, http.StatusConflict, "some members are not yet on the new key generation", "members_behind")
	case errors.Is(err, db.ErrRoleChangeConflict):
		WriteErrorWithCode(w, http.StatusConflict, "another change was in progress; retry", "conflict_retry")
	default:
		WriteError(w, http.StatusInternalServerError, fallback)
	}
	return true
}
