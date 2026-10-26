package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

// selfWrapRequest is the body of POST /api/groups/{groupId}/rotation/selfwrap:
// the group's key, as the handoff row holds it, wrapped to the caller's own
// current X25519 key as their entry point.
type selfWrapRequest struct {
	Generation int64      `json:"generation"`
	WrappedKey wrappedKey `json:"wrappedKey"`
}

// selfWrap implements POST /api/groups/{groupId}/rotation/selfwrap (#62): a
// member of an Open (or public) group who rotated their account keys brings
// their own entry point to the new key from the key their handoff row holds.
// Any member may call it, for their own entry only; rewrap/{userId} refuses
// the caller's own id on purpose. Nothing is minted, so the generation stays.
// The transaction consumes the handoff row; a row that is missing, names
// another key or holds another generation is 409 handoff_stale, which tells
// the client to delete it. A group that rotates is 400 rotation_not_applicable.
func (h *Handler) selfWrap(w http.ResponseWriter, r *http.Request) {
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
	var req selfWrapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	// Same rule as getGroup: every read happens before any 404 branch.
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not wrap the group key")
		return
	}
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not wrap the group key")
		return
	}
	// The strongly consistent read: the key epoch and the wrapping key below
	// are re-checked by the transaction, but a stale read would send an honest
	// client a spurious refusal.
	self, err := h.db.GetUserByIDConsistent(r.Context(), userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not wrap the group key")
		return
	}
	if caller == nil || group == nil {
		groupNotFound(w)
		return
	}
	if !group.HasNoRotation() {
		WriteErrorWithCode(w, http.StatusBadRequest, "this group rotates its keys; use the re-key", "rotation_not_applicable")
		return
	}
	if req.Generation != caller.Generation {
		WriteError(w, http.StatusBadRequest, "generation: does not match your current key generation")
		return
	}
	wrapped, err := decodeWrappedKey(req.WrappedKey)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "wrappedKey: "+err.Error())
		return
	}
	err = h.db.SelfWrap(r.Context(), db.SelfWrapInput{
		GroupID:           groupID,
		CallerUserID:      userID,
		Generation:        caller.Generation,
		Wrapped:           wrapped,
		CallerKeyEpoch:    self.KeyEpoch,
		CallerWrappingKey: self.WrappingPublicKey,
	})
	switch {
	case errors.Is(err, db.ErrHandoffStale):
		WriteErrorWithCode(w, http.StatusConflict, "your handoff for this group is missing or out of date; delete it", "handoff_stale")
	case errors.Is(err, db.ErrWrapEpochStale):
		WriteErrorWithCode(w, http.StatusConflict, "your keys were rotated by another request; reload and try again", "key_epoch_stale")
	default:
		if !h.writeRotationErr(w, r, err, "could not wrap the group key") {
			w.WriteHeader(http.StatusNoContent)
		}
	}
}
