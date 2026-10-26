package handlers

import (
	"errors"
	"net/http"

	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// convertOpen implements POST /api/groups/{groupId}/convert-open (#61): a
// Rotating group becomes Open, once and never back (everyone who was ever a
// member already holds the old keys, so an upgrade would promise a guarantee
// it cannot deliver). Admin only, no body. The group must be settled: a
// removal still running (409 rotation_in_progress) or a member waiting on its
// wrap (409 members_behind) would be abandoned, since Open never completes a
// marker. A group already Open is 409 already_open. The member cap follows the
// mode at write time (memberCap), so conversion lifts it; the generation chain
// is left as it is.
func (h *Handler) convertOpen(w http.ResponseWriter, r *http.Request) {
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
	// Both reads before either 404 branch, as in getGroup.
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not convert the group")
		return
	}
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not convert the group")
		return
	}
	if group == nil || caller == nil {
		groupNotFound(w)
		return
	}
	if caller.Role != models.RoleAdmin {
		WriteError(w, http.StatusForbidden, "only a group admin can convert a group to Open")
		return
	}
	if group.GroupType == "dm" {
		WriteError(w, http.StatusBadRequest, "a direct message cannot be converted")
		return
	}
	if group.RevocationMode == models.RevocationOpen {
		WriteErrorWithCode(w, http.StatusConflict, "this group is already Open", "already_open")
		return
	}

	err = h.db.ConvertGroupToOpen(r.Context(), groupID, userID, caller.Generation)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, db.ErrNotGroupAdmin):
		WriteError(w, http.StatusForbidden, "only a group admin can convert a group to Open")
	case errors.Is(err, db.ErrGroupAlreadyOpen):
		WriteErrorWithCode(w, http.StatusConflict, "this group is already Open", "already_open")
	case errors.Is(err, db.ErrRotationInProgress):
		WriteErrorWithCode(w, http.StatusConflict, "a key rotation is in progress; convert the group once it finishes", "rotation_in_progress")
	case errors.Is(err, db.ErrMembersBehind):
		WriteErrorWithCode(w, http.StatusConflict, "some members are not yet on the current key generation; convert the group once they are", "members_behind")
	case errors.Is(err, db.ErrRoleChangeConflict):
		WriteErrorWithCode(w, http.StatusConflict, "another change was in progress; retry", "conflict_retry")
	default:
		WriteInternalError(w, r, err, "could not convert the group")
	}
}
