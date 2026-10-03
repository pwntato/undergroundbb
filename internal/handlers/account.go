package handlers

import (
	"errors"
	"net/http"

	"github.com/pwntato/undergroundbb/internal/db"
)

// deleteAccount implements DELETE /api/account -- issue #77.
//
// It does not leave groups for the caller: the client leaves each one first,
// because leaving is what signs an admin's own demotion and what enforces the
// last-admin rule (#66, #161). A caller who still belongs to any group gets
// 409 still_member and nothing changes. That is also the answer to #161's
// "who signs the demotion" for account deletion: the departing user does, in
// the leave that precedes the delete, so deletion never needs anyone else's
// signature and never has to pick a successor.
//
// On success PROFILE is a tombstone (see db.DeleteAccount), the username is
// free again and the response clears the caller's own session cookie. Cookies
// issued earlier stay valid until they expire; nothing they can reach would
// work on the tombstone.
func (h *Handler) deleteAccount(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	err := h.db.DeleteAccount(r.Context(), userID)
	switch {
	case err == nil, errors.Is(err, db.ErrAccountCleanupIncomplete):
		// An incomplete sweep leaves only unreachable rows, and the same
		// request can be repeated to finish it, so the account is deleted.
	case errors.Is(err, db.ErrUserNotFound):
		WriteError(w, http.StatusNotFound, "account not found")
		return
	case errors.Is(err, db.ErrStillMember):
		WriteErrorWithCode(w, http.StatusConflict, "leave every group before deleting your account", "still_member")
		return
	default:
		WriteError(w, http.StatusInternalServerError, "could not delete account")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
