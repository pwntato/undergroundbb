package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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
// issued earlier stay valid until they expire. A stale cookie cannot create a
// membership (CreateGroup and CompleteInvite refuse a deleted account), but
// anything else it writes, such as pins or an invite acceptance that can never
// complete, lands on a partition nobody can sign in to.
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
		WriteInternalError(w, r, err, "could not delete account")
		return
	}
	clearSessionCookie(w)
	WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// MaxBioRunes is the longest bio, in characters; MaxBioBytes bounds the same
// text in bytes so a bio of four-byte characters cannot be four times the size.
const (
	MaxBioRunes = 280
	MaxBioBytes = 1024
	maxBioBody  = 4 * 1024
)

type putBioRequest struct {
	Bio string `json:"bio"`
}

// validBio reports whether s is acceptable bio text: valid UTF-8, within both
// caps, and free of control characters other than newline. s is already
// trimmed by the caller.
func validBio(s string) bool {
	if !utf8.ValidString(s) || len(s) > MaxBioBytes || utf8.RuneCountInString(s) > MaxBioRunes {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' {
			return false
		}
	}
	return true
}

// putBio implements PUT /api/account/bio -- issue #75. The bio is plaintext,
// stored on PROFILE and served to every signed-in user by GET /api/users/{id}
// (the users projection), so it is public to the site like the username. It
// is deliberately not signed: nothing trusts it, and it carries no key
// material. An empty bio clears it.
func (h *Handler) putBio(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBioBody)
	var req putBioRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	bio := strings.TrimSpace(req.Bio)
	if !validBio(bio) {
		WriteError(w, http.StatusBadRequest, "bio: at most "+strconv.Itoa(MaxBioRunes)+" characters, no control characters")
		return
	}
	switch err := h.db.SetBio(r.Context(), userID, bio); {
	case err == nil:
		WriteJSON(w, http.StatusOK, map[string]string{"bio": bio})
	case errors.Is(err, db.ErrUserNotFound):
		WriteError(w, http.StatusNotFound, "account not found")
	default:
		WriteInternalError(w, r, err, "could not save bio")
	}
}
