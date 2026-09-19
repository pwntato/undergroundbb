package handlers

import (
	"net/http"
	"strings"
)

// usernameAvailableResponse reports whether a candidate username is free to
// register. It deliberately says only "available" and nothing about why
// not -- there is no separate "invalid" vs "taken" status, since both a
// syntactically invalid candidate and a claimed one are equally
// unregistrable, and a client typing a name in real time only needs the one
// bit.
type usernameAvailableResponse struct {
	Available bool `json:"available"`
}

// usernameAvailable implements GET /api/auth/username-available?u=<name> --
// see issue #26. Unauthenticated and rate-limited (terraform/waf.tf's
// /api/auth/* rule already covers this path by prefix; no separate rule was
// needed). This is a deliberate enumeration surface: see docs/DESIGN.md,
// "usernames are confirmable one at a time through the signup availability
// check" -- invites need it (a client must be able to tell a typo from a
// taken name before sending an invite) and signup cannot work without it
// (better to tell a user their chosen name is taken before they've
// generated keypairs and derived Argon2id, not after).
//
// The result is advisory, not authoritative -- see db.UsernameAvailable's
// own doc comment. Register's conditional write is what actually decides
// ownership; a client must still handle 409 from register even after this
// says true, since the two calls can race.
func (h *Handler) usernameAvailable(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("u")
	if !usernamePattern.MatchString(u) {
		// A syntactically invalid candidate is reported as unavailable
		// rather than a 400 -- see usernameAvailableResponse's own comment.
		// A client polling this endpoint as someone types (before they've
		// finished a name that would pass usernamePattern) is the expected
		// caller, not a malformed request.
		WriteJSON(w, http.StatusOK, usernameAvailableResponse{Available: false})
		return
	}

	available, err := h.db.UsernameAvailable(r.Context(), strings.ToLower(u))
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not check username availability")
		return
	}
	WriteJSON(w, http.StatusOK, usernameAvailableResponse{Available: available})
}
