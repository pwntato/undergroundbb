package handlers

import (
	"net/http"
	"strings"

	"github.com/pwntato/undergroundbb/internal/config"
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
// check" -- signup cannot work without it (better to tell a user their
// chosen name is taken before they've generated keypairs and derived
// Argon2id, not after).
//
// Gated on RegistrationPolicy the same way register is (403 when closed).
// docs/DESIGN.md:1655 says a closed deployment should be read as having a
// smaller enumeration surface than the threat model otherwise assumes --
// leaving this endpoint open on a closed deployment would move the
// name-confirmation oracle DESIGN.md attributes to signup onto a second
// endpoint rather than actually closing it, and a closed deployment has no
// legitimate caller for this check (accounts are provisioned out of band,
// per the same section; invites work by link and never look up a username
// here, per the "an invite has no invitee until step 2" invite section).
//
// The result is advisory, not authoritative -- see db.UsernameAvailable's
// own doc comment. Register's conditional write is what actually decides
// ownership; a client must still handle 409 from register even after this
// says true, since the two calls can race.
func (h *Handler) usernameAvailable(w http.ResponseWriter, r *http.Request) {
	if h.cfg.RegistrationPolicy == config.RegistrationClosed {
		WriteError(w, http.StatusForbidden, "registration is closed on this deployment")
		return
	}

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
