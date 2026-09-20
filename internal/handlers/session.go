package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/pwntato/undergroundbb/internal/session"
)

// sessionUserIDKey is the context key requireSession stores the verified
// user id under. An unexported type keeps it collision-proof against any
// other package's context keys, the standard net/http idiom.
type sessionUserIDKey struct{}

// requireSession wraps next so it only runs when the request carries a
// valid ubb_session cookie, responding 401 otherwise. This is issue #32's
// backend slice: a minimal, self-contained session check rather than a
// generalized middleware chain, since nothing in this codebase yet needs
// more than "is there a valid session, and whose." #33 (signup/login
// screens) is what will need frontend route guarding; this only guards the
// one endpoint (#30's change-password) that needs an authenticated caller
// today.
//
// The verified user id is attached to the request context
// (sessionUserID reads it back) rather than re-verified inside next --
// verification happens exactly once per request.
func (h *Handler) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := h.verifySessionCookie(r)
		if err != nil {
			WriteError(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		ctx := context.WithValue(r.Context(), sessionUserIDKey{}, userID)
		next(w, r.WithContext(ctx))
	}
}

// verifySessionCookie reads and verifies the ubb_session cookie, returning
// the user id it names. Factored out of requireSession so getSession can
// share the identical check without duplicating cookie-reading logic, even
// though the two handlers respond differently on failure (401 vs. a 200
// carrying authenticated: false -- see getSession's own doc comment).
func (h *Handler) verifySessionCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", errNoSessionCookie
	}
	userID, err := h.sessions.Verify(cookie.Value)
	if err != nil {
		return "", err
	}
	return userID, nil
}

var errNoSessionCookie = errors.New("handlers: no session cookie")

// sessionUserID reads the user id requireSession attached to r's context.
// The second return is false if called on a request that never passed
// through requireSession -- a programmer error (wiring a handler to the
// wrong route), not a request-time condition, so callers besides
// requireSession's own wrapped handlers are not expected to check it.
func sessionUserID(r *http.Request) (string, bool) {
	userID, ok := r.Context().Value(sessionUserIDKey{}).(string)
	return userID, ok
}

// sessionResponse is GET /api/auth/session's response body.
type sessionResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"userId,omitempty"`
}

// getSession implements GET /api/auth/session -- issue #32: "GET
// /api/auth/session on app boot." Unlike requireSession's 401, a missing or
// invalid cookie here is not an error: this endpoint exists specifically
// for a client that does not yet know whether it has a session, so
// "unauthenticated" is a normal, 200 answer, not a failure the client must
// handle as one. Always 200; Authenticated is the field a caller branches
// on.
func (h *Handler) getSession(w http.ResponseWriter, r *http.Request) {
	userID, err := h.verifySessionCookie(r)
	if err != nil {
		if !errors.Is(err, errNoSessionCookie) && !errors.Is(err, session.ErrInvalid) {
			WriteError(w, http.StatusInternalServerError, "could not check session")
			return
		}
		WriteJSON(w, http.StatusOK, sessionResponse{Authenticated: false})
		return
	}
	WriteJSON(w, http.StatusOK, sessionResponse{Authenticated: true, UserID: userID})
}
