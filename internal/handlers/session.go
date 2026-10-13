package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/pwntato/undergroundbb/internal/db"
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
			if !errors.Is(err, errNoSessionCookie) && !errors.Is(err, session.ErrInvalid) {
				WriteInternalError(w, r, err, "could not check session")
				return
			}
			WriteError(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		ctx := context.WithValue(r.Context(), sessionUserIDKey{}, userID)
		next(w, r.WithContext(ctx))
	}
}

// verifySessionCookie reads and verifies the ubb_session cookie, returning
// the user id it names. Besides the signature and expiry it compares the
// token's session generation with the one stored on the user (#224), so a
// token from before a logout is session.ErrInvalid; a store failure is a
// different error, which callers answer as a 500, never as "logged out". Factored out of requireSession so getSession can
// share the identical check without duplicating cookie-reading logic, even
// though the two handlers respond differently on failure (401 vs. a 200
// carrying authenticated: false -- see getSession's own doc comment).
func (h *Handler) verifySessionCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", errNoSessionCookie
	}
	userID, gen, err := h.sessions.Verify(cookie.Value)
	if err != nil {
		return "", err
	}
	current, err := h.db.GetSessionGeneration(r.Context(), userID)
	if errors.Is(err, db.ErrUserNotFound) {
		return "", session.ErrInvalid
	}
	if err != nil {
		return "", err
	}
	if gen != current {
		return "", session.ErrInvalid
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
			WriteInternalError(w, r, err, "could not check session")
			return
		}
		WriteJSON(w, http.StatusOK, sessionResponse{Authenticated: false})
		return
	}
	WriteJSON(w, http.StatusOK, sessionResponse{Authenticated: true, UserID: userID})
}

// clearSessionCookie expires the session cookie with the same attributes it
// was issued under, which browsers require to match for the clear to apply.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// logout is POST /api/auth/logout (#222, #224). It needs no valid session: a
// visitor whose cookie already expired or was already revoked still gets a
// clean 200 and a cleared cookie. When the cookie is valid, logout also bumps
// the user's session generation, so a token copied elsewhere stops working
// and every other session of that user ends with it. The bump comes before
// the cookie is cleared: if it fails the answer is a 500 and the browser keeps
// its cookie, rather than claiming a logout that did not happen.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	// A cross-site form POST must not be able to log the visitor out. Browsers
	// always send Sec-Fetch-Site; a client that omits it is not a browser
	// being driven by another site, so it is let through.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		WriteError(w, http.StatusForbidden, "cross-site logout refused")
		return
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		// Only a correctly signed token can revoke. A stale generation is
		// harmless: RevokeSessions refuses to bump past a newer login.
		if userID, gen, err := h.sessions.Verify(cookie.Value); err == nil {
			if err := h.db.RevokeSessions(r.Context(), userID, gen); err != nil {
				WriteInternalError(w, r, err, "could not log out")
				return
			}
		}
	}
	clearSessionCookie(w)
	WriteJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}
