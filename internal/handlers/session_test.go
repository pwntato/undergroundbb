package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
)

func doGetSession(t *testing.T, h *Handler, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func sessionCookieFrom(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

func TestGetSessionAuthenticated(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)
	loginRec := completeLogin(t, h, user)
	cookie := sessionCookieFrom(loginRec)
	if cookie == nil {
		t.Fatal("no session cookie set by login")
	}

	rec := doGetSession(t, h, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if !body.Authenticated {
		t.Error("Authenticated = false, want true")
	}
	if body.UserID != user.userID {
		t.Errorf("UserID = %q, want %q", body.UserID, user.userID)
	}
}

// TestGetSessionNoCookie and TestGetSessionInvalidCookie both cover
// getSession's own doc comment: a missing/invalid session is a normal 200
// answer, not an error status, since the endpoint exists specifically for
// a client that doesn't yet know whether it's authenticated.
func TestGetSessionNoCookie(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	rec := doGetSession(t, h, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body.Authenticated {
		t.Error("Authenticated = true with no cookie at all")
	}
	if body.UserID != "" {
		t.Errorf("UserID = %q, want empty", body.UserID)
	}
}

func TestGetSessionInvalidCookie(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	rec := doGetSession(t, h, &http.Cookie{Name: sessionCookieName, Value: "garbage.not.a.token"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body.Authenticated {
		t.Error("Authenticated = true with a garbage cookie")
	}
}

// TestRequireSessionBlocksUnauthenticated exercises requireSession through
// a real wired route (changePassword) rather than calling it directly,
// since its whole job is gating that wiring.
func TestRequireSessionBlocksUnauthenticated(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body, err := json.Marshal(changePasswordRequest{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/account/password", bytes.NewReader(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}
