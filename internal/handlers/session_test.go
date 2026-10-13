package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/db"
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

func doLogout(t *testing.T, h *Handler, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func assertSessionCookieCleared(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	c := sessionCookieFrom(rec)
	if c == nil {
		t.Fatal("no Set-Cookie for the session cookie")
	}
	if c.Value != "" || c.MaxAge >= 0 {
		t.Errorf("cookie not expired: value=%q maxAge=%d", c.Value, c.MaxAge)
	}
	if c.Path != "/" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("clearing cookie attributes differ from the issued cookie: %+v", c)
	}
}

func TestLogoutClearsSessionCookie(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)
	cookie := sessionCookieFrom(completeLogin(t, h, user))
	if cookie == nil {
		t.Fatal("no session cookie set by login")
	}

	rec := doLogout(t, h, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	assertSessionCookieCleared(t, rec)
}

func TestLogoutWithoutSessionStillSucceeds(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	rec := doLogout(t, h, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	assertSessionCookieCleared(t, rec)
}

func TestLogoutRefusesCrossSiteRequests(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	for _, site := range []string{"cross-site", "same-site", "none"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		req.Header.Set("Sec-Fetch-Site", site)
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("Sec-Fetch-Site %q: status = %d, want 403", site, rec.Code)
		}
		if sessionCookieFrom(rec) != nil {
			t.Errorf("Sec-Fetch-Site %q: refused request still set a cookie", site)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("same-origin: status = %d, want 200", rec.Code)
	}
}

// #224: logout must end the session server-side, not only drop the browser's
// copy. A token copied before logout is the attacker's stand-in here.
func loggedInCookie(t *testing.T, h *Handler, user registeredUser) *http.Cookie {
	t.Helper()
	cookie := sessionCookieFrom(completeLogin(t, h, user))
	if cookie == nil {
		t.Fatal("no session cookie set by login")
	}
	return cookie
}

func TestLogoutRevokesACopiedToken(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)
	cookie := loggedInCookie(t, h, user)
	copied := &http.Cookie{Name: cookie.Name, Value: cookie.Value}

	if rec := doGetAccountCredentials(t, h, copied); rec.Code != http.StatusOK {
		t.Fatalf("before logout: credentials status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if rec := doLogout(t, h, cookie); rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want 200", rec.Code)
	}

	if rec := doGetAccountCredentials(t, h, copied); rec.Code != http.StatusUnauthorized {
		t.Errorf("after logout: protected route status = %d, want 401, body: %s", rec.Code, rec.Body.String())
	}
	var body sessionResponse
	rec := doGetSession(t, h, copied)
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if rec.Code != http.StatusOK || body.Authenticated {
		t.Errorf("after logout: GET session = %d authenticated=%v, want 200 false", rec.Code, body.Authenticated)
	}
}

func TestLogoutEndsEveryTokenOfTheUser(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)
	laptop := loggedInCookie(t, h, user)
	phone := loggedInCookie(t, h, user)

	doLogout(t, h, laptop)

	if rec := doGetAccountCredentials(t, h, phone); rec.Code != http.StatusUnauthorized {
		t.Errorf("other session after logout: status = %d, want 401", rec.Code)
	}
}

func TestLoginAfterLogoutGetsAWorkingSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)
	doLogout(t, h, loggedInCookie(t, h, user))

	fresh := loggedInCookie(t, h, user)
	if rec := doGetAccountCredentials(t, h, fresh); rec.Code != http.StatusOK {
		t.Errorf("fresh login after logout: status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
}

// A revoked token replayed to logout must not bump the counter past the newer
// login, or whoever holds an old token could sign the user out at will.
func TestRevokedTokenCannotLogOutANewerSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)
	old := loggedInCookie(t, h, user)
	doLogout(t, h, old)
	fresh := loggedInCookie(t, h, user)

	if rec := doLogout(t, h, &http.Cookie{Name: old.Name, Value: old.Value}); rec.Code != http.StatusOK {
		t.Fatalf("replayed logout status = %d, want 200", rec.Code)
	}
	if rec := doGetAccountCredentials(t, h, fresh); rec.Code != http.StatusOK {
		t.Errorf("newer session after replayed logout: status = %d, want 200", rec.Code)
	}
}

// A token with a valid signature for a generation the user never had is not
// a session either, in both directions.
func TestSessionWithWrongGenerationIsRejected(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)
	for _, gen := range []int64{1, 5} {
		token := h.sessions.Issue(user.userID, gen, time.Hour)
		cookie := &http.Cookie{Name: sessionCookieName, Value: token}
		if rec := doGetAccountCredentials(t, h, cookie); rec.Code != http.StatusUnauthorized {
			t.Errorf("generation %d: status = %d, want 401", gen, rec.Code)
		}
	}
	token := h.sessions.Issue(user.userID, 0, time.Hour)
	if rec := doGetAccountCredentials(t, h, &http.Cookie{Name: sessionCookieName, Value: token}); rec.Code != http.StatusOK {
		t.Errorf("generation 0: status = %d, want 200", rec.Code)
	}
}

func TestSessionOfAnUnknownUserIsRejected(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	token := h.sessions.Issue("no-such-user-"+randomUsername(t), 0, time.Hour)
	if rec := doGetAccountCredentials(t, h, &http.Cookie{Name: sessionCookieName, Value: token}); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// A store failure must never read as "not logged in" (the web client would
// drop a live session) and logout must not claim success it did not have.
func TestSessionStoreFailureIsA500NotALogout(t *testing.T) {
	good := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, good)
	cookie := loggedInCookie(t, good, user)
	failing := New(config.FromEnv(), conflictingDBOn(t, "GetItem", "ValidationException",
		`{"__type":"com.amazon.coral.validate#ValidationException","message":"injected"}`))

	if rec := doGetAccountCredentials(t, failing, cookie); rec.Code != http.StatusInternalServerError {
		t.Errorf("protected route: status = %d, want 500", rec.Code)
	}
	if rec := doGetSession(t, failing, cookie); rec.Code != http.StatusInternalServerError {
		t.Errorf("GET session: status = %d, want 500", rec.Code)
	}

	failingWrite := New(config.FromEnv(), conflictingDBOn(t, "UpdateItem", "ValidationException",
		`{"__type":"com.amazon.coral.validate#ValidationException","message":"injected"}`))
	rec := doLogout(t, failingWrite, cookie)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("logout with failing revoke: status = %d, want 500", rec.Code)
	}
	if sessionCookieFrom(rec) != nil {
		t.Error("failed logout still cleared the cookie")
	}
	if rec := doGetAccountCredentials(t, good, cookie); rec.Code != http.StatusOK {
		t.Errorf("session after failed logout: status = %d, want 200", rec.Code)
	}
}

// staleReadsDB returns a db.Client in front of DynamoDB Local that answers
// every GetItem not asking for ConsistentRead with a session generation of 0,
// as a lagging replica would after a logout. DynamoDB Local is always
// consistent, so without this the eventual-consistency race cannot be seen.
func staleReadsDB(t *testing.T) *db.Client {
	t.Helper()
	target, err := url.Parse(testEndpoint(t))
	if err != nil {
		t.Fatalf("parsing DYNAMODB_ENDPOINT: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	director := proxy.Director
	proxy.Director = func(r *http.Request) {
		director(r)
		r.Header.Del("Accept-Encoding") // keep the response body readable
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		if !strings.HasSuffix(resp.Request.Header.Get("X-Amz-Target"), ".GetItem") {
			return nil
		}
		if resp.Request.Header.Get("X-Test-Consistent") == "1" {
			return nil
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		if item, ok := out["Item"].(map[string]any); ok {
			item["SessionGeneration"] = map[string]any{"N": "0"}
		}
		body, err = json.Marshal(out)
		if err != nil {
			return err
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return nil
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading proxied request: %v", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		if strings.Contains(string(raw), `"ConsistentRead":true`) {
			r.Header.Set("X-Test-Consistent", "1")
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	c, err := db.New(context.Background(), testTableName(), srv.URL)
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	return c
}

// A login right after a logout must get a session that works even when the
// profile lookup login does is served by a replica that has not seen the
// logout yet (review of #227).
func TestLoginRightAfterLogoutIsNotDeadOnArrival(t *testing.T) {
	good := New(config.FromEnv(), testDB(t))
	lagging := New(config.FromEnv(), staleReadsDB(t))
	user := registerTestUser(t, good)
	doLogout(t, good, loggedInCookie(t, good, user))

	fresh := loggedInCookie(t, lagging, user)
	if rec := doGetAccountCredentials(t, good, fresh); rec.Code != http.StatusOK {
		t.Errorf("session from a login served by a lagging replica: status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
}
