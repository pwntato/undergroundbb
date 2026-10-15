package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/db"
)

// A password change or a recovery reset is what someone does when they think
// they are compromised, so it has to end every session that existed before it
// (#224's counter, the same one logout bumps). The bump rides in the
// credential re-wrap's own transaction, so these tests look for the two ways it
// could be wrong: a session that survives, and a session the caller loses.

func changePasswordRequestAt(version int64) changePasswordRequest {
	return changePasswordRequest{
		ExpectedCredentialVersion: version,
		credentialRewrapFields:    validCredentialRewrapFields(),
	}
}

func TestChangePasswordEndsOtherSessionsAndKeepsTheCallers(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)
	laptop := loggedInCookie(t, h, user)
	phone := loggedInCookie(t, h, user)
	stolen := &http.Cookie{Name: laptop.Name, Value: laptop.Value}

	rec := doChangePassword(t, h, laptop, changePasswordRequestAt(1))
	if rec.Code != http.StatusOK {
		t.Fatalf("change status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	reissued := sessionCookieFrom(rec)
	if reissued == nil || reissued.MaxAge <= 0 || reissued.Value == "" {
		t.Fatalf("change did not reissue a session cookie: %+v", reissued)
	}

	for name, old := range map[string]*http.Cookie{"the caller's old token": laptop, "a copied token": stolen, "another device": phone} {
		if rec := doGetAccountCredentials(t, h, old); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s after the change: status = %d, want 401", name, rec.Code)
		}
	}
	if rec := doGetAccountCredentials(t, h, reissued); rec.Code != http.StatusOK {
		t.Fatalf("reissued token: status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	// The reissued token carries the new generation, so it can change the
	// password again and then be replaced in turn (generation 1 -> 2).
	second := doChangePassword(t, h, reissued, changePasswordRequestAt(2))
	if second.Code != http.StatusOK {
		t.Fatalf("second change status = %d, want 200, body: %s", second.Code, second.Body.String())
	}
	if rec := doGetAccountCredentials(t, h, reissued); rec.Code != http.StatusUnauthorized {
		t.Errorf("token from before the second change: status = %d, want 401", rec.Code)
	}
	if rec := doGetAccountCredentials(t, h, sessionCookieFrom(second)); rec.Code != http.StatusOK {
		t.Errorf("token from the second change: status = %d, want 200", rec.Code)
	}
}

// A change that conflicts commits nothing, so it must not log anyone out.
func TestChangePasswordConflictRevokesNothing(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)
	laptop := loggedInCookie(t, h, user)
	phone := loggedInCookie(t, h, user)

	rec := doChangePassword(t, h, laptop, changePasswordRequestAt(99))
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale change status = %d, want 409, body: %s", rec.Code, rec.Body.String())
	}
	if sessionCookieFrom(rec) != nil {
		t.Error("a refused change touched the session cookie")
	}
	for name, c := range map[string]*http.Cookie{"caller": laptop, "other device": phone} {
		if rec := doGetAccountCredentials(t, h, c); rec.Code != http.StatusOK {
			t.Errorf("%s after a refused change: status = %d, want 200", name, rec.Code)
		}
	}
}

// failingNthGetItemDB lets the first passFirst GetItem calls through and
// answers every later one with an error, so a test can break the read that
// follows a commit without breaking the session check that precedes it.
func failingNthGetItemDB(t *testing.T, passFirst int32) *db.Client {
	t.Helper()
	target, err := url.Parse(testEndpoint(t))
	if err != nil {
		t.Fatalf("parsing DYNAMODB_ENDPOINT: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var seen atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".GetItem") && seen.Add(1) > passFirst {
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			w.Header().Set("X-Amzn-Errortype", "ValidationException")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"com.amazon.coral.validate#ValidationException","message":"injected"}`))
			return
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

// The write has committed by the time the generation is read back, so a
// failed read must not turn into a 500 that tells the client its password did
// not change. The request still answers 200; the caller's cookie is cleared
// because the old token no longer verifies.
func TestChangePasswordStaysCommittedWhenTheReissueReadFails(t *testing.T) {
	good := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, good)
	cookie := loggedInCookie(t, good, user)

	// GetItem #1 is requireSession's generation check; #2 is the post-commit read.
	failing := New(config.FromEnv(), failingNthGetItemDB(t, 1))
	rec := doChangePassword(t, failing, cookie, changePasswordRequestAt(1))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the change committed), body: %s", rec.Code, rec.Body.String())
	}
	if c := sessionCookieFrom(rec); c == nil || c.MaxAge >= 0 {
		t.Errorf("session cookie after a failed reissue = %+v, want it cleared", c)
	}
	if rec := doGetAccountCredentials(t, good, cookie); rec.Code != http.StatusUnauthorized {
		t.Errorf("old token after the committed change: status = %d, want 401", rec.Code)
	}
	again := doChangePassword(t, good, loggedInCookie(t, good, user), changePasswordRequestAt(1))
	if again.Code != http.StatusConflict {
		t.Errorf("repeating the change at version 1: status = %d, want 409 (it committed once)", again.Code)
	}
}

func TestRecoveryResetEndsEverySession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)
	// The fixture has no login material, so mint the tokens a login would have.
	tokenFor := func() *http.Cookie {
		gen, err := h.db.GetSessionGeneration(context.Background(), fixture.userID)
		if err != nil {
			t.Fatalf("GetSessionGeneration: %v", err)
		}
		return &http.Cookie{Name: sessionCookieName, Value: h.sessions.Issue(fixture.userID, gen, h.cfg.SessionTTL)}
	}
	attacker := tokenFor()
	if rec := doGetAccountCredentials(t, h, attacker); rec.Code != http.StatusOK {
		t.Fatalf("session before recovery: status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	rec := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              fixture.recoveryCode,
		ExpectedCredentialVersion: 1,
		credentialRewrapFields:    validCredentialRewrapFields(),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("reset status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if sessionCookieFrom(rec) != nil {
		t.Error("recovery issued a session cookie; the user is meant to log in with the new password")
	}
	if rec := doGetAccountCredentials(t, h, attacker); rec.Code != http.StatusUnauthorized {
		t.Errorf("session from before recovery: status = %d, want 401", rec.Code)
	}
	if rec := doGetAccountCredentials(t, h, tokenFor()); rec.Code != http.StatusOK {
		t.Errorf("a login after recovery: status = %d, want 200", rec.Code)
	}
}
