package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
)

func doDeleteAccount(t *testing.T, h *Handler, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/account", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func TestDeleteAccountRequiresSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	if rec := doDeleteAccount(t, h, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// The client leaves each group first; deletion itself never does it for them,
// because leaving is what signs a demotion and enforces the last-admin rule.
func TestDeleteAccountRefusesWhileInAGroupThenSucceedsAfterLeaving(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob, bobCookie := loggedInUser(t, h)
	addMember(t, gid, bob, "member")

	rec := doDeleteAccount(t, h, bobCookie)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "still_member" {
		t.Fatalf("in a group: status = %d code = %q, want 409 still_member (%s)", rec.Code, errCode(t, rec), rec.Body.String())
	}
	if rec := doChallenge(t, h, bob.username); rec.Code != http.StatusOK {
		t.Fatalf("a refused deletion must leave login working, challenge = %d", rec.Code)
	}

	if rec := doLeave(t, h, bobCookie, gid); rec.Code != http.StatusOK {
		t.Fatalf("leave = %d: %s", rec.Code, rec.Body.String())
	}
	rec = doDeleteAccount(t, h, bobCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body.String())
	}
	cleared := sessionCookieFrom(rec)
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Errorf("response must clear the session cookie, got %+v", cleared)
	}

	// Login is gone: the username resolves to nobody, and the account's own
	// keys remain readable only as a flagged tombstone.
	if rec := completeLogin(t, h, bob); rec.Code == http.StatusOK {
		t.Error("a deleted account can still log in")
	}
	_, viewerCookie := loggedInUser(t, h)
	got := doGetUser(t, h, viewerCookie, bob.userID)
	if got.Code != http.StatusOK {
		t.Fatalf("getUser = %d", got.Code)
	}
	var proj userProjection
	if err := json.Unmarshal(got.Body.Bytes(), &proj); err != nil {
		t.Fatal(err)
	}
	if !proj.Deleted || proj.Username != "" || proj.SigningPublicKey == "" {
		t.Errorf("tombstone projection = %+v, want deleted, no username, keys kept", proj)
	}
}

func TestDeleteAccountLastAdminMustPromoteFirst(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob, _ := loggedInUser(t, h)
	addMember(t, gid, bob, "member")

	if rec := doLeave(t, h, ownerCookie, gid); rec.Code != http.StatusConflict {
		t.Fatalf("last admin leave = %d, want 409", rec.Code)
	}
	rec := doDeleteAccount(t, h, ownerCookie)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "still_member" {
		t.Fatalf("last admin delete = %d %q, want 409 still_member", rec.Code, errCode(t, rec))
	}
}
