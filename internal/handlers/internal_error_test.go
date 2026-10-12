package handlers

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
)

func TestWriteInternalErrorLogsCauseButNotToClient(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/groups", nil)
	WriteInternalError(w, r, errors.New("AccessDeniedException: ConditionCheckItem"), "could not create group")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "could not create group") {
		t.Errorf("body = %q, want the generic message", body)
	}
	if strings.Contains(body, "AccessDenied") {
		t.Errorf("body leaks the underlying error: %q", body)
	}
	logged := buf.String()
	for _, want := range []string{"POST", "/api/groups", "could not create group", "AccessDeniedException: ConditionCheckItem"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log %q is missing %q", logged, want)
		}
	}
}

// captureLog redirects the standard logger for the rest of the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })
	return &buf
}

// The three helpers below return a 500 without a *http.Request in scope, so
// they log directly. Each case makes the caller's PROFILE read fail.
func TestMemberHelperInternalErrorsAreLogged(t *testing.T) {
	t.Run("remove demotion", func(t *testing.T) {
		h := New(config.FromEnv(), testDB(t))
		owner, ownerCookie := loggedInUser(t, h)
		gid := createOpenGroup(t, h, owner, ownerCookie)
		bob := registerTestUser(t, h)
		addMember(t, gid, bob, "admin")
		req := removalGrant(t, owner, gid, bob.userID, backdatedRef(t, gid, owner))
		deleteRow(t, "USER#"+owner.userID, "PROFILE")
		buf := captureLog(t)
		rec := doRemove(t, h, ownerCookie, gid, bob.userID, &req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d %s, want 500", rec.Code, rec.Body.String())
		}
		if !strings.Contains(buf.String(), "build remove demotion") || !strings.Contains(buf.String(), owner.userID) {
			t.Errorf("log = %q", buf.String())
		}
	})
	t.Run("rotation start", func(t *testing.T) {
		h := New(config.FromEnv(), testDB(t))
		owner, ownerCookie := loggedInUser(t, h)
		gid := createPrivateGroup(t, h, owner, ownerCookie)
		bob := registerTestUser(t, h)
		addMember(t, gid, bob, "member")
		body := &removeMemberRequest{Rotation: rotationBody(t, owner, gid, bob.userID, 1)}
		deleteRow(t, "USER#"+owner.userID, "PROFILE")
		buf := captureLog(t)
		rec := doRemove(t, h, ownerCookie, gid, bob.userID, body)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d %s, want 500", rec.Code, rec.Body.String())
		}
		if !strings.Contains(buf.String(), "verify rotation start") || !strings.Contains(buf.String(), owner.userID) {
			t.Errorf("log = %q", buf.String())
		}
	})
	t.Run("leave demotion", func(t *testing.T) {
		h, gid, owner, _, ownerCookie, _ := setupTwoAdmins(t)
		leave := signedLeave(t, owner, gid, backdatedRef(t, gid, owner))
		deleteRow(t, "USER#"+owner.userID, "PROFILE")
		buf := captureLog(t)
		rec := doLeaveWith(t, h, ownerCookie, gid, &leave)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d %s, want 500", rec.Code, rec.Body.String())
		}
		if !strings.Contains(buf.String(), "build leave demotion") || !strings.Contains(buf.String(), owner.userID) {
			t.Errorf("log = %q", buf.String())
		}
	})
}
