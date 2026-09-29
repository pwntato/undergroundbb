package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
)

func doLeave(t *testing.T, h *Handler, cookie *http.Cookie, groupID string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/groups/"+groupID+"/leave", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Code
}

func TestLeaveGroupMemberLeaves(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob, bobCookie := loggedInUser(t, h)
	addMember(t, gid, bob, "member")

	rec := doLeave(t, h, bobCookie, gid)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var resp leaveGroupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.GroupDeleted {
		t.Errorf("resp = %+v err=%v, want groupDeleted false", resp, err)
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+bob.userID) != nil {
		t.Error("bob's membership still exists")
	}
	if rec := doListMembers(t, h, bobCookie, gid, ""); rec.Code != http.StatusNotFound {
		t.Errorf("bob still reads the roster after leaving: %d", rec.Code)
	}
	// A second leave is a plain non-member 404.
	if rec := doLeave(t, h, bobCookie, gid); rec.Code != http.StatusNotFound {
		t.Errorf("second leave = %d, want 404", rec.Code)
	}
}

func TestLeaveGroupLastAdminGets409ThenSucceedsAfterPromotion(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob := registerTestUser(t, h)
	addMember(t, gid, bob, "member")

	rec := doLeave(t, h, ownerCookie, gid)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "last_admin" {
		t.Fatalf("status = %d code = %q, want 409 last_admin (body: %s)", rec.Code, errCode(t, rec), rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+owner.userID) == nil {
		t.Fatal("blocked admin's membership was deleted")
	}

	// Promote bob through the real endpoint, then the leave goes through.
	req := signedRoleRequest(t, owner, gid, bob.userID, "admin", rootRef(t, gid, owner))
	if rec := doChangeRole(t, h, ownerCookie, gid, bob.userID, req); rec.Code != http.StatusOK {
		t.Fatalf("promote: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doLeave(t, h, ownerCookie, gid); rec.Code != http.StatusOK {
		t.Fatalf("leave after promotion: %d %s", rec.Code, rec.Body.String())
	}
}

func TestLeaveGroupOnlyMemberDeletesGroup(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	root := rootRef(t, gid, owner)

	rec := doLeave(t, h, ownerCookie, gid)
	var resp leaveGroupResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || !resp.GroupDeleted {
		t.Fatalf("status = %d body: %s, want 200 groupDeleted true", rec.Code, rec.Body.String())
	}
	for _, sk := range []string{"META", "MEMBER#" + owner.userID, root} {
		if getRow(t, "GROUP#"+gid, sk) != nil {
			t.Errorf("row %s survived group deletion", sk)
		}
	}
}

func TestLeaveGroupAuthAndNotFound(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	_, strangerCookie := loggedInUser(t, h)

	if rec := doLeave(t, h, nil, gid); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", rec.Code)
	}
	a := doLeave(t, h, strangerCookie, gid)
	b := doLeave(t, h, strangerCookie, "3f0c7a52-1111-4222-8333-444455556666")
	c := doLeave(t, h, strangerCookie, "not-a-uuid")
	if a.Code != 404 || b.Code != 404 || c.Code != 404 {
		t.Fatalf("statuses = %d %d %d, want 404 all", a.Code, b.Code, c.Code)
	}
	if a.Body.String() != b.Body.String() || a.Body.String() != c.Body.String() {
		t.Error("404 bodies differ")
	}
	if getRow(t, "GROUP#"+gid, "META") == nil {
		t.Error("a stranger's leave damaged the group")
	}
}
