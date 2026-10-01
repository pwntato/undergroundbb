package handlers

import (
	"net/http"
	"testing"
	"time"

	"github.com/pwntato/undergroundbb/internal/config"
)

// Issue #57: the server's role gates, pinned per role. This is a first line,
// not a boundary (docs/DESIGN.md, "Roles and the chain of trust", the
// paragraph beginning "The server also enforces"): a client holding the
// group key can ignore it, and the signed grant chain is what actually
// decides who holds a role. These tests catch the cheap failures, a gate
// dropped or loosened by a refactor, for each role rather than only for
// "not a member".
func TestRoleGatesPerRole(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	amb, ambCookie := loggedInUser(t, h)
	mem, memCookie := loggedInUser(t, h)
	target := registerTestUser(t, h)
	addMember(t, gid, amb, "ambassador")
	addMember(t, gid, mem, "member")
	addMember(t, gid, target, "member")

	t.Run("create invite: admin and ambassador yes, member no", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			user   registeredUser
			cookie *http.Cookie
			want   int
		}{
			{"admin", owner, ownerCookie, http.StatusCreated},
			{"ambassador", amb, ambCookie, http.StatusCreated},
			{"member", mem, memCookie, http.StatusForbidden},
		} {
			req := signedCreateInviteRequest(t, tc.user, gid, time.Now().Add(24*time.Hour))
			rec := doJSON(t, h, http.MethodPost, "/api/groups/"+gid+"/invites", tc.cookie, req)
			if rec.Code != tc.want {
				t.Errorf("%s: status = %d, want %d, body: %s", tc.name, rec.Code, tc.want, rec.Body.String())
			}
		}
	})

	t.Run("edit group settings: admin only", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			cookie *http.Cookie
			want   int
		}{
			{"ambassador", ambCookie, http.StatusForbidden},
			{"member", memCookie, http.StatusForbidden},
		} {
			if rec := doGroupRequest(t, h, tc.cookie, http.MethodPut, gid, updateReq(0)); rec.Code != tc.want {
				t.Errorf("%s: status = %d, want %d, body: %s", tc.name, rec.Code, tc.want, rec.Body.String())
			}
		}
		// A rejected edit must not have bumped the version.
		if d := decodeDetail(t, doGroupRequest(t, h, ownerCookie, http.MethodGet, gid, nil)); d.Version != 0 {
			t.Errorf("rejected edits changed the group: %+v", d)
		}
		if rec := doGroupRequest(t, h, ownerCookie, http.MethodPut, gid, updateReq(0)); rec.Code != http.StatusOK {
			t.Errorf("admin: status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("change role: a plain member is rejected and writes nothing", func(t *testing.T) {
		memRef := "GRANT#" + mem.userID + "#2026-01-01#0000000000000000"
		req := signedRoleRequest(t, mem, gid, target.userID, "ambassador", memRef)
		if rec := doChangeRole(t, h, memCookie, gid, target.userID, req); rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403, body: %s", rec.Code, rec.Body.String())
		}
		if got := strAttr(getRow(t, "GROUP#"+gid, "MEMBER#"+target.userID), "Role"); got != "member" {
			t.Errorf("target role = %q after a rejected change", got)
		}
	})
}
