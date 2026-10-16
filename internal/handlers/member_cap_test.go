package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pwntato/undergroundbb/internal/config"
)

// capHandler is a handler whose Rotating-group member cap is n.
func capHandler(t *testing.T, n int) *Handler {
	t.Helper()
	cfg := config.FromEnv()
	cfg.MaxRotatingGroupMembers = n
	return New(cfg, testDB(t))
}

func completeAs(t *testing.T, h *Handler, creator registeredUser, creatorCookie *http.Cookie, invitee registeredUser, groupID, inviteID string) *httptest.ResponseRecorder {
	t.Helper()
	adm := signedAdmission(t, h, creator, groupID, inviteID, invitee)
	rec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/complete", creatorCookie, completeBody(adm))
	return rec
}

// #60: a Rotating group at its cap refuses the join with a code the client can
// act on, leaves the invite pending (a departure may free a slot), and accepts
// it once the cap allows.
func TestCompleteInviteRefusedAtTheCapThenAcceptedWhenRaised(t *testing.T) {
	// The invite is made while there is room (cap 2), then the cap drops to 1:
	// the creator is member 1, so the group is full when the invite completes.
	roomy := capHandler(t, 2)
	creator, creatorCookie, invitee, groupID, inviteID := acceptedInviteFixture(t, roomy)
	full := capHandler(t, 1)

	res := completeAs(t, full, creator, creatorCookie, invitee, groupID, inviteID)
	if res.Code != http.StatusConflict || errorCode(t, res) != "group_full" {
		t.Fatalf("complete into a full group: status %d, want 409 group_full", res.Code)
	}
	pending := doJSON(t, full, http.MethodGet, "/api/invites/pending-completions", creatorCookie, nil)
	if pending.Code != http.StatusOK || !json.Valid(pending.Body.Bytes()) || !strings.Contains(pending.Body.String(), inviteID) {
		t.Errorf("the refused invite should stay pending; pending-completions = %d %s", pending.Code, pending.Body.String())
	}

	// Same database, same group, a larger cap: the retry succeeds.
	res = completeAs(t, roomy, creator, creatorCookie, invitee, groupID, inviteID)
	if res.Code != http.StatusOK {
		t.Fatalf("complete after raising the cap: status %d", res.Code)
	}
}

// #60: creating an invite for a full group is refused up front, so an invitee
// is not left accepting something that can never complete.
func TestCreateInviteRefusedWhenTheGroupIsFull(t *testing.T) {
	h := capHandler(t, 1)
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)

	req := signedCreateInviteRequest(t, creator, groupID, time.Now().Add(24*time.Hour))
	rec := doJSON(t, h, http.MethodPost, "/api/groups/"+groupID+"/invites", creatorCookie, req)
	if rec.Code != http.StatusConflict || errorCode(t, rec) != "group_full" {
		t.Fatalf("create invite for a full group: status %d body %s, want 409 group_full", rec.Code, rec.Body.String())
	}
}

// #60: an Open group has no cap, whatever the deployment's setting.
func TestOpenGroupsAreNotCapped(t *testing.T) {
	h := capHandler(t, 1)
	creator, creatorCookie := loggedInUser(t, h)
	req := signedCreateGroupRequest(t, creator)
	req.RevocationMode = "open"
	rec := doCreateGroup(t, h, creatorCookie, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create open group: status %d body %s", rec.Code, rec.Body.String())
	}
	var created createGroupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	inviteReq := signedCreateInviteRequest(t, creator, created.GroupID, time.Now().Add(24*time.Hour))
	if inv := doJSON(t, h, http.MethodPost, "/api/groups/"+created.GroupID+"/invites", creatorCookie, inviteReq); inv.Code != http.StatusCreated {
		t.Fatalf("invite to an open group at cap 1: status %d body %s", inv.Code, inv.Body.String())
	}
}

// #60: the group detail carries the cap, so the settings screen shows the
// deployment's real number instead of a hardcoded one.
func TestGroupDetailReportsTheMemberCap(t *testing.T) {
	h := capHandler(t, 37)
	creator, creatorCookie := loggedInUser(t, h)
	rotating := createTestGroupWithMembers(t, h, creator, creatorCookie)

	openReq := signedCreateGroupRequest(t, creator)
	openReq.RevocationMode = "open"
	openRec := doCreateGroup(t, h, creatorCookie, openReq)
	var open createGroupResponse
	if err := json.Unmarshal(openRec.Body.Bytes(), &open); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, id string
		want     int
	}{{"rotating", rotating, 37}, {"open", open.GroupID, 0}} {
		rec := doJSON(t, h, http.MethodGet, "/api/groups/"+tc.id, creatorCookie, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: detail status %d", tc.name, rec.Code)
		}
		var d struct {
			MemberCap int `json:"memberCap"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		if d.MemberCap != tc.want {
			t.Errorf("%s group memberCap = %d, want %d", tc.name, d.MemberCap, tc.want)
		}
	}
}
