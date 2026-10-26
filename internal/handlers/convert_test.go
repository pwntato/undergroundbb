package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pwntato/undergroundbb/internal/config"
)

// #61: a Rotating group converts to Open once, in that direction only.

func doConvert(t *testing.T, h *Handler, cookie *http.Cookie, gid string) int {
	t.Helper()
	return doConvertRec(t, h, cookie, gid).Code
}

func doConvertRec(t *testing.T, h *Handler, cookie *http.Cookie, gid string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, h, http.MethodPost, "/api/groups/"+gid+"/convert-open", cookie, nil)
}

func modeOf(t *testing.T, gid string) string {
	t.Helper()
	return strAttr(getRow(t, "GROUP#"+gid, "META"), "RevocationMode")
}

func TestConvertOpenRefusedWhileARemovalRotationRuns(t *testing.T) {
	f := startRotation(t)
	rec := doConvertRec(t, f.h, f.ownerCookie, f.gid)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_in_progress" {
		t.Fatalf("convert mid-rotation: %d %s", rec.Code, rec.Body.String())
	}
	if m := modeOf(t, f.gid); m != "rotating" {
		t.Errorf("mode = %q after a refused conversion", m)
	}
	if getRow(t, "GROUP#"+f.gid, "ROTATION") == nil {
		t.Error("the refused conversion cleared the marker")
	}
}

func TestConvertOpenRefusedWhileAMemberIsBehind(t *testing.T) {
	f := startRotation(t)
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", rewrapReq(1, f.carol, f.dave)); rec.Code != http.StatusNoContent {
		t.Fatalf("rewrap: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "complete", completeRotationRequest{Generation: 1}); rec.Code != http.StatusNoContent {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
	// A member who joined behind the group's generation, after completion.
	setMemberGeneration(t, f.gid, f.dave.userID, 0)
	rec := doConvertRec(t, f.h, f.ownerCookie, f.gid)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "members_behind" {
		t.Fatalf("convert with a member behind: %d %s", rec.Code, rec.Body.String())
	}
	if m := modeOf(t, f.gid); m != "rotating" {
		t.Errorf("mode = %q", m)
	}
}

// The chain a converted group keeps is load-bearing and never extended: a
// group with several generations of history still serves every link, and its
// removals stop rotating.
func TestConvertOpenKeepsTheChainAndStopsRotating(t *testing.T) {
	f := startRotation(t)
	for _, u := range []registeredUser{f.carol, f.dave} {
		if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", rewrapReq(1, u)); rec.Code != http.StatusNoContent {
			t.Fatalf("rewrap: %d %s", rec.Code, rec.Body.String())
		}
	}
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "complete", completeRotationRequest{Generation: 1}); rec.Code != http.StatusNoContent {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
	// A second generation of history.
	if rec := doRemove(t, f.h, f.ownerCookie, f.gid, f.dave.userID, &removeMemberRequest{Rotation: rotationBody(t, f.owner, f.gid, f.dave.userID, 2)}); rec.Code != http.StatusNoContent {
		t.Fatalf("second removal: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", rewrapReq(2, f.carol)); rec.Code != http.StatusNoContent {
		t.Fatalf("rewrap 2: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "complete", completeRotationRequest{Generation: 2}); rec.Code != http.StatusNoContent {
		t.Fatalf("complete 2: %d %s", rec.Code, rec.Body.String())
	}
	before := decodeKeychain(t, doKeychain(t, f.h, f.ownerCookie, f.gid, "from=0&to=1"))
	if len(before.Links) != 2 {
		t.Fatalf("history before = %d links, want 2", len(before.Links))
	}
	versionBefore := numAttr(getRow(t, "GROUP#"+f.gid, "META"), "Version")

	if code := doConvert(t, f.h, f.ownerCookie, f.gid); code != http.StatusNoContent {
		t.Fatalf("convert: %d", code)
	}
	if m := modeOf(t, f.gid); m != "open" {
		t.Fatalf("mode = %q, want open", m)
	}
	if v := numAttr(getRow(t, "GROUP#"+f.gid, "META"), "Version"); v == versionBefore {
		t.Error("conversion did not bump the settings version")
	}
	after := decodeKeychain(t, doKeychain(t, f.h, f.ownerCookie, f.gid, "from=0&to=1"))
	if len(after.Links) != 2 {
		t.Errorf("history after = %d links, want 2 (the chain is frozen, not dropped)", len(after.Links))
	}
	d := decodeDetail(t, doGroupRequest(t, f.h, f.ownerCookie, http.MethodGet, f.gid, nil))
	if d.RevocationMode != "open" || !d.NoRotation {
		t.Errorf("detail = mode %q noRotation %v", d.RevocationMode, d.NoRotation)
	}

	// One way: a second conversion is refused and nothing converts back.
	rec := doConvertRec(t, f.h, f.ownerCookie, f.gid)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "already_open" {
		t.Errorf("second convert: %d %s", rec.Code, rec.Body.String())
	}

	// Removal in the converted group mints no generation and starts no marker.
	if rec := doRemove(t, f.h, f.ownerCookie, f.gid, f.carol.userID, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("removal after conversion: %d %s", rec.Code, rec.Body.String())
	}
	if getRow(t, "GROUP#"+f.gid, "ROTATION") != nil {
		t.Error("a removal in a converted group started a rotation")
	}
}

func TestConvertOpenRefusals(t *testing.T) {
	h := noCooldown(t)
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	member, memberCookie := loggedInUser(t, h)
	addMember(t, gid, member, "member")
	amb, ambCookie := loggedInUser(t, h)
	addMember(t, gid, amb, "ambassador")
	_, strangerCookie := loggedInUser(t, h)

	if code := doConvert(t, h, nil, gid); code != http.StatusUnauthorized {
		t.Errorf("no session: %d", code)
	}
	if code := doConvert(t, h, strangerCookie, gid); code != http.StatusNotFound {
		t.Errorf("stranger: %d", code)
	}
	if code := doConvert(t, h, memberCookie, gid); code != http.StatusForbidden {
		t.Errorf("member: %d", code)
	}
	if code := doConvert(t, h, ambCookie, gid); code != http.StatusForbidden {
		t.Errorf("ambassador: %d", code)
	}
	if m := modeOf(t, gid); m != "rotating" {
		t.Errorf("mode = %q after refusals", m)
	}
	open := createOpenGroup(t, h, owner, ownerCookie)
	if rec := doConvertRec(t, h, ownerCookie, open); rec.Code != http.StatusConflict || errCode(t, rec) != "already_open" {
		t.Errorf("an Open group: %d %s", rec.Code, rec.Body.String())
	}
}

// #60: the member cap follows the mode at write time, so converting a full
// Rotating group lifts it.
func TestConvertOpenLiftsTheMemberCap(t *testing.T) {
	cfg := config.FromEnv()
	cfg.MaxRotatingGroupMembers = 1
	h := New(cfg, testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	gid := createTestGroupWithMembers(t, h, creator, creatorCookie)

	req := signedCreateInviteRequest(t, creator, gid, time.Now().Add(24*time.Hour))
	if rec := doJSON(t, h, http.MethodPost, "/api/groups/"+gid+"/invites", creatorCookie, req); rec.Code != http.StatusConflict || errorCode(t, rec) != "group_full" {
		t.Fatalf("invite into a full Rotating group: %d %s", rec.Code, rec.Body.String())
	}
	if code := doConvert(t, h, creatorCookie, gid); code != http.StatusNoContent {
		t.Fatalf("convert: %d", code)
	}
	req = signedCreateInviteRequest(t, creator, gid, time.Now().Add(24*time.Hour))
	if rec := doJSON(t, h, http.MethodPost, "/api/groups/"+gid+"/invites", creatorCookie, req); rec.Code != http.StatusCreated {
		t.Fatalf("invite after conversion: %d %s", rec.Code, rec.Body.String())
	}
}
