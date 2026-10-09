package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
)

// A leaver's key material is untrusted (#178 review): it lands beside each
// holder's entry as pending, is adopted only when the holder asks, and an admin
// can replace a rotation whose key no one could verify.

type leftFixture struct {
	h                       *Handler
	gid                     string
	owner, bob, carol, dave registeredUser
	ownerCookie, bobCookie  *http.Cookie
	daveCookie              *http.Cookie
}

// leftWithHolders: owner and bob (admins) are the holders when carol leaves.
func leftWithHolders(t *testing.T) leftFixture {
	t.Helper()
	h := New(config.FromEnv(), testDB(t))
	gid, owner, bob, carol, ownerCookie, bobCookie, carolCookie := rotatingGroupWith(t, h)
	dave, daveCookie := loggedInUser(t, h)
	addMember(t, gid, dave, "member")
	body := &leaveGroupRequest{Rotation: leaveRotation(t, carol, gid, 1, owner, bob)}
	if rec := doLeaveWith(t, h, carolCookie, gid, body); rec.Code != http.StatusOK {
		t.Fatalf("leave: %d %s", rec.Code, rec.Body.String())
	}
	return leftFixture{h, gid, owner, bob, carol, dave, ownerCookie, bobCookie, daveCookie}
}

type detailView struct {
	Generation             int64          `json:"generation"`
	Rotation               *rotationState `json:"rotation"`
	PendingWrappedGroupKey *wrappedKey    `json:"pendingWrappedGroupKey"`
}

func getDetail(t *testing.T, f leftFixture, cookie *http.Cookie) detailView {
	t.Helper()
	rec := doGroupRequest(t, f.h, cookie, http.MethodGet, f.gid, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get group: %d %s", rec.Code, rec.Body.String())
	}
	var d detailView
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func restartBody(t *testing.T, f leftFixture, admin registeredUser, gen int64) restartRotationRequest {
	t.Helper()
	sig, err := crypto.Sign(admin.signPriv, crypto.ContextRotationStart, crypto.RotationStartPayload(f.gid, admin.userID, f.carol.userID, gen))
	if err != nil {
		t.Fatal(err)
	}
	return restartRotationRequest{
		Generation:     gen,
		Link:           wrappedBlob{Nonce: b64(12), Ciphertext: b64(48)},
		WrappedKey:     wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		StartSignature: base64.StdEncoding.EncodeToString(sig),
	}
}

func TestDetailServesTheHolderTheirPendingKeyOnly(t *testing.T) {
	f := leftWithHolders(t)
	d := getDetail(t, f, f.ownerCookie)
	if d.PendingWrappedGroupKey == nil || d.Generation != 0 || d.Rotation == nil || d.Rotation.Generation != 1 {
		t.Fatalf("holder's view: %+v", d)
	}
	if d := getDetail(t, f, f.daveCookie); d.PendingWrappedGroupKey != nil {
		t.Fatal("a member nobody named was served a pending key")
	}
}

func TestAdoptEndpoint(t *testing.T) {
	f := leftWithHolders(t)
	eve := registerTestUser(t, f.h)
	addMember(t, f.gid, eve, "admin") // an admin nobody named
	eveCookie := loginCookie(t, f.h, eve)
	body := completeRotationRequest{Generation: 1}

	if rec := doRotationCall(t, f.h, nil, http.MethodPost, f.gid, "adopt", body); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: %d", rec.Code)
	}
	if rec := doRotationCall(t, f.h, f.daveCookie, http.MethodPost, f.gid, "adopt", body); rec.Code != http.StatusForbidden {
		t.Errorf("member: %d", rec.Code)
	}
	if rec := doRotationCall(t, f.h, eveCookie, http.MethodPost, f.gid, "adopt", body); rec.Code != http.StatusConflict || errCode(t, rec) != "no_pending_key" {
		t.Errorf("non-holder admin: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "adopt", completeRotationRequest{Generation: 2}); rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_not_active" {
		t.Errorf("wrong generation: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "adopt", body); rec.Code != http.StatusNoContent {
		t.Fatalf("holder: %d %s", rec.Code, rec.Body.String())
	}
	d := getDetail(t, f, f.ownerCookie)
	if d.Generation != 1 || d.PendingWrappedGroupKey != nil || d.Rotation == nil || d.Rotation.Adopted != 1 {
		t.Fatalf("after adopt: %+v", d)
	}
	// The other holder is untouched and still sees theirs.
	if d := getDetail(t, f, f.bobCookie); d.Generation != 0 || d.PendingWrappedGroupKey == nil {
		t.Fatalf("other holder: %+v", d)
	}
}

func TestRestartEndpointReplacesTheLeaversRotation(t *testing.T) {
	f := leftWithHolders(t)
	ok := restartBody(t, f, f.owner, 1)

	// Refusals first; none of them may change anything.
	bad := ok
	bad.StartSignature = restartBody(t, f, f.bob, 1).StartSignature // signed by someone else
	wrongGen := restartBody(t, f, f.owner, 2)
	for name, tc := range map[string]struct {
		cookie *http.Cookie
		body   restartRotationRequest
		status int
		code   string // "-" means the response carries no code
	}{
		"unauthenticated": {nil, ok, http.StatusUnauthorized, ""},
		"member":          {f.daveCookie, ok, http.StatusForbidden, ""},
		"bad signature":   {f.ownerCookie, bad, http.StatusBadRequest, "bad_signature"},
		// Signed correctly FOR generation 2, so only the generation check can refuse it.
		"wrong gen": {f.ownerCookie, wrongGen, http.StatusBadRequest, "-"},
	} {
		rec := doRotationCall(t, f.h, tc.cookie, http.MethodPost, f.gid, "restart", tc.body)
		want := tc.code
		if want == "-" {
			want = ""
		}
		if rec.Code != tc.status || (tc.code != "" && errCode(t, rec) != want) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if m := getRow(t, "GROUP#"+f.gid, "ROTATION"); strAttr(m, "StartedBy") != f.carol.userID {
		t.Fatal("a refused restart replaced the marker")
	}

	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "restart", ok); rec.Code != http.StatusNoContent {
		t.Fatalf("restart: %d %s", rec.Code, rec.Body.String())
	}
	m := getRow(t, "GROUP#"+f.gid, "ROTATION")
	if strAttr(m, "StartedBy") != f.owner.userID || strAttr(m, "RemovedUserID") != f.carol.userID || bytesAttrB64(m, "StartSignature") != ok.StartSignature {
		t.Fatalf("marker = %v", m)
	}
	link := getRow(t, "GROUP#"+f.gid, "GENKEY#000000")
	if strAttr(link, "RemoverUserID") != f.owner.userID || strAttr(link, "RemovedUserID") != f.carol.userID {
		t.Fatalf("link = %v", link)
	}
	if d := getDetail(t, f, f.ownerCookie); d.Generation != 1 || d.PendingWrappedGroupKey != nil {
		t.Fatalf("caller after restart: %+v", d)
	}
	// The marker is an admin's now: the other holder's leftover key is not
	// served as adoptable, and cannot be adopted.
	if d := getDetail(t, f, f.bobCookie); d.PendingWrappedGroupKey != nil {
		t.Fatalf("a replaced rotation's pending key is still served: %+v", d)
	}
	if rec := doRotationCall(t, f.h, f.bobCookie, http.MethodPost, f.gid, "adopt", completeRotationRequest{Generation: 1}); rec.Code != http.StatusConflict {
		t.Errorf("adopt after restart: %d %s", rec.Code, rec.Body.String())
	}
	// ...and an admin's rotation cannot be restarted again.
	again := restartBody(t, f, f.bob, 1)
	if rec := doRotationCall(t, f.h, f.bobCookie, http.MethodPost, f.gid, "restart", again); rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_not_active" {
		t.Errorf("second restart: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRestartEndpointRefusedOnceAnAdminAdopted(t *testing.T) {
	f := leftWithHolders(t)
	if rec := doRotationCall(t, f.h, f.bobCookie, http.MethodPost, f.gid, "adopt", completeRotationRequest{Generation: 1}); rec.Code != http.StatusNoContent {
		t.Fatalf("adopt: %d %s", rec.Code, rec.Body.String())
	}
	rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "restart", restartBody(t, f, f.owner, 1))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_adopted" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if m := getRow(t, "GROUP#"+f.gid, "ROTATION"); strAttr(m, "StartedBy") != f.carol.userID {
		t.Fatal("restart replaced a rotation an admin had adopted")
	}
}
