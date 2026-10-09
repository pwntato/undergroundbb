package handlers

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
)

// An admin takes over the bare marker a leaver left (#178): the leaver never
// mints the key, so a hostile one never holds it.

type leftFixture struct {
	h                       *Handler
	gid                     string
	owner, bob, carol, dave registeredUser
	ownerCookie, bobCookie  *http.Cookie
	daveCookie              *http.Cookie
}

// leftRotating: carol (a plain member) has left, owner and bob are admins.
func leftRotating(t *testing.T) leftFixture {
	t.Helper()
	h := New(config.FromEnv(), testDB(t))
	gid, owner, bob, carol, ownerCookie, bobCookie, carolCookie := rotatingGroupWith(t, h)
	dave, daveCookie := loggedInUser(t, h)
	addMember(t, gid, dave, "member")
	body := &leaveGroupRequest{Rotation: leaveRotation(t, carol, gid, 1)}
	if rec := doLeaveWith(t, h, carolCookie, gid, body); rec.Code != http.StatusOK {
		t.Fatalf("leave: %d %s", rec.Code, rec.Body.String())
	}
	return leftFixture{h, gid, owner, bob, carol, dave, ownerCookie, bobCookie, daveCookie}
}

func takeOverBody(t *testing.T, f leftFixture, admin registeredUser, gen int64) takeOverRotationRequest {
	t.Helper()
	sig, err := crypto.Sign(admin.signPriv, crypto.ContextRotationStart, crypto.RotationStartPayload(f.gid, admin.userID, f.carol.userID, gen))
	if err != nil {
		t.Fatal(err)
	}
	return takeOverRotationRequest{
		Generation:     gen,
		Link:           wrappedBlob{Nonce: b64(12), Ciphertext: b64(48)},
		WrappedKey:     wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		StartSignature: base64.StdEncoding.EncodeToString(sig),
	}
}

func TestTakeOverEndpointMintsTheAdminsRotation(t *testing.T) {
	f := leftRotating(t)
	ok := takeOverBody(t, f, f.owner, 1)

	// Refusals first; none of them may change anything.
	bad := ok
	bad.StartSignature = takeOverBody(t, f, f.bob, 1).StartSignature // signed by someone else
	wrongGen := takeOverBody(t, f, f.owner, 2)                       // signed correctly FOR 2, so only the generation check refuses it
	for name, tc := range map[string]struct {
		cookie *http.Cookie
		body   takeOverRotationRequest
		status int
		code   string
	}{
		"unauthenticated": {nil, ok, http.StatusUnauthorized, ""},
		"member":          {f.daveCookie, ok, http.StatusForbidden, ""},
		"bad signature":   {f.ownerCookie, bad, http.StatusBadRequest, "bad_signature"},
		"wrong gen":       {f.ownerCookie, wrongGen, http.StatusBadRequest, ""},
	} {
		rec := doRotationCall(t, f.h, tc.cookie, http.MethodPost, f.gid, "takeover", tc.body)
		if rec.Code != tc.status || (tc.code != "" && errCode(t, rec) != tc.code) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if m := getRow(t, "GROUP#"+f.gid, "ROTATION"); strAttr(m, "StartedBy") != f.carol.userID {
		t.Fatal("a refused takeover replaced the marker")
	}
	if getRow(t, "GROUP#"+f.gid, "GENKEY#000000") != nil {
		t.Fatal("a refused takeover wrote a link")
	}

	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "takeover", ok); rec.Code != http.StatusNoContent {
		t.Fatalf("takeover: %d %s", rec.Code, rec.Body.String())
	}
	m := getRow(t, "GROUP#"+f.gid, "ROTATION")
	if strAttr(m, "StartedBy") != f.owner.userID || strAttr(m, "RemovedUserID") != f.carol.userID || bytesAttrB64(m, "StartSignature") != ok.StartSignature {
		t.Fatalf("marker = %v", m)
	}
	link := getRow(t, "GROUP#"+f.gid, "GENKEY#000000")
	if strAttr(link, "RemoverUserID") != f.owner.userID || strAttr(link, "RemovedUserID") != f.carol.userID {
		t.Fatalf("link = %v", link)
	}
	if g := numAttr(getRow(t, "GROUP#"+f.gid, "MEMBER#"+f.owner.userID), "Generation"); g != "1" {
		t.Fatalf("caller generation = %s, want 1", g)
	}
	if g := numAttr(getRow(t, "GROUP#"+f.gid, "MEMBER#"+f.bob.userID), "Generation"); g != "0" {
		t.Fatalf("other admin generation = %s, want 0 (re-wrapped later)", g)
	}
	// It is an admin's marker now: nobody else can take it over.
	again := takeOverBody(t, f, f.bob, 1)
	if rec := doRotationCall(t, f.h, f.bobCookie, http.MethodPost, f.gid, "takeover", again); rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_not_active" {
		t.Errorf("second takeover: %d %s", rec.Code, rec.Body.String())
	}
}
