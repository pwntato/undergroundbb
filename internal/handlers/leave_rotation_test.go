package handlers

import (
	"encoding/base64"
	"net/http"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
)

// Leaving a private Rotating group re-keys it (#178): the leaver signs a
// rotation start naming THEMSELVES and nothing else. They mint no key and hand
// no one anything, so a hostile leaver never holds the next generation's key; an
// admin takes the marker over and mints it.

// leaveRotation is a valid rotation half of a leave: the leaver signs the start
// naming themselves for generation gen.
func leaveRotation(t *testing.T, leaver registeredUser, gid string, gen int64) *leaveRotationRequest {
	t.Helper()
	sig, err := crypto.Sign(leaver.signPriv, crypto.ContextRotationStart, crypto.RotationStartPayload(gid, leaver.userID, leaver.userID, gen))
	if err != nil {
		t.Fatal(err)
	}
	return &leaveRotationRequest{Generation: gen, StartSignature: base64.StdEncoding.EncodeToString(sig)}
}

// rotatingGroupWith returns a Rotating group with its creator (admin), a second
// admin, and a plain member, all at generation 0.
func rotatingGroupWith(t *testing.T, h *Handler) (gid string, owner, bob, carol registeredUser, ownerCookie, bobCookie, carolCookie *http.Cookie) {
	t.Helper()
	owner, ownerCookie = loggedInUser(t, h)
	gid = createPrivateGroup(t, h, owner, ownerCookie) // rotating by default
	bob, bobCookie = loggedInUser(t, h)
	carol, carolCookie = loggedInUser(t, h)
	addMember(t, gid, bob, "admin")
	addMember(t, gid, carol, "member")
	return
}

func TestLeaveRotatingGroupWritesOnlyTheSignedMarker(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	gid, owner, bob, carol, _, _, carolCookie := rotatingGroupWith(t, h)
	dave := registerTestUser(t, h)
	addMember(t, gid, dave, "member")

	before := map[string]map[string]types.AttributeValue{}
	for _, u := range []registeredUser{owner, bob, dave} {
		before[u.userID] = getRow(t, "GROUP#"+gid, "MEMBER#"+u.userID)
	}
	body := &leaveGroupRequest{Rotation: leaveRotation(t, carol, gid, 1)}
	if rec := doLeaveWith(t, h, carolCookie, gid, body); rec.Code != http.StatusOK {
		t.Fatalf("leave: %d %s", rec.Code, rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+carol.userID) != nil {
		t.Error("leaver still a member")
	}
	if getRow(t, "GROUP#"+gid, "ADMISSION#"+carol.userID) != nil {
		t.Error("leaver's admission row survived")
	}

	marker := getRow(t, "GROUP#"+gid, "ROTATION")
	if marker == nil || numAttr(marker, "Generation") != "1" || strAttr(marker, "StartedBy") != carol.userID || strAttr(marker, "RemovedUserID") != carol.userID {
		t.Fatalf("marker = %v", marker)
	}
	if got := bytesAttrB64(marker, "StartSignature"); got != body.Rotation.StartSignature {
		t.Errorf("marker StartSignature = %q, want %q", got, body.Rotation.StartSignature)
	}

	// No chain link: only an admin mints one, so nothing the leaver sent can sit
	// where the next key's proof of origin belongs.
	if getRow(t, "GROUP#"+gid, "GENKEY#000000") != nil {
		t.Error("the leave wrote a chain link")
	}
	// Nobody's entry changed at all, byte for byte.
	for _, u := range []registeredUser{owner, bob, dave} {
		if after := getRow(t, "GROUP#"+gid, "MEMBER#"+u.userID); !reflect.DeepEqual(after, before[u.userID]) {
			t.Errorf("member %s changed by the leave:\nbefore %v\nafter  %v", u.userID, before[u.userID], after)
		}
	}
}

func TestLeaveRotatingGroupRequiresRotation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	gid, _, _, carol, _, _, carolCookie := rotatingGroupWith(t, h)

	rec := doLeave(t, h, carolCookie, gid)
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != "rotation_required" {
		t.Fatalf("%d %q %s", rec.Code, errCode(t, rec), rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+carol.userID) == nil {
		t.Error("a refused leave removed the member")
	}
	if getRow(t, "GROUP#"+gid, "ROTATION") != nil {
		t.Error("a refused leave left a marker")
	}
}

func TestLeaveRotatingGroupRejectsBadRotation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	gid, owner, bob, carol, _, _, carolCookie := rotatingGroupWith(t, h)
	dave := registerTestUser(t, h)
	addMember(t, gid, dave, "member")
	other := registerTestUser(t, h)

	wrongSigner := leaveRotation(t, carol, gid, 1)
	wrongSigner.StartSignature = leaveRotation(t, other, gid, 1).StartSignature
	namesSomeoneElse := leaveRotation(t, carol, gid, 1)
	sig, _ := crypto.Sign(carol.signPriv, crypto.ContextRotationStart, crypto.RotationStartPayload(gid, carol.userID, dave.userID, 1))
	namesSomeoneElse.StartSignature = base64.StdEncoding.EncodeToString(sig)
	notASignature := leaveRotation(t, carol, gid, 1)
	notASignature.StartSignature = "!!!"

	cases := []struct {
		name   string
		rot    *leaveRotationRequest
		status int
		code   string
	}{
		{"signed by another key", wrongSigner, 400, "bad_signature"},
		{"signature names someone else as removed", namesSomeoneElse, 400, "bad_signature"},
		{"signature that is not a signature", notASignature, 400, "bad_signature"},
		{"wrong generation", leaveRotation(t, carol, gid, 2), 400, "rotation_required"},
		{"generation behind", leaveRotation(t, carol, gid, 0), 400, "rotation_required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doLeaveWith(t, h, carolCookie, gid, &leaveGroupRequest{Rotation: tc.rot})
			if rec.Code != tc.status || errCode(t, rec) != tc.code {
				t.Fatalf("%d %q, want %d %q: %s", rec.Code, errCode(t, rec), tc.status, tc.code, rec.Body.String())
			}
			if getRow(t, "GROUP#"+gid, "MEMBER#"+carol.userID) == nil {
				t.Error("a refused leave removed the member")
			}
			if getRow(t, "GROUP#"+gid, "ROTATION") != nil {
				t.Error("a refused leave left a marker behind")
			}
			for _, u := range []registeredUser{owner, bob} {
				if g := numAttr(getRow(t, "GROUP#"+gid, "MEMBER#"+u.userID), "Generation"); g != "0" {
					t.Errorf("admin %s generation = %s after a refused leave", u.userID, g)
				}
			}
		})
	}
}

func TestLeaveRotatingGroupWhileRotationRunsIsRefused(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	gid, _, _, carol, _, _, carolCookie := rotatingGroupWith(t, h)
	dave, daveCookie := loggedInUser(t, h)
	addMember(t, gid, dave, "member")

	// carol leaves first and starts the rotation (marker at generation 1).
	if rec := doLeaveWith(t, h, carolCookie, gid, &leaveGroupRequest{Rotation: leaveRotation(t, carol, gid, 1)}); rec.Code != http.StatusOK {
		t.Fatalf("first leave: %d %s", rec.Code, rec.Body.String())
	}
	// dave, still at generation 0, cannot leave until it finishes.
	rec := doLeaveWith(t, h, daveCookie, gid, &leaveGroupRequest{Rotation: leaveRotation(t, dave, gid, 1)})
	if rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_in_progress" {
		t.Fatalf("%d %q %s", rec.Code, errCode(t, rec), rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+dave.userID) == nil {
		t.Error("a refused leave removed the member")
	}
}

func TestLeaveOpenGroupRefusesARotation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenPrivateGroup(t, h, owner, ownerCookie)
	bob, bobCookie := loggedInUser(t, h)
	addMember(t, gid, bob, "member")

	rec := doLeaveWith(t, h, bobCookie, gid, &leaveGroupRequest{Rotation: leaveRotation(t, bob, gid, 1)})
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != "rotation_not_applicable" {
		t.Fatalf("%d %q %s", rec.Code, errCode(t, rec), rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+bob.userID) == nil {
		t.Error("a refused leave removed the member")
	}
}

func TestLeaveRotatingGroupAsOnlyMemberNeedsNoRotation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)

	rec := doLeave(t, h, ownerCookie, gid)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "META") != nil {
		t.Error("the group survived its last member leaving")
	}
}

func TestLeaveRotatingGroupAsAdminSendsDemotionAndRotation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	gid, owner, _, _, ownerCookie, _, _ := rotatingGroupWith(t, h)

	// The creator (an admin) leaves with a signed self-demotion AND a rotation
	// start; the other admin is the successor and takes the marker over.
	ref := backdatedRef(t, gid, owner)
	body := signedLeave(t, owner, gid, ref)
	body.Rotation = leaveRotation(t, owner, gid, 1)
	rec := doLeaveWith(t, h, ownerCookie, gid, &body)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+owner.userID) != nil {
		t.Error("leaver still a member")
	}
	if getRow(t, "GROUP#"+gid, body.GrantSortKey) == nil {
		t.Error("demotion grant was not written")
	}
	if getRow(t, "GROUP#"+gid, "ROTATION") == nil {
		t.Error("no marker")
	}
}

// A public group holds no group key (its text is plaintext), so there is
// nothing to re-key even when its revocation mode says Rotating: leaving must
// not demand a rotation nobody could build, and must not accept one.
func TestLeavePublicRotatingGroupNeedsNoRotation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	// createPublicGroup makes an Open one; a public group may be set to Rotating.
	req := signedCreateGroupRequest(t, owner)
	req.Visibility = "public"
	req.NameCiphertext, req.DescriptionCiphertext = wrappedBlob{}, wrappedBlob{}
	req.NamePlaintext, req.DescriptionPlaintext = "Book Club", "We read books"
	req.RevocationMode = "rotating"
	if rec := doCreateGroup(t, h, ownerCookie, req); rec.Code != http.StatusCreated {
		t.Fatalf("create public rotating group: %d %s", rec.Code, rec.Body.String())
	}
	gid := req.GroupID
	bob, bobCookie := loggedInUser(t, h)
	carol, carolCookie := loggedInUser(t, h)
	addMember(t, gid, bob, "member")
	addMember(t, gid, carol, "member")

	rec := doLeaveWith(t, h, bobCookie, gid, &leaveGroupRequest{Rotation: leaveRotation(t, bob, gid, 1)})
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != "rotation_not_applicable" {
		t.Fatalf("with a rotation: %d %q %s", rec.Code, errCode(t, rec), rec.Body.String())
	}
	if rec := doLeave(t, h, carolCookie, gid); rec.Code != http.StatusOK {
		t.Fatalf("without one: %d %s", rec.Code, rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "ROTATION") != nil {
		t.Error("a public group's leave started a rotation")
	}
}
