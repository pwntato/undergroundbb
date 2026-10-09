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

// Leaving a private Rotating group re-keys it (#178): the leaver mints the next
// generation, signs a rotation start naming THEMSELVES, and hands the new key to
// other admins in the same transaction, since their own copy leaves with them.

// leaveRotation is a valid rotation half of a leave: the leaver signs the start
// naming themselves for generation gen, and the new key is "wrapped" to each
// holder (the server only checks shape).
func leaveRotation(t *testing.T, leaver registeredUser, gid string, gen int64, holders ...registeredUser) *leaveRotationRequest {
	t.Helper()
	sig, err := crypto.Sign(leaver.signPriv, crypto.ContextRotationStart, crypto.RotationStartPayload(gid, leaver.userID, leaver.userID, gen))
	if err != nil {
		t.Fatal(err)
	}
	req := &leaveRotationRequest{
		Generation:     gen,
		Link:           wrappedBlob{Nonce: b64(12), Ciphertext: b64(48)},
		StartSignature: base64.StdEncoding.EncodeToString(sig),
	}
	for _, h := range holders {
		req.Holders = append(req.Holders, leaveHolderRequest{
			UserID:     h.userID,
			WrappedKey: wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		})
	}
	return req
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

func TestLeaveRotatingGroupStartsRotationAndHandsKeyToAdmins(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	gid, owner, bob, carol, ownerCookie, _, carolCookie := rotatingGroupWith(t, h)
	dave := registerTestUser(t, h)
	addMember(t, gid, dave, "member")

	before := map[string]map[string]types.AttributeValue{
		owner.userID: getRow(t, "GROUP#"+gid, "MEMBER#"+owner.userID),
		bob.userID:   getRow(t, "GROUP#"+gid, "MEMBER#"+bob.userID),
	}
	body := &leaveGroupRequest{Rotation: leaveRotation(t, carol, gid, 1, owner, bob)}
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
	sig := body.Rotation.StartSignature
	if bytesAttrB64(marker, "StartSignature") != sig {
		t.Errorf("marker StartSignature = %q, want %q", bytesAttrB64(marker, "StartSignature"), sig)
	}

	// The durable chain link carries the same signed record, naming the leaver
	// as both remover and removed, so a verifier at a later generation finds it.
	link := getRow(t, "GROUP#"+gid, "GENKEY#000000")
	if link == nil {
		t.Fatal("no GENKEY#000000 link")
	}
	if strAttr(link, "RemoverUserID") != carol.userID || strAttr(link, "RemovedUserID") != carol.userID || bytesAttrB64(link, "StartSignature") != sig {
		t.Errorf("link record = %v", link)
	}
	chain := decodeKeychain(t, doKeychain(t, h, ownerCookie, gid, "from=0&to=0"))
	if len(chain.Links) != 1 || chain.Links[0].RemovedUserID != carol.userID || chain.Links[0].RemoverUserID != carol.userID {
		t.Errorf("keychain = %+v", chain.Links)
	}

	// Every named holder has the leaver's wrap waiting BESIDE their entry: the
	// entry itself is untouched, so nothing the leaver sent can replace the
	// key an admin already holds. A member nobody named has no pending key and
	// stays behind for the ordinary re-wrap batch.
	for _, u := range []registeredUser{owner, bob} {
		assertHolderPending(t, gid, u, before[u.userID])
	}
	dRow := getRow(t, "GROUP#"+gid, "MEMBER#"+dave.userID)
	if g := numAttr(dRow, "Generation"); g != "0" {
		t.Errorf("bystander generation = %s, want 0", g)
	}
	if _, ok := dRow["PendingWrappedKey"]; ok {
		t.Error("a member nobody named has a pending key")
	}
}

// assertHolderPending checks a holder's entry is exactly as it was (same
// generation 0, same wrapped key) with a pending key beside it.
func assertHolderPending(t *testing.T, gid string, u registeredUser, before map[string]types.AttributeValue) {
	t.Helper()
	row := getRow(t, "GROUP#"+gid, "MEMBER#"+u.userID)
	if g := numAttr(row, "Generation"); g != "0" {
		t.Errorf("holder %s generation = %s, want 0 (unchanged until they adopt)", u.userID, g)
	}
	if !reflect.DeepEqual(row["WrappedGroupKey"], before["WrappedGroupKey"]) {
		t.Errorf("holder %s WrappedGroupKey was overwritten by the leave", u.userID)
	}
	if _, ok := row["PendingWrappedKey"]; !ok {
		t.Errorf("holder %s has no pending key", u.userID)
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

	wrongSigner := leaveRotation(t, carol, gid, 1, owner)
	wrongSigner.StartSignature = leaveRotation(t, other, gid, 1, owner).StartSignature
	namesSomeoneElse := leaveRotation(t, carol, gid, 1, owner)
	sig, _ := crypto.Sign(carol.signPriv, crypto.ContextRotationStart, crypto.RotationStartPayload(gid, carol.userID, dave.userID, 1))
	namesSomeoneElse.StartSignature = base64.StdEncoding.EncodeToString(sig)
	wrongGeneration := leaveRotation(t, carol, gid, 2, owner)
	repeated := leaveRotation(t, carol, gid, 1, owner, owner)
	includesLeaver := leaveRotation(t, carol, gid, 1, owner, carol)
	tooMany := leaveRotation(t, carol, gid, 1, owner)
	for i := 0; i < 50; i++ {
		tooMany.Holders = append(tooMany.Holders, leaveHolderRequest{UserID: registerTestUser(t, h).userID, WrappedKey: tooMany.Holders[0].WrappedKey})
	}
	badKey := leaveRotation(t, carol, gid, 1, owner)
	badKey.Holders[0].WrappedKey.EphemeralPub = "!!!"

	cases := []struct {
		name   string
		rot    *leaveRotationRequest
		status int
		code   string
	}{
		{"signed by another key", wrongSigner, 400, "bad_signature"},
		{"signature names someone else as removed", namesSomeoneElse, 400, "bad_signature"},
		{"wrong generation", wrongGeneration, 400, "rotation_required"},
		{"no holders", leaveRotation(t, carol, gid, 1), 400, "bad_holders"},
		{"a holder named twice", repeated, 400, "bad_holders"},
		{"the leaver as their own holder", includesLeaver, 400, "bad_holders"},
		{"more than 50 holders", tooMany, 400, "bad_holders"},
		{"a holder wrap that is not a wrap", badKey, 400, "bad_holders"},
		{"a holder who is not an admin", leaveRotation(t, carol, gid, 1, dave), 409, "holder_changed"},
		{"a holder who is not a member", leaveRotation(t, carol, gid, 1, other), 409, "holder_changed"},
		{"one good holder and one who is not an admin", leaveRotation(t, carol, gid, 1, bob, dave), 409, "holder_changed"},
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
			if getRow(t, "GROUP#"+gid, "ROTATION") != nil || getRow(t, "GROUP#"+gid, "GENKEY#000000") != nil {
				t.Error("a refused leave left a marker or link behind")
			}
			// No holder moved either: the transaction is all or nothing.
			for _, u := range []registeredUser{owner, bob} {
				if g := numAttr(getRow(t, "GROUP#"+gid, "MEMBER#"+u.userID), "Generation"); g != "0" {
					t.Errorf("admin %s generation = %s after a refused leave", u.userID, g)
				}
			}
		})
	}
}

func TestLeaveRotatingGroupHolderBehindIsRefused(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	gid, owner, bob, carol, _, _, carolCookie := rotatingGroupWith(t, h)
	// bob's entry is already at another generation than the leaver's.
	setMemberGeneration(t, gid, bob.userID, 3)

	rec := doLeaveWith(t, h, carolCookie, gid, &leaveGroupRequest{Rotation: leaveRotation(t, carol, gid, 1, owner, bob)})
	if rec.Code != http.StatusConflict || errCode(t, rec) != "holder_changed" {
		t.Fatalf("%d %q %s", rec.Code, errCode(t, rec), rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+carol.userID) == nil {
		t.Error("a refused leave removed the member")
	}
}

func TestLeaveRotatingGroupWhileRotationRunsIsRefused(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	gid, owner, bob, carol, _, bobCookie, carolCookie := rotatingGroupWith(t, h)
	dave, daveCookie := loggedInUser(t, h)
	addMember(t, gid, dave, "member")

	// carol leaves first and starts the rotation (marker at generation 1).
	if rec := doLeaveWith(t, h, carolCookie, gid, &leaveGroupRequest{Rotation: leaveRotation(t, carol, gid, 1, owner, bob)}); rec.Code != http.StatusOK {
		t.Fatalf("first leave: %d %s", rec.Code, rec.Body.String())
	}
	// dave, still at generation 0, cannot leave until it finishes.
	rec := doLeaveWith(t, h, daveCookie, gid, &leaveGroupRequest{Rotation: leaveRotation(t, dave, gid, 1, owner, bob)})
	if rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_in_progress" {
		t.Fatalf("%d %q %s", rec.Code, errCode(t, rec), rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+dave.userID) == nil {
		t.Error("a refused leave removed the member")
	}
	_ = bobCookie
}

func TestLeaveOpenGroupRefusesARotation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenPrivateGroup(t, h, owner, ownerCookie)
	bob, bobCookie := loggedInUser(t, h)
	addMember(t, gid, bob, "member")

	rec := doLeaveWith(t, h, bobCookie, gid, &leaveGroupRequest{Rotation: leaveRotation(t, bob, gid, 1, owner)})
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
	gid, owner, bob, _, ownerCookie, _, _ := rotatingGroupWith(t, h)

	// The creator (an admin) leaves with a signed self-demotion AND a rotation;
	// the other admin is the holder.
	ref := backdatedRef(t, gid, owner)
	bobBefore := getRow(t, "GROUP#"+gid, "MEMBER#"+bob.userID)
	body := signedLeave(t, owner, gid, ref)
	body.Rotation = leaveRotation(t, owner, gid, 1, bob)
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
	if getRow(t, "GROUP#"+gid, "ROTATION") == nil || getRow(t, "GROUP#"+gid, "GENKEY#000000") == nil {
		t.Error("no marker or link")
	}
	assertHolderPending(t, gid, bob, bobBefore)
}

// The cap is the most holders one transaction can carry with the rest of a
// leave (DynamoDB allows 100 items); 50 admins must go through in one commit.
func TestLeaveRotatingGroupWithMaxHolders(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	carol, carolCookie := loggedInUser(t, h)
	addMember(t, gid, carol, "member")
	holders := []registeredUser{owner}
	for len(holders) < 50 {
		u := registerTestUser(t, h)
		addMember(t, gid, u, "admin")
		holders = append(holders, u)
	}

	rec := doLeaveWith(t, h, carolCookie, gid, &leaveGroupRequest{Rotation: leaveRotation(t, carol, gid, 1, holders...)})
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	for _, u := range holders {
		if _, ok := getRow(t, "GROUP#"+gid, "MEMBER#"+u.userID)["PendingWrappedKey"]; !ok {
			t.Fatalf("holder %s has no pending key", u.userID)
		}
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

	rec := doLeaveWith(t, h, bobCookie, gid, &leaveGroupRequest{Rotation: leaveRotation(t, bob, gid, 1, owner)})
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
