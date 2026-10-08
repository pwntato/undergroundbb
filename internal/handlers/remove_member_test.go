package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/models"
)

// createOpenGroup makes a private group whose revocation mode is Open: the
// only mode removal works in until rotation exists (#58, first slice).
func createOpenGroup(t *testing.T, h *Handler, user registeredUser, cookie *http.Cookie) string {
	t.Helper()
	req := signedCreateGroupRequest(t, user)
	req.RevocationMode = "open"
	if rec := doCreateGroup(t, h, cookie, req); rec.Code != http.StatusCreated {
		t.Fatalf("create open group: %d %s", rec.Code, rec.Body.String())
	}
	return req.GroupID
}

func doRemove(t *testing.T, h *Handler, cookie *http.Cookie, groupID, subjectID string, body *removeMemberRequest) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/groups/"+groupID+"/members/"+subjectID, &buf)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

// removalGrant is the remover's signed demotion of subject, as the client
// would send it.
func removalGrant(t *testing.T, remover registeredUser, gid, subjectID, ref string) removeMemberRequest {
	t.Helper()
	g := signedRoleRequest(t, remover, gid, subjectID, "member", ref)
	return removeMemberRequest{GrantSortKey: g.GrantSortKey, GrantorGrantRef: g.GrantorGrantRef, Signature: g.Signature}
}

// backdatedRef points the remover's current grant at an earlier UTC day, as
// it is for any admin promoted before today. The server only reads this
// pointer (never the row), and a group made today has a root grant dated
// today, which removal of an elevated member now refuses (see
// TestRemoveMemberRefusedWhenRemoversGrantIsDatedToday).
func backdatedRef(t *testing.T, gid string, owner registeredUser) string {
	t.Helper()
	ref := testGrantSortKey(t, owner.userID, time.Now().AddDate(0, 0, -3))
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + gid},
			"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + owner.userID},
		},
		UpdateExpression:          aws.String("SET GrantSortKey = :r"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":r": &types.AttributeValueMemberS{Value: ref}},
	}); err != nil {
		t.Fatal(err)
	}
	return ref
}

func memberRole(t *testing.T, gid, userID string) string {
	t.Helper()
	return strAttr(getRow(t, "GROUP#"+gid, "MEMBER#"+userID), "Role")
}

// putAdmissionRow stores a stand-in ADMISSION# row for a member (#178), so a
// test can see whether removing or leaving takes it away.
func putAdmissionRow(t *testing.T, groupID, userID string) {
	t.Helper()
	av, err := attributevalue.MarshalMap(models.Admission{
		Record:        models.Record{PK: "GROUP#" + groupID, SK: "ADMISSION#" + userID, Type: "Admission"},
		InviteeUserID: userID,
	})
	if err != nil {
		t.Fatalf("MarshalMap admission: %v", err)
	}
	if _, err := rawDDB(t).PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName: aws.String(testTableName()),
		Item:      av,
	}); err != nil {
		t.Fatalf("PutItem admission: %v", err)
	}
}

func TestRemoveMemberPlainMemberLeavesNoGrant(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	bob, bobCookie := loggedInUser(t, h)
	addMember(t, gid, bob, "member")
	carol, _ := loggedInUser(t, h)
	addMember(t, gid, carol, "member")
	putAdmissionRow(t, gid, bob.userID)
	putAdmissionRow(t, gid, carol.userID)

	if rec := doRemove(t, h, ownerCookie, gid, bob.userID, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+bob.userID) != nil {
		t.Error("bob's membership survived")
	}
	// The admission goes with the membership; another member's stays.
	if getRow(t, "GROUP#"+gid, "ADMISSION#"+bob.userID) != nil {
		t.Error("bob's admission record survived his removal")
	}
	if getRow(t, "GROUP#"+gid, "ADMISSION#"+carol.userID) == nil {
		t.Error("removing bob deleted carol's admission record")
	}
	// Removed means gone from the access gate, not just the roster.
	if rec := doGroupRequest(t, h, bobCookie, http.MethodGet, gid, nil); rec.Code != http.StatusNotFound {
		t.Errorf("removed member reading a private group: %d, want 404", rec.Code)
	}
}

func TestRemoveMemberElevatedAppendsRemoversDemotion(t *testing.T) {
	for _, role := range []string{"admin", "ambassador"} {
		t.Run(role, func(t *testing.T) {
			h := New(config.FromEnv(), testDB(t))
			owner, ownerCookie := loggedInUser(t, h)
			gid := createOpenGroup(t, h, owner, ownerCookie)
			bob := registerTestUser(t, h)
			addMember(t, gid, bob, role)
			ref := backdatedRef(t, gid, owner)

			req := removalGrant(t, owner, gid, bob.userID, ref)
			if rec := doRemove(t, h, ownerCookie, gid, bob.userID, &req); rec.Code != http.StatusNoContent {
				t.Fatalf("remove: %d %s", rec.Code, rec.Body.String())
			}
			if getRow(t, "GROUP#"+gid, "MEMBER#"+bob.userID) != nil {
				t.Error("membership survived")
			}
			row := getRow(t, "GROUP#"+gid, req.GrantSortKey)
			if row == nil {
				t.Fatal("demotion grant was not written")
			}
			// Signed by the REMOVER about the subject: no cooperation from the
			// removed admin, and a chain the verifier can follow from the remover.
			for k, want := range map[string]string{
				"SubjectUserID": bob.userID, "GrantorUserID": owner.userID,
				"GrantedRole": "member", "GrantorGrantRef": ref,
			} {
				if got := strAttr(row, k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
			// The remover is untouched and still an admin.
			if got := memberRole(t, gid, owner.userID); got != "admin" {
				t.Errorf("remover role = %q", got)
			}
		})
	}
}

func TestRemoveMemberRejections(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	amb, ambCookie := loggedInUser(t, h)
	mem, memCookie := loggedInUser(t, h)
	adm := registerTestUser(t, h)
	stranger, strangerCookie := loggedInUser(t, h)
	addMember(t, gid, amb, "ambassador")
	addMember(t, gid, mem, "member")
	addMember(t, gid, adm, "admin")
	ref := backdatedRef(t, gid, owner)

	good := func() removeMemberRequest { return removalGrant(t, owner, gid, adm.userID, ref) }
	wrongRole := good()
	sig, _ := crypto.Sign(owner.signPriv, crypto.ContextRoleGrant, crypto.RoleGrantPayload(gid, adm.userID, "admin", wrongRole.GrantSortKey, ref))
	wrongRole.Signature = base64.StdEncoding.EncodeToString(sig)
	forged := removalGrant(t, stranger, gid, adm.userID, ref)
	stale := removalGrant(t, owner, gid, adm.userID, "GRANT#"+owner.userID+"#2020-01-01#0000000000000000")
	otherSubject := removalGrant(t, owner, gid, mem.userID, ref)
	plainWithBody := removalGrant(t, owner, gid, mem.userID, ref)

	cases := []struct {
		name   string
		cookie *http.Cookie
		subj   string
		body   *removeMemberRequest
		want   int
		code   string
	}{
		{"ambassador is not admin", ambCookie, mem.userID, nil, 403, ""},
		{"member is not admin", memCookie, amb.userID, nil, 403, ""},
		{"non-member caller", strangerCookie, mem.userID, nil, 404, ""},
		{"self", ownerCookie, owner.userID, nil, 400, ""},
		{"subject not a member", ownerCookie, stranger.userID, nil, 404, ""},
		{"malformed subject id", ownerCookie, "nope", nil, 404, ""},
		{"admin subject, no demotion", ownerCookie, adm.userID, nil, 400, "demotion_required"},
		{"demotion signed for a different role", ownerCookie, adm.userID, &wrongRole, 400, "bad_signature"},
		{"demotion signed by another key", ownerCookie, adm.userID, &forged, 400, "bad_signature"},
		{"demotion with stale grantor ref", ownerCookie, adm.userID, &stale, 409, "grantor_ref_stale"},
		{"demotion sort key for another subject", ownerCookie, adm.userID, &otherSubject, 400, "bad_grant_sort_key"},
		{"plain member with a demotion attached", ownerCookie, mem.userID, &plainWithBody, 409, "conflict_retry"},
	}
	for _, tc := range cases {
		rec := doRemove(t, h, tc.cookie, gid, tc.subj, tc.body)
		if rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d, body: %s", tc.name, rec.Code, tc.want, rec.Body.String())
		} else if tc.code != "" && errCode(t, rec) != tc.code {
			t.Errorf("%s: code = %q, want %q", tc.name, errCode(t, rec), tc.code)
		}
	}
	// Nothing above may have removed anyone or written a grant.
	for _, id := range []string{amb.userID, mem.userID, adm.userID, owner.userID} {
		if getRow(t, "GROUP#"+gid, "MEMBER#"+id) == nil {
			t.Errorf("member %s was removed by a rejected request", id)
		}
	}
	if got := memberRole(t, gid, adm.userID); got != "admin" {
		t.Errorf("adm role = %q", got)
	}
}

// rotationBody is a valid Rotating-group removal's rotation half: remover
// signs the rotation start naming subjectID, as the browser does (#178).
func rotationBody(t *testing.T, remover registeredUser, gid, subjectID string, gen int64) *removeRotationRequest {
	t.Helper()
	sig, err := crypto.Sign(remover.signPriv, crypto.ContextRotationStart, crypto.RotationStartPayload(gid, remover.userID, subjectID, gen))
	if err != nil {
		t.Fatal(err)
	}
	return &removeRotationRequest{
		Generation:        gen,
		Link:              wrappedBlob{Nonce: b64(12), Ciphertext: b64(48)},
		RemoverWrappedKey: wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		StartSignature:    base64.StdEncoding.EncodeToString(sig),
	}
}

func bytesAttrB64(item map[string]types.AttributeValue, name string) string {
	if v, ok := item[name].(*types.AttributeValueMemberB); ok {
		return base64.StdEncoding.EncodeToString(v.Value)
	}
	return ""
}

func numAttr(item map[string]types.AttributeValue, name string) string {
	if v, ok := item[name].(*types.AttributeValueMemberN); ok {
		return v.Value
	}
	return ""
}

// Removal in a Rotating group starts the rotation in the same transaction as
// the delete: marker, chain link for the OLD generation, remover's own entry
// point at the new one. Everyone else stays at generation 0 until the client
// re-wraps them.
func TestRemoveMemberRotatingStartsRotation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie) // rotating by default
	bob, carol := registerTestUser(t, h), registerTestUser(t, h)
	addMember(t, gid, bob, "member")
	addMember(t, gid, carol, "member")

	body := &removeMemberRequest{Rotation: rotationBody(t, owner, gid, bob.userID, 1)}
	if rec := doRemove(t, h, ownerCookie, gid, bob.userID, body); rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+bob.userID) != nil {
		t.Error("subject still a member")
	}
	marker := getRow(t, "GROUP#"+gid, "ROTATION")
	if marker == nil || numAttr(marker, "Generation") != "1" || strAttr(marker, "StartedBy") != owner.userID || strAttr(marker, "StartedAt") == "" {
		t.Errorf("marker = %v", marker)
	}
	if _, ttl := marker["TTL"]; ttl {
		t.Error("marker carries a TTL")
	}
	// The marker records whom this rotation removed, under the remover's
	// signature, so a resuming admin need not trust the member list (#178).
	if strAttr(marker, "RemovedUserID") != bob.userID {
		t.Errorf("marker RemovedUserID = %q, want %q", strAttr(marker, "RemovedUserID"), bob.userID)
	}
	if want := body.Rotation.StartSignature; want == "" || bytesAttrB64(marker, "StartSignature") != want {
		t.Errorf("marker StartSignature = %q, want %q", bytesAttrB64(marker, "StartSignature"), want)
	}
	// ... and a member reading the group is served exactly that record.
	var served struct {
		Rotation *rotationState `json:"rotation"`
	}
	getRec := doGroupRequest(t, h, ownerCookie, http.MethodGet, gid, nil)
	if err := json.Unmarshal(getRec.Body.Bytes(), &served); err != nil || served.Rotation == nil {
		t.Fatalf("GET group: %v %s", err, getRec.Body.String())
	}
	if served.Rotation.RemovedUserID != bob.userID || served.Rotation.StartSignature != body.Rotation.StartSignature {
		t.Errorf("served rotation = %+v", *served.Rotation)
	}
	link := getRow(t, "GROUP#"+gid, "GENKEY#000000")
	if link == nil {
		t.Fatal("no GENKEY#000000 link for the old generation")
	}
	if _, ttl := link["TTL"]; ttl {
		t.Error("chain link carries a TTL")
	}
	if g := numAttr(getRow(t, "GROUP#"+gid, "MEMBER#"+owner.userID), "Generation"); g != "1" {
		t.Errorf("remover generation = %s, want 1", g)
	}
	if g := numAttr(getRow(t, "GROUP#"+gid, "MEMBER#"+carol.userID), "Generation"); g != "0" {
		t.Errorf("bystander generation = %s, want 0 (the client re-wraps them)", g)
	}

	// A second removal while the rotation runs is refused and changes nothing.
	rec := doRemove(t, h, ownerCookie, gid, carol.userID, &removeMemberRequest{Rotation: rotationBody(t, owner, gid, carol.userID, 2)})
	if rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_in_progress" {
		t.Fatalf("%d %q %s", rec.Code, errCode(t, rec), rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+carol.userID) == nil {
		t.Error("second removal went through during a rotation")
	}
	if g := numAttr(getRow(t, "GROUP#"+gid, "MEMBER#"+owner.userID), "Generation"); g != "1" {
		t.Errorf("rejected removal moved remover generation to %s", g)
	}
}

// Without the rotation payload a Rotating removal must not half-happen: that
// would leave the removed member reading every new post with nothing saying so.
func TestRemoveMemberRotatingRejectsBadRotation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob := registerTestUser(t, h)
	addMember(t, gid, bob, "member")

	badLink := rotationBody(t, owner, gid, bob.userID, 1)
	badLink.Link.Nonce = "AAAA"
	cases := map[string]*removeMemberRequest{
		"no body":            nil,
		"no rotation":        {},
		"generation skips":   {Rotation: rotationBody(t, owner, gid, bob.userID, 2)},
		"generation repeats": {Rotation: rotationBody(t, owner, gid, bob.userID, 0)},
		"short link nonce":   {Rotation: badLink},
	}
	for name, body := range cases {
		rec := doRemove(t, h, ownerCookie, gid, bob.userID, body)
		if rec.Code != http.StatusBadRequest || errCode(t, rec) != "rotation_required" {
			t.Errorf("%s: %d %q %s", name, rec.Code, errCode(t, rec), rec.Body.String())
		}
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+bob.userID) == nil {
		t.Error("member removed without a rotation")
	}
	if getRow(t, "GROUP#"+gid, "ROTATION") != nil || getRow(t, "GROUP#"+gid, "GENKEY#000000") != nil {
		t.Error("rejected requests wrote rotation state")
	}
}

// The rotation start must be the remover's own signature naming THIS subject
// and THIS generation; a missing, malformed or misdirected one is refused and
// nothing is written, so a marker that no resuming client could verify never
// lands (#178).
func TestRemoveMemberRotatingRejectsBadStartSignature(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob, carol := registerTestUser(t, h), registerTestUser(t, h)
	addMember(t, gid, bob, "member")
	addMember(t, gid, carol, "member")

	missing := rotationBody(t, owner, gid, bob.userID, 1)
	missing.StartSignature = ""
	short := rotationBody(t, owner, gid, bob.userID, 1)
	short.StartSignature = b64(10)
	cases := map[string]*removeRotationRequest{
		"missing":        missing,
		"short":          short,
		"names another":  rotationBody(t, owner, gid, carol.userID, 1),
		"another group":  rotationBody(t, owner, "00000000-0000-4000-8000-000000000000", bob.userID, 1),
		"another signer": rotationBody(t, carol, gid, bob.userID, 1),
		"another gen":    rotationBody(t, owner, gid, bob.userID, 2),
	}
	// "another gen" is signed for 2 but sent as 1.
	cases["another gen"].Generation = 1
	for name, rot := range cases {
		rec := doRemove(t, h, ownerCookie, gid, bob.userID, &removeMemberRequest{Rotation: rot})
		if rec.Code != http.StatusBadRequest || errCode(t, rec) != "bad_signature" {
			t.Errorf("%s: %d %q %s", name, rec.Code, errCode(t, rec), rec.Body.String())
		}
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+bob.userID) == nil {
		t.Error("member removed with a bad rotation signature")
	}
	if getRow(t, "GROUP#"+gid, "ROTATION") != nil || getRow(t, "GROUP#"+gid, "GENKEY#000000") != nil {
		t.Error("rejected requests wrote rotation state")
	}
}

// Rotation is a Rotating-group concept; an Open group says so rather than
// silently ignoring a payload that implies a guarantee it does not give.
func TestRemoveMemberOpenGroupRefusesRotation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	bob := registerTestUser(t, h)
	addMember(t, gid, bob, "member")

	rec := doRemove(t, h, ownerCookie, gid, bob.userID, &removeMemberRequest{Rotation: rotationBody(t, owner, gid, bob.userID, 1)})
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != "rotation_not_applicable" {
		t.Fatalf("%d %q %s", rec.Code, errCode(t, rec), rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+bob.userID) == nil {
		t.Error("member removed by a rejected request")
	}
}

// An elevated subject in a Rotating group needs BOTH halves: the remover's
// signed demotion and the rotation, and they commit together.
func TestRemoveMemberRotatingAdminSubjectDemotesAndRotates(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	adm := registerTestUser(t, h)
	addMember(t, gid, adm, "admin")

	body := removalGrant(t, owner, gid, adm.userID, backdatedRef(t, gid, owner))
	body.Rotation = rotationBody(t, owner, gid, adm.userID, 1)
	if rec := doRemove(t, h, ownerCookie, gid, adm.userID, &body); rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+adm.userID) != nil || getRow(t, "GROUP#"+gid, "ROTATION") == nil {
		t.Error("expected the admin gone and a rotation started")
	}
	if getRow(t, "GROUP#"+gid, body.GrantSortKey) == nil {
		t.Error("demotion grant not written")
	}
}

func TestRemoveMemberRequiresSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	if rec := doRemove(t, h, nil, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// The role the handler read can change before the transaction runs. The
// delete is conditioned on it, so a stale view is a conflict rather than a
// removal that signed the wrong demotion (or none): here the subject was
// promoted after the caller saw a plain member.
func TestRemoveMemberStaleSubjectRoleIsAConflict(t *testing.T) {
	client := testDB(t)
	h := New(config.FromEnv(), client)
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	bob := registerTestUser(t, h)
	addMember(t, gid, bob, "admin") // promoted after the (stale) read below

	err := client.RemoveMember(context.Background(), db.RemoveMemberInput{
		GroupID: gid, SubjectUserID: bob.userID, SubjectRole: "member",
		RemoverUserID: owner.userID, RemoverHasStoredGrant: true, RemoverGrantRef: rootRef(t, gid, owner),
	})
	if !errors.Is(err, db.ErrSubjectRoleChanged) {
		t.Fatalf("err = %v, want ErrSubjectRoleChanged", err)
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+bob.userID) == nil {
		t.Error("member was removed on a stale role")
	}
}

// {} and null mean "no demotion", exactly like no body (leaveGroup's empty()):
// a client that always sends a body must not get a false "role changed" 409.
func TestRemoveMemberEmptyBodyIsNoDemotion(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	bob := registerTestUser(t, h)
	addMember(t, gid, bob, "member")

	if rec := doRemove(t, h, ownerCookie, gid, bob.userID, &removeMemberRequest{}); rec.Code != http.StatusNoContent {
		t.Fatalf("remove with {}: %d %s", rec.Code, rec.Body.String())
	}
}

// The remover is re-checked inside the transaction, not only by the handler:
// between the handler's read and the write they may have been demoted, or
// have had their current grant replaced. Either is a conflict that removes
// nobody (the handler's own caller.Role check hides this everywhere else).
func TestRemoveMemberStaleRemoverIsAConflict(t *testing.T) {
	client := testDB(t)
	h := New(config.FromEnv(), client)
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	bob := registerTestUser(t, h)
	addMember(t, gid, bob, "member")
	ref := rootRef(t, gid, owner)

	remove := func(in db.RemoveMemberInput) error {
		in.GroupID, in.SubjectUserID, in.SubjectRole, in.RemoverUserID = gid, bob.userID, "member", owner.userID
		return client.RemoveMember(context.Background(), in)
	}
	t.Run("remover on a different grant than they signed against", func(t *testing.T) {
		err := remove(db.RemoveMemberInput{RemoverHasStoredGrant: true, RemoverGrantRef: "GRANT#" + owner.userID + "#2020-01-01#0000000000000000"})
		if !errors.Is(err, db.ErrGrantorChanged) {
			t.Fatalf("err = %v, want ErrGrantorChanged", err)
		}
	})
	t.Run("remover no longer an admin", func(t *testing.T) {
		// Demote the owner row directly, as a concurrent role change would.
		if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
			TableName: aws.String(testTableName()),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "GROUP#" + gid},
				"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + owner.userID},
			},
			UpdateExpression:         aws.String("SET #r = :m"),
			ExpressionAttributeNames: map[string]string{"#r": "Role"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":m": &types.AttributeValueMemberS{Value: "member"},
			},
		}); err != nil {
			t.Fatal(err)
		}
		err := remove(db.RemoveMemberInput{RemoverHasStoredGrant: true, RemoverGrantRef: ref})
		if !errors.Is(err, db.ErrGrantorChanged) {
			t.Fatalf("err = %v, want ErrGrantorChanged", err)
		}
	})
	if getRow(t, "GROUP#"+gid, "MEMBER#"+bob.userID) == nil {
		t.Error("member was removed by a stale remover")
	}
}

// Removing an admin whose demotion would be signed on the same UTC day the
// remover's own role was set cannot verify (the strict same-day rule), and
// would take the remover's later grants down with it. Reachable by an honest
// admin: a creator's root grant is dated the day the group was made.
func TestRemoveMemberRefusedWhenRemoversGrantIsDatedToday(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie) // root grant dated today
	adm := registerTestUser(t, h)
	addMember(t, gid, adm, "admin")

	req := removalGrant(t, owner, gid, adm.userID, rootRef(t, gid, owner))
	rec := doRemove(t, h, ownerCookie, gid, adm.userID, &req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body: %s", rec.Code, rec.Body.String())
	}
	if got := errCode(t, rec); got != "remover_granted_today" {
		t.Fatalf("code = %q, want remover_granted_today", got)
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+adm.userID) == nil {
		t.Error("admin was removed with an unverifiable demotion")
	}
	if getRow(t, "GROUP#"+gid, req.GrantSortKey) != nil {
		t.Error("an unverifiable demotion was written")
	}

	// Only a demotion is signed for an elevated subject: a plain member's
	// removal signs nothing, so the same remover may do it today.
	bob := registerTestUser(t, h)
	addMember(t, gid, bob, "member")
	if rec := doRemove(t, h, ownerCookie, gid, bob.userID, nil); rec.Code != http.StatusNoContent {
		t.Errorf("plain member removal on the remover's grant day: %d %s", rec.Code, rec.Body.String())
	}
}

// Removal deletes the subject's own pending invites, as leaving does: an
// invitee must not be left holding an invite whose inviter is gone.
func TestRemoveMemberDeletesTheirPendingInvites(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	bob, bobCookie := loggedInUser(t, h)
	addMember(t, gid, bob, "ambassador")

	inv := signedCreateInviteRequest(t, bob, gid, time.Now().Add(24*time.Hour))
	if rec := doJSON(t, h, http.MethodPost, "/api/groups/"+gid+"/invites", bobCookie, inv); rec.Code != http.StatusCreated {
		t.Fatalf("create invite: %d %s", rec.Code, rec.Body.String())
	}
	sent := func() int {
		out, err := rawDDB(t).Query(context.Background(), &dynamodb.QueryInput{
			TableName:              aws.String(testTableName()),
			KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "USER#" + bob.userID},
				":sk": &types.AttributeValueMemberS{Value: "SENT#"},
			},
			ConsistentRead: aws.Bool(true),
		})
		if err != nil {
			t.Fatal(err)
		}
		return len(out.Items)
	}
	if sent() != 1 || getRow(t, "INVITE#"+inv.InviteID, "META") == nil {
		t.Fatal("precondition: the invite rows should exist before removal")
	}

	req := removalGrant(t, owner, gid, bob.userID, backdatedRef(t, gid, owner))
	if rec := doRemove(t, h, ownerCookie, gid, bob.userID, &req); rec.Code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body.String())
	}
	if sent() != 0 {
		t.Error("the removed member's SENT# row survived")
	}
	if getRow(t, "INVITE#"+inv.InviteID, "META") != nil {
		t.Error("the removed member's INVITE# row survived")
	}
}

// The verifier needs the remover's grant strictly EARLIER than the demotion.
// A grant dated LATER is reachable with honest clients near 00:00 UTC (the
// grant day window is now-26h..now+2h): the remover is promoted just after
// midnight, and a slow client dates the removal for the day before. Stored,
// it leaves the removal "grantor held no grant on the signing day" and
// everything the remover signs afterwards unverified, permanently if the
// removed admin was the creator.
func TestRemoveMemberRefusedWhenRemoversGrantIsDatedAfterTheDemotion(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	adm := registerTestUser(t, h)
	addMember(t, gid, adm, "admin")

	// Remover's grant is dated tomorrow; the demotion is dated today.
	tomorrow := testGrantSortKey(t, owner.userID, time.Now().AddDate(0, 0, 1))
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + gid},
			"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + owner.userID},
		},
		UpdateExpression:          aws.String("SET GrantSortKey = :r"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":r": &types.AttributeValueMemberS{Value: tomorrow}},
	}); err != nil {
		t.Fatal(err)
	}

	req := removalGrant(t, owner, gid, adm.userID, tomorrow)
	rec := doRemove(t, h, ownerCookie, gid, adm.userID, &req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body: %s", rec.Code, rec.Body.String())
	}
	if got := errCode(t, rec); got != "remover_granted_today" {
		t.Fatalf("code = %q, want remover_granted_today", got)
	}
	if msg := errMessage(t, rec); !strings.Contains(msg, "clock") {
		t.Errorf("a later-dated remover grant needs clock advice, not 'try again after 00:00 UTC': %q", msg)
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+adm.userID) == nil {
		t.Error("admin was removed with an unverifiable demotion")
	}
	if getRow(t, "GROUP#"+gid, req.GrantSortKey) != nil {
		t.Error("an unverifiable demotion was written")
	}
}

func errMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("decoding error body %q: %v", rec.Body.String(), err)
	}
	return b.Error
}

func deleteRow(t *testing.T, pk, sk string) {
	t.Helper()
	if _, err := rawDDB(t).DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: pk},
			"SK": &types.AttributeValueMemberS{Value: sk},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func setMemberGeneration(t *testing.T, gid, userID string, gen int) {
	t.Helper()
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + gid},
			"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + userID},
		},
		UpdateExpression:          aws.String("SET Generation = :g"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":g": &types.AttributeValueMemberN{Value: strconv.Itoa(gen)}},
	}); err != nil {
		t.Fatal(err)
	}
}

// The GENKEY# put is the only thing stopping an admin whose own entry point is
// behind the group's from overwriting an existing chain link. State: a
// rotation 0->1 finished (marker gone), and an admin still at generation 0
// (e.g. an invite wrapped at 0 and accepted after) asks for generation 1
// again. That is not "in progress": it is a distinct error and the link, and
// the membership, are untouched.
func TestRemoveMemberStaleGenerationNeverOverwritesChainLink(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob, carol := registerTestUser(t, h), registerTestUser(t, h)
	addMember(t, gid, bob, "member")
	addMember(t, gid, carol, "member")

	if rec := doRemove(t, h, ownerCookie, gid, bob.userID, &removeMemberRequest{Rotation: rotationBody(t, owner, gid, bob.userID, 1)}); rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	before := getRow(t, "GROUP#"+gid, "GENKEY#000000")
	deleteRow(t, "GROUP#"+gid, "ROTATION") // the rotation finished
	setMemberGeneration(t, gid, owner.userID, 0)

	rec := doRemove(t, h, ownerCookie, gid, carol.userID, &removeMemberRequest{Rotation: rotationBody(t, owner, gid, carol.userID, 1)})
	if rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_stale_generation" {
		t.Fatalf("%d %q %s", rec.Code, errCode(t, rec), rec.Body.String())
	}
	after := getRow(t, "GROUP#"+gid, "GENKEY#000000")
	if !reflect.DeepEqual(before, after) {
		t.Error("existing chain link was overwritten")
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+carol.userID) == nil || getRow(t, "GROUP#"+gid, "ROTATION") != nil {
		t.Error("rejected removal changed state")
	}
}

// While a rotation runs the remover already holds the new generation, which
// un-re-wrapped members cannot read, so a private group's name (written at the
// writer's own generation) cannot be edited until the marker clears.
func TestPrivateGroupEditRefusedDuringRotation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob := registerTestUser(t, h)
	addMember(t, gid, bob, "member")
	if rec := doRemove(t, h, ownerCookie, gid, bob.userID, &removeMemberRequest{Rotation: rotationBody(t, owner, gid, bob.userID, 1)}); rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}

	req := updateReq(0)
	req.NameGeneration = 1
	rec := doGroupRequest(t, h, ownerCookie, http.MethodPut, gid, req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_in_progress" {
		t.Fatalf("during rotation: %d %q %s", rec.Code, errCode(t, rec), rec.Body.String())
	}
	deleteRow(t, "GROUP#"+gid, "ROTATION")
	if rec := doGroupRequest(t, h, ownerCookie, http.MethodPut, gid, req); rec.Code != http.StatusOK {
		t.Fatalf("after rotation: %d %s", rec.Code, rec.Body.String())
	}
}
