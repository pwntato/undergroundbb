package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
)

func doRotationCall(t *testing.T, h *Handler, cookie *http.Cookie, method, gid, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, "/api/groups/"+gid+"/rotation/"+path, &buf)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func loginCookie(t *testing.T, h *Handler, u registeredUser) *http.Cookie {
	t.Helper()
	rec := completeLogin(t, h, u)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	return sessionCookieFrom(rec)
}

func setMemberRole(t *testing.T, gid, userID, role string) {
	t.Helper()
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + gid},
			"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + userID},
		},
		UpdateExpression:          aws.String("SET #r = :r"),
		ExpressionAttributeNames:  map[string]string{"#r": "Role"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":r": &types.AttributeValueMemberS{Value: role}},
	}); err != nil {
		t.Fatal(err)
	}
}

func rewrapReq(gen int64, users ...registeredUser) rewrapMembersRequest {
	req := rewrapMembersRequest{Generation: gen}
	for _, u := range users {
		req.Wraps = append(req.Wraps, memberRewrapIn{
			UserID:     u.userID,
			WrappedKey: wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		})
	}
	return req
}

func memberGen(t *testing.T, gid string, u registeredUser) string {
	t.Helper()
	return numAttr(getRow(t, "GROUP#"+gid, "MEMBER#"+u.userID), "Generation")
}

// rotatingGroup builds: owner (admin, will be at gen 1 after starting), plus
// members carol and dave and a victim who is removed to start rotation 0->1.
type rotationFixture struct {
	h                    *Handler
	gid                  string
	owner                registeredUser
	ownerCookie          *http.Cookie
	carol, dave, bobGone registeredUser
}

func startRotation(t *testing.T) rotationFixture {
	t.Helper()
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	f := rotationFixture{h: h, gid: gid, owner: owner, ownerCookie: ownerCookie,
		carol: registerTestUser(t, h), dave: registerTestUser(t, h), bobGone: registerTestUser(t, h)}
	for _, u := range []registeredUser{f.carol, f.dave, f.bobGone} {
		addMember(t, gid, u, "member")
	}
	if rec := doRemove(t, h, ownerCookie, gid, f.bobGone.userID, &removeMemberRequest{Rotation: rotationBody(1)}); rec.Code != http.StatusNoContent {
		t.Fatalf("start rotation: %d %s", rec.Code, rec.Body.String())
	}
	return f
}

func TestRotationRewrapAndComplete(t *testing.T) {
	f := startRotation(t)

	// The marker is visible to members on the group detail.
	d := decodeDetail(t, doGroupRequest(t, f.h, f.ownerCookie, http.MethodGet, f.gid, nil))
	if d.Rotation == nil || d.Rotation.Generation != 1 || d.Rotation.StartedBy != f.owner.userID {
		t.Fatalf("detail rotation = %+v", d.Rotation)
	}

	// Completion is refused while anyone is behind.
	rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "complete", completeRotationRequest{Generation: 1})
	if rec.Code != http.StatusConflict || errCode(t, rec) != "members_behind" {
		t.Fatalf("early complete: %d %s", rec.Code, rec.Body.String())
	}

	req := rewrapReq(1, f.carol)
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", req); rec.Code != http.StatusNoContent {
		t.Fatalf("rewrap: %d %s", rec.Code, rec.Body.String())
	}
	if g := memberGen(t, f.gid, f.carol); g != "1" {
		t.Errorf("carol generation = %s", g)
	}
	if memberGen(t, f.gid, f.dave) != "0" {
		t.Error("dave moved without being in a batch")
	}
	// A resend of an already-moved member is fine (lost-response retry).
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", rewrapReq(1, f.carol, f.dave)); rec.Code != http.StatusNoContent {
		t.Fatalf("resend: %d %s", rec.Code, rec.Body.String())
	}

	rec = doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "complete", completeRotationRequest{Generation: 1})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
	if getRow(t, "GROUP#"+f.gid, "ROTATION") != nil {
		t.Error("marker still present")
	}
	if d := decodeDetail(t, doGroupRequest(t, f.h, f.ownerCookie, http.MethodGet, f.gid, nil)); d.Rotation != nil {
		t.Errorf("detail still shows rotation: %+v", d.Rotation)
	}
	rec = doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "complete", completeRotationRequest{Generation: 1})
	if rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_not_active" {
		t.Errorf("second complete: %d %s", rec.Code, rec.Body.String())
	}
}

// A member who ends up behind AFTER completion (an invite completed by an
// inviter who was re-wrapped mid-request, or added in the scan/delete gap) must
// be movable with no marker present: only a removal starts a rotation, so
// without this nothing could ever bring them up to the group's key.
func TestRotationCatchUpAfterCompletion(t *testing.T) {
	f := startRotation(t)
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", rewrapReq(1, f.carol, f.dave)); rec.Code != http.StatusNoContent {
		t.Fatalf("rewrap: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "complete", completeRotationRequest{Generation: 1}); rec.Code != http.StatusNoContent {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
	late := registerTestUser(t, f.h)
	addMember(t, f.gid, late, "member") // lands at generation 0, one behind

	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", rewrapReq(1, late)); rec.Code != http.StatusNoContent {
		t.Fatalf("catch-up: %d %s", rec.Code, rec.Body.String())
	}
	if g := memberGen(t, f.gid, late); g != "1" {
		t.Errorf("late member generation = %s, want 1", g)
	}
	if getRow(t, "GROUP#"+f.gid, "ROTATION") != nil {
		t.Error("catch-up created a marker")
	}
	// It cannot be used to rotate: the generation is pinned to the caller's own
	// entry point, so asking for 2 is refused, and nobody is moved backward.
	rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", rewrapReq(2, f.carol))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_caller_behind" {
		t.Errorf("catch-up to a generation the caller does not hold: %d %s", rec.Code, rec.Body.String())
	}
	setMemberGeneration(t, f.gid, f.dave.userID, 2)
	rec = doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", rewrapReq(1, f.dave))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "member_changed" {
		t.Errorf("catch-up over a member already ahead: %d %s", rec.Code, rec.Body.String())
	}
}

// A stale tab completing generation 1 after its admin has started rotation 2
// must hear "not active" (which the client treats as done), not "caller
// behind", the same answer RewrapMembers gives.
func TestRotationCompleteStaleTabHearsNotActive(t *testing.T) {
	f := startRotation(t)
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", rewrapReq(1, f.carol, f.dave)); rec.Code != http.StatusNoContent {
		t.Fatalf("rewrap: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "complete", completeRotationRequest{Generation: 1}); rec.Code != http.StatusNoContent {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRemove(t, f.h, f.ownerCookie, f.gid, f.carol.userID, &removeMemberRequest{Rotation: rotationBody(2)}); rec.Code != http.StatusNoContent {
		t.Fatalf("rotation 2: %d %s", rec.Code, rec.Body.String())
	}
	// Now at generation 2 with marker 2; a stale tab completes generation 1.
	rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "complete", completeRotationRequest{Generation: 1})
	if rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_not_active" {
		t.Errorf("stale complete: %d %q %s", rec.Code, errCode(t, rec), rec.Body.String())
	}
}

func TestRotationRewrapRejections(t *testing.T) {
	f := startRotation(t)
	adm2 := registerTestUser(t, f.h)
	addMember(t, f.gid, adm2, "admin") // a second admin, still at generation 0
	adm2Cookie := loginCookie(t, f.h, adm2)
	carolCookie := loginCookie(t, f.h, f.carol)
	_, strangerCookie := loggedInUser(t, f.h)

	ghost := registerTestUser(t, f.h) // never a member
	dup := rewrapReq(1, f.carol, f.carol)
	self := rewrapReq(1, f.owner)
	empty := rewrapMembersRequest{Generation: 1}

	cases := []struct {
		name   string
		cookie *http.Cookie
		body   any
		want   int
		code   string
	}{
		{"non-admin member", carolCookie, rewrapReq(1, f.dave), 403, ""},
		{"non-member", strangerCookie, rewrapReq(1, f.dave), 404, ""},
		{"admin not yet at the generation", adm2Cookie, rewrapReq(1, f.dave), 409, "rotation_caller_behind"},
		{"wrong generation", f.ownerCookie, rewrapReq(2, f.dave), 409, "rotation_not_active"},
		{"empty batch", f.ownerCookie, empty, 400, ""},
		{"duplicate user", f.ownerCookie, dup, 400, ""},
		{"caller's own entry", f.ownerCookie, self, 400, ""},
		{"member who is not in the group", f.ownerCookie, rewrapReq(1, f.dave, ghost), 409, "member_changed"},
	}
	for _, tc := range cases {
		rec := doRotationCall(t, f.h, tc.cookie, http.MethodPut, f.gid, "members", tc.body)
		if rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d: %s", tc.name, rec.Code, tc.want, rec.Body.String())
		} else if tc.code != "" && errCode(t, rec) != tc.code {
			t.Errorf("%s: code %q, want %q", tc.name, errCode(t, rec), tc.code)
		}
	}
	// Nothing above may have moved anyone: the ghost batch is all-or-nothing.
	if memberGen(t, f.gid, f.dave) != "0" || memberGen(t, f.gid, f.carol) != "0" {
		t.Error("a rejected batch moved a member")
	}

	// A member already past the generation is not walked backward or sideways.
	setMemberGeneration(t, f.gid, f.dave.userID, 2)
	rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", rewrapReq(1, f.dave))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "member_changed" {
		t.Errorf("past-generation member: %d %s", rec.Code, rec.Body.String())
	}
	// Completion by an admin who is not at the generation is refused.
	rec = doRotationCall(t, f.h, adm2Cookie, http.MethodPost, f.gid, "complete", completeRotationRequest{Generation: 1})
	if rec.Code != http.StatusConflict {
		t.Errorf("complete by behind admin: %d %s", rec.Code, rec.Body.String())
	}
}

// With no marker the re-wrap is a catch-up and moves only members STRICTLY
// behind the caller's generation. A fresh group that never rotated has everyone
// at the current generation, so an admin must not be able to replace a peer's
// wrapped key there (nothing outside an active rotation could do that before).
func TestRotationNoMarkerNeverOverwritesMemberAtGeneration(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	peer := registerTestUser(t, h)
	addMember(t, gid, peer, "admin")
	before := getRow(t, "GROUP#"+gid, "MEMBER#"+peer.userID)

	rec := doRotationCall(t, h, ownerCookie, http.MethodPut, gid, "members", rewrapReq(0, peer))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "member_changed" {
		t.Fatalf("%d %q %s", rec.Code, errCode(t, rec), rec.Body.String())
	}
	if !reflect.DeepEqual(before, getRow(t, "GROUP#"+gid, "MEMBER#"+peer.userID)) {
		t.Error("peer's membership was rewritten")
	}
}

// The handler half of the inviter-generation guard: when CompleteInvite's check
// fails the handler re-reads the inviter. Still elevated is a retryable 409; no
// longer elevated stays the 403. (The race itself, the generation moving between
// the handler's read and the write, is covered at the db layer; it cannot be
// staged through the handler without a hook, so this calls the mapping directly.)
func TestWriteInviterNotEligibleDistinguishesGenerationFromRole(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, cookie)
	call := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.writeInviterNotEligible(rec, httptest.NewRequest(http.MethodPost, "/", nil), gid, owner.userID)
		return rec
	}
	setMemberGeneration(t, gid, owner.userID, 1) // re-wrapped under the inviter
	if rec := call(); rec.Code != http.StatusConflict || errCode(t, rec) != "conflict_retry" {
		t.Errorf("still an admin: %d %s", rec.Code, rec.Body.String())
	}
	setMemberRole(t, gid, owner.userID, "member")
	if rec := call(); rec.Code != http.StatusForbidden {
		t.Errorf("demoted: %d %s", rec.Code, rec.Body.String())
	}
	deleteRow(t, "GROUP#"+gid, "MEMBER#"+owner.userID)
	if rec := call(); rec.Code != http.StatusForbidden {
		t.Errorf("gone: %d %s", rec.Code, rec.Body.String())
	}
}
