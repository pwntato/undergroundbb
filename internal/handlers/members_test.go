package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
)

// addMember writes a MEMBER# row directly, standing in for the invite
// handshake (covered by invite_test.go) so these tests can start from "a
// group with several members" cheaply.
func addMember(t *testing.T, groupID string, user registeredUser, role string) {
	t.Helper()
	item := map[string]types.AttributeValue{
		"PK":         &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
		"SK":         &types.AttributeValueMemberS{Value: "MEMBER#" + user.userID},
		"Type":       &types.AttributeValueMemberS{Value: "Membership"},
		"GSI1PK":     &types.AttributeValueMemberS{Value: "USER#" + user.userID},
		"GSI1SK":     &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
		"Role":       &types.AttributeValueMemberS{Value: role},
		"Generation": &types.AttributeValueMemberN{Value: "0"},
	}
	if _, err := rawDDB(t).PutItem(context.Background(), &dynamodb.PutItemInput{TableName: aws.String(testTableName()), Item: item}); err != nil {
		t.Fatalf("addMember: %v", err)
	}
}

func getRow(t *testing.T, pk, sk string) map[string]types.AttributeValue {
	t.Helper()
	out, err := rawDDB(t).GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(testTableName()), ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: pk},
			"SK": &types.AttributeValueMemberS{Value: sk},
		},
	})
	if err != nil {
		t.Fatalf("GetItem: %v", err)
	}
	return out.Item
}

func strAttr(item map[string]types.AttributeValue, name string) string {
	if v, ok := item[name].(*types.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}

func doListMembers(t *testing.T, h *Handler, cookie *http.Cookie, groupID, query string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/groups/"+groupID+"/members"+query, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func signedRoleRequest(t *testing.T, grantor registeredUser, groupID, subjectID, role, grantorRef string) changeRoleRequest {
	t.Helper()
	sk := testGrantSortKey(t, subjectID, time.Now())
	sig, err := crypto.Sign(grantor.signPriv, crypto.ContextRoleGrant, crypto.RoleGrantPayload(groupID, subjectID, role, sk, grantorRef))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return changeRoleRequest{Role: role, GrantSortKey: sk, GrantorGrantRef: grantorRef, Signature: base64.StdEncoding.EncodeToString(sig)}
}

func doChangeRole(t *testing.T, h *Handler, cookie *http.Cookie, groupID, subjectID string, req changeRoleRequest) *httptest.ResponseRecorder {
	t.Helper()
	return doGroupRequest(t, h, cookie, http.MethodPut, groupID+"/members/"+subjectID+"/role", req)
}

// rootRef reads the creator's current grant off their membership row.
func rootRef(t *testing.T, groupID string, creator registeredUser) string {
	t.Helper()
	ref := strAttr(getRow(t, "GROUP#"+groupID, "MEMBER#"+creator.userID), "GrantSortKey")
	if ref == "" {
		t.Fatal("creator membership has no GrantSortKey")
	}
	return ref
}

func TestListMembers(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	second := registerTestUser(t, h)
	third := registerTestUser(t, h)
	addMember(t, gid, second, "member")
	addMember(t, gid, third, "ambassador")

	rec := doListMembers(t, h, ownerCookie, gid, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var resp listMembersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	roles := map[string]string{}
	for _, m := range resp.Members {
		roles[m.UserID] = m.Role
	}
	if len(resp.Members) != 3 || roles[owner.userID] != "admin" || roles[second.userID] != "member" || roles[third.userID] != "ambassador" || resp.NextCursor != "" {
		t.Errorf("unexpected roster: %+v", resp)
	}

	// Pagination: pages of 2 then 1, together the whole roster, no repeats.
	seen := map[string]bool{}
	cursor, pages := "", 0
	for {
		q := "?limit=2"
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		var page listMembersResponse
		if err := json.Unmarshal(doListMembers(t, h, ownerCookie, gid, q).Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		for _, m := range page.Members {
			if seen[m.UserID] {
				t.Errorf("member %s repeated across pages", m.UserID)
			}
			seen[m.UserID] = true
		}
		pages++
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
		if pages > 5 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != 3 || pages != 2 {
		t.Errorf("seen %d members over %d pages, want 3 over 2", len(seen), pages)
	}

	if rec := doListMembers(t, h, ownerCookie, gid, "?limit=0"); rec.Code != http.StatusBadRequest {
		t.Errorf("limit=0 status = %d", rec.Code)
	}
	if rec := doListMembers(t, h, ownerCookie, gid, "?cursor=nope"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad cursor status = %d", rec.Code)
	}
}

func TestListMembersMembersOnlyAlways(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	_, otherCookie := loggedInUser(t, h)
	priv := createPrivateGroup(t, h, owner, ownerCookie)
	pub := createPublicGroup(t, h, owner, ownerCookie)

	if rec := doListMembers(t, h, nil, priv, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d", rec.Code)
	}
	a := doListMembers(t, h, otherCookie, priv, "")
	b := doListMembers(t, h, otherCookie, pub, "")
	c := doListMembers(t, h, otherCookie, "3f0c7a52-1111-4222-8333-444455556666", "")
	if a.Code != 404 || b.Code != 404 || c.Code != 404 {
		t.Fatalf("statuses = %d %d %d, want 404 all (a public group has no public roster)", a.Code, b.Code, c.Code)
	}
	if a.Body.String() != b.Body.String() || a.Body.String() != c.Body.String() {
		t.Error("404 bodies differ")
	}
}

func TestChangeRolePromoteAndChain(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	alice, aliceCookie := loggedInUser(t, h)
	bob := registerTestUser(t, h)
	addMember(t, gid, alice, "member")
	addMember(t, gid, bob, "member")

	// creator -> alice (admin)
	req := signedRoleRequest(t, owner, gid, alice.userID, "admin", rootRef(t, gid, owner))
	if rec := doChangeRole(t, h, ownerCookie, gid, alice.userID, req); rec.Code != http.StatusOK {
		t.Fatalf("promote alice: %d %s", rec.Code, rec.Body.String())
	}
	aliceMember := getRow(t, "GROUP#"+gid, "MEMBER#"+alice.userID)
	if strAttr(aliceMember, "Role") != "admin" || strAttr(aliceMember, "GrantSortKey") != req.GrantSortKey {
		t.Errorf("alice membership: %v", aliceMember)
	}
	grant := getRow(t, "GROUP#"+gid, req.GrantSortKey)
	if grant == nil {
		t.Fatal("grant row not written")
	}
	if strAttr(grant, "GrantedRole") != "admin" || strAttr(grant, "SubjectUserID") != alice.userID ||
		strAttr(grant, "GrantorUserID") != owner.userID || strAttr(grant, "GrantorGrantRef") != req.GrantorGrantRef {
		t.Errorf("grant row: %v", grant)
	}
	if _, has := grant["CreatedAt"]; has {
		t.Error("grant row carries CreatedAt; see issue #147")
	}

	// alice (chain: creator -> alice) -> bob (ambassador), referencing HER grant.
	req2 := signedRoleRequest(t, alice, gid, bob.userID, "ambassador", req.GrantSortKey)
	if rec := doChangeRole(t, h, aliceCookie, gid, bob.userID, req2); rec.Code != http.StatusOK {
		t.Fatalf("alice promotes bob: %d %s", rec.Code, rec.Body.String())
	}
	if got := strAttr(getRow(t, "GROUP#"+gid, "MEMBER#"+bob.userID), "Role"); got != "ambassador" {
		t.Errorf("bob role = %q", got)
	}

	// alice demotes the creator: allowed (append-only, alice is an admin),
	// and the group still has an admin.
	req3 := signedRoleRequest(t, alice, gid, owner.userID, "member", req.GrantSortKey)
	if rec := doChangeRole(t, h, aliceCookie, gid, owner.userID, req3); rec.Code != http.StatusOK {
		t.Fatalf("demote creator: %d %s", rec.Code, rec.Body.String())
	}
	// ...after which the creator can no longer change roles.
	req4 := signedRoleRequest(t, owner, gid, bob.userID, "member", req3.GrantSortKey)
	if rec := doChangeRole(t, h, ownerCookie, gid, bob.userID, req4); rec.Code != http.StatusForbidden {
		t.Errorf("demoted creator: %d, want 403", rec.Code)
	}
}

// A creator on a group made before Membership.GrantSortKey existed has no
// stored grant; the root grant on META is their current one.
func TestChangeRoleLegacyCreatorUsesRootGrant(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	member := registerTestUser(t, h)
	addMember(t, gid, member, "member")
	root := rootRef(t, gid, owner)

	_, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + gid},
			"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + owner.userID},
		},
		UpdateExpression: aws.String("REMOVE GrantSortKey"),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := signedRoleRequest(t, owner, gid, member.userID, "ambassador", root)
	if rec := doChangeRole(t, h, ownerCookie, gid, member.userID, req); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
}

func TestChangeRoleRejections(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	amb, ambCookie := loggedInUser(t, h)
	target := registerTestUser(t, h)
	stranger, strangerCookie := loggedInUser(t, h)
	addMember(t, gid, amb, "ambassador")
	addMember(t, gid, target, "member")
	root := rootRef(t, gid, owner)

	good := func() changeRoleRequest { return signedRoleRequest(t, owner, gid, target.userID, "ambassador", root) }

	// Wrong role in body relative to what was signed.
	r := good()
	r.Role = "admin"
	// Valid ref, but signed by a different user's key.
	forged := signedRoleRequest(t, stranger, gid, target.userID, "ambassador", root)
	// Stale ref.
	stale := signedRoleRequest(t, owner, gid, target.userID, "ambassador", "GRANT#"+owner.userID+"#2026-01-01#0000000000000000")
	// Sort key for the wrong subject.
	wrongSubject := signedRoleRequest(t, owner, gid, amb.userID, "ambassador", root)
	// Bad signature bytes.
	shortSig := good()
	shortSig.Signature = base64.StdEncoding.EncodeToString([]byte("short"))
	badRole := signedRoleRequest(t, owner, gid, target.userID, "emperor", root)
	sameRole := signedRoleRequest(t, owner, gid, target.userID, "member", root)
	self := signedRoleRequest(t, owner, gid, owner.userID, "member", root)

	cases := []struct {
		name   string
		cookie *http.Cookie
		subj   string
		req    changeRoleRequest
		want   int
	}{
		{"role differs from signed", ownerCookie, target.userID, r, 400},
		{"signed by another key", ownerCookie, target.userID, forged, 400},
		{"stale grantorGrantRef", ownerCookie, target.userID, stale, 409},
		{"grant key for other subject", ownerCookie, target.userID, wrongSubject, 400},
		{"malformed signature", ownerCookie, target.userID, shortSig, 400},
		{"unknown role", ownerCookie, target.userID, badRole, 400},
		{"role unchanged", ownerCookie, target.userID, sameRole, 400},
		{"self change", ownerCookie, owner.userID, self, 400},
		{"ambassador is not admin", ambCookie, target.userID, signedRoleRequest(t, amb, gid, target.userID, "admin", "GRANT#"+amb.userID+"#2026-01-01#0000000000000000"), 403},
		{"non-member caller", strangerCookie, target.userID, signedRoleRequest(t, stranger, gid, target.userID, "admin", "x"), 404},
		{"subject not a member", ownerCookie, stranger.userID, signedRoleRequest(t, owner, gid, stranger.userID, "member", root), 404},
		{"malformed subject id", ownerCookie, "nope", good(), 404},
	}

	for _, tc := range cases {
		if rec := doChangeRole(t, h, tc.cookie, gid, tc.subj, tc.req); rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d, body: %s", tc.name, rec.Code, tc.want, rec.Body.String())
		}
	}
	// Nothing above may have changed the target or written a grant.
	if got := strAttr(getRow(t, "GROUP#"+gid, "MEMBER#"+target.userID), "Role"); got != "member" {
		t.Errorf("target role = %q after rejected requests", got)
	}

	// Replaying a successful request's sort key is a conflict, not a second grant.
	ok := good()
	if rec := doChangeRole(t, h, ownerCookie, gid, target.userID, ok); rec.Code != http.StatusOK {
		t.Fatalf("good request: %d %s", rec.Code, rec.Body.String())
	}
	back := signedRoleRequest(t, owner, gid, target.userID, "member", root)
	back.GrantSortKey = ok.GrantSortKey // reuse the taken address
	sig, _ := crypto.Sign(owner.signPriv, crypto.ContextRoleGrant, crypto.RoleGrantPayload(gid, target.userID, "member", back.GrantSortKey, root))
	back.Signature = base64.StdEncoding.EncodeToString(sig)
	rec := doChangeRole(t, h, ownerCookie, gid, target.userID, back)
	if rec.Code != http.StatusConflict {
		t.Errorf("reused grant sort key: %d, want 409, body: %s", rec.Code, rec.Body.String())
	}
}

func TestChangeRoleRequiresSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	if rec := doChangeRole(t, h, nil, "3f0c7a52-1111-4222-8333-444455556666", "3f0c7a52-1111-4222-8333-444455556667", changeRoleRequest{}); rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", rec.Code)
	}
}
