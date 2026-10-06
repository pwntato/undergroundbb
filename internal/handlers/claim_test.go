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
	"github.com/pwntato/undergroundbb/internal/db"
)

func daysAgo(n int) time.Time { return time.Now().UTC().AddDate(0, 0, -n) }

func s(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

// ageRootGrant moves the creator's root grant (row, MEMBER# pointer and META
// pointer) to a day long ago, so a designation dated between then and now has
// no grant to the admin inside its window. The signature is not re-made: the
// server never re-verifies a stored grant.
func ageRootGrant(t *testing.T, gid string, owner registeredUser, n int) string {
	t.Helper()
	ctx := context.Background()
	old := rootRef(t, gid, owner)
	row := getRow(t, "GROUP#"+gid, old)
	if row == nil {
		t.Fatalf("no root grant row at %s", old)
	}
	ref := testGrantSortKey(t, owner.userID, daysAgo(n))
	row["SK"] = s(ref)
	tbl := aws.String(testTableName())
	if _, err := rawDDB(t).PutItem(ctx, &dynamodb.PutItemInput{TableName: tbl, Item: row}); err != nil {
		t.Fatal(err)
	}
	if _, err := rawDDB(t).DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: tbl, Key: map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s(old)}}); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"MEMBER#" + owner.userID, "META"} {
		attr := "GrantSortKey"
		if key == "META" {
			attr = "RootGrantSortKey"
		}
		if _, err := rawDDB(t).UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName: tbl, Key: map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s(key)},
			UpdateExpression:          aws.String("SET " + attr + " = :r"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":r": s(ref)},
		}); err != nil {
			t.Fatal(err)
		}
	}
	return ref
}

func setUserField(t *testing.T, userID, expr string, vals map[string]types.AttributeValue) {
	t.Helper()
	in := &dynamodb.UpdateItemInput{
		TableName:        aws.String(testTableName()),
		Key:              map[string]types.AttributeValue{"PK": s("USER#" + userID), "SK": s("PROFILE")},
		UpdateExpression: aws.String(expr),
	}
	if vals != nil {
		in.ExpressionAttributeValues = vals
	}
	if _, err := rawDDB(t).UpdateItem(context.Background(), in); err != nil {
		t.Fatal(err)
	}
}

func setLastLogin(t *testing.T, userID string, day time.Time) {
	t.Helper()
	setUserField(t, userID, "SET LastLoginDay = :d", map[string]types.AttributeValue{":d": s(day.Format(dayLayout))})
}

func setMemberField(t *testing.T, gid, userID, attr, val string) {
	t.Helper()
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:                 aws.String(testTableName()),
		Key:                       map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s("MEMBER#" + userID)},
		UpdateExpression:          aws.String("SET #a = :v"),
		ExpressionAttributeNames:  map[string]string{"#a": attr},
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": s(val)},
	}); err != nil {
		t.Fatal(err)
	}
}

// seedDesignation writes a DESIGNATION# row dated day through the db layer (the
// PUT handler only accepts today). The signature is a placeholder: the server
// verified it at PUT time and never re-verifies a stored row.
func seedDesignation(t *testing.T, h *Handler, gid string, admin registeredUser, successorID string, period int, day time.Time, ref string) string {
	t.Helper()
	sk := testDesignationSortKey(t, admin.userID, day)
	err := h.db.PutDesignation(context.Background(), db.PutDesignationInput{
		GroupID: gid, AdminUserID: admin.userID, SortKey: sk, SuccessorUserID: successorID,
		PeriodDays: period, AdminGrantRef: ref, AdminHasStoredGrant: true, Signature: make([]byte, 64),
	})
	if err != nil {
		t.Fatalf("seed designation: %v", err)
	}
	return sk
}

func signedClaim(t *testing.T, succ registeredUser, gid, designationSK string, day time.Time) claimDesignationRequest {
	t.Helper()
	claimSK := testGrantSortKey(t, succ.userID, day)
	sig, err := crypto.Sign(succ.signPriv, crypto.ContextSuccessorClaim,
		crypto.SuccessorClaimPayload(gid, succ.userID, designationSK, claimSK))
	if err != nil {
		t.Fatal(err)
	}
	return claimDesignationRequest{
		DesignationSortKey: designationSK, ClaimSortKey: claimSK,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
}

func doClaim(t *testing.T, h *Handler, cookie *http.Cookie, gid string, req claimDesignationRequest) *httptest.ResponseRecorder {
	t.Helper()
	return doGroupRequest(t, h, cookie, http.MethodPost, gid+"/designation/claim", req)
}

// claimWorld is an abandoned group: an admin whose root grant and last login
// are long past, a member bob who joined before the designation, and a 90 day
// designation of bob dated 100 days ago.
type claimWorld struct {
	h           *Handler
	gid         string
	owner       registeredUser
	bob         registeredUser
	bobCookie   *http.Cookie
	ownerCookie *http.Cookie
	ref         string
	designation string
}

func newClaimWorld(t *testing.T) claimWorld {
	t.Helper()
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob, bobCookie := loggedInUser(t, h)
	addMember(t, gid, bob, "member")
	setMemberField(t, gid, bob.userID, "CreatedAt", daysAgo(200).Format(time.RFC3339))
	ref := ageRootGrant(t, gid, owner, 200)
	setLastLogin(t, owner.userID, daysAgo(100))
	sk := seedDesignation(t, h, gid, owner, bob.userID, 90, daysAgo(100), ref)
	return claimWorld{h, gid, owner, bob, bobCookie, ownerCookie, ref, sk}
}

func (w claimWorld) claim(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	return doClaim(t, w.h, w.bobCookie, w.gid, signedClaim(t, w.bob, w.gid, w.designation, time.Now()))
}

func (w claimWorld) assertRefused(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status || (code != "" && errCode(t, rec) != code) {
		t.Fatalf("status = %d code %q, want %d %q: %s", rec.Code, errCode(t, rec), status, code, rec.Body.String())
	}
	if got := memberRole(t, w.gid, w.bob.userID); got != "member" {
		t.Fatalf("a refused claim changed bob's role to %q", got)
	}
}

func TestClaimDesignationPromotesTheSuccessor(t *testing.T) {
	w := newClaimWorld(t)
	req := signedClaim(t, w.bob, w.gid, w.designation, time.Now())
	rec := doClaim(t, w.h, w.bobCookie, w.gid, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", rec.Code, rec.Body.String())
	}
	row := getRow(t, "GROUP#"+w.gid, req.ClaimSortKey)
	if row == nil {
		t.Fatal("claim row not written")
	}
	want := map[string]string{
		"SubjectUserID": w.bob.userID, "GrantedRole": "admin", "GrantorUserID": w.owner.userID,
		"GrantorGrantRef": w.ref, "ViaDesignation": w.designation, "Type": "RoleGrant",
	}
	for k, v := range want {
		if strAttr(row, k) != v {
			t.Errorf("%s = %q, want %q", k, strAttr(row, k), v)
		}
	}
	if sig, ok := row["Signature"].(*types.AttributeValueMemberB); !ok || base64.StdEncoding.EncodeToString(sig.Value) != req.Signature {
		t.Error("the row does not carry the successor's signature")
	}
	if _, has := row["CreatedAt"]; has {
		t.Error("claim row carries CreatedAt; the sort key already carries the day (#147)")
	}
	if memberRole(t, w.gid, w.bob.userID) != "admin" {
		t.Error("bob is not admin")
	}
	if got := strAttr(getRow(t, "GROUP#"+w.gid, "MEMBER#"+w.bob.userID), "GrantSortKey"); got != req.ClaimSortKey {
		t.Errorf("bob's current grant = %q, want the claim", got)
	}
	if memberRole(t, w.gid, w.owner.userID) != "admin" {
		t.Error("the original admin lost their role; nothing is revoked")
	}
}

func TestClaimedRowIsServedWithViaDesignation(t *testing.T) {
	w := newClaimWorld(t)
	req := signedClaim(t, w.bob, w.gid, w.designation, time.Now())
	if rec := doClaim(t, w.h, w.bobCookie, w.gid, req); rec.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", rec.Code, rec.Body.String())
	}
	rec := doGroupRequest(t, w.h, w.ownerCookie, http.MethodGet, w.gid+"/grants", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("grants: %d", rec.Code)
	}
	var resp listGrantsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range resp.Grants {
		if g.SortKey == req.ClaimSortKey {
			found = true
			if g.ViaDesignation != w.designation || g.GrantorUserID != w.owner.userID {
				t.Errorf("served claim row: %+v", g)
			}
		} else if g.ViaDesignation != "" {
			t.Errorf("an ordinary grant is served with viaDesignation: %+v", g)
		}
	}
	if !found {
		t.Fatal("claim row not served")
	}
}

func TestClaimDesignationRefusals(t *testing.T) {
	type tc struct {
		name   string
		setup  func(t *testing.T, w *claimWorld)
		status int
		code   string
	}
	cases := []tc{
		{"another designation by the admin since", func(t *testing.T, w *claimWorld) {
			seedDesignation(t, w.h, w.gid, w.owner, w.bob.userID, 90, daysAgo(50), w.ref)
		}, http.StatusConflict, "designation_superseded"},
		{"a revocation since", func(t *testing.T, w *claimWorld) {
			seedDesignation(t, w.h, w.gid, w.owner, "", 90, daysAgo(10), w.ref)
		}, http.StatusConflict, "designation_superseded"},
		{"a same-day second designation cancels it", func(t *testing.T, w *claimWorld) {
			seedDesignation(t, w.h, w.gid, w.owner, w.bob.userID, 90, daysAgo(100), w.ref)
		}, http.StatusConflict, "designation_superseded"},
		{"the admin's own role changed since", func(t *testing.T, w *claimWorld) {
			putRaw(t, w.gid, testGrantSortKey(t, w.owner.userID, daysAgo(40)), map[string]types.AttributeValue{
				"SubjectUserID": s(w.owner.userID), "GrantedRole": s("member"), "GrantorUserID": s(w.owner.userID)})
		}, http.StatusConflict, "designation_lapsed"},
		{"a grant to the admin on the designation's own day", func(t *testing.T, w *claimWorld) {
			putRaw(t, w.gid, testGrantSortKey(t, w.owner.userID, daysAgo(100)), map[string]types.AttributeValue{
				"SubjectUserID": s(w.owner.userID), "GrantedRole": s("admin"), "GrantorUserID": s(w.owner.userID)})
		}, http.StatusConflict, "designation_lapsed"},
		{"already used", func(t *testing.T, w *claimWorld) {
			carol := registerTestUser(t, w.h)
			putRaw(t, w.gid, testGrantSortKey(t, carol.userID, daysAgo(5)), map[string]types.AttributeValue{
				"SubjectUserID": s(carol.userID), "GrantedRole": s("admin"), "GrantorUserID": s(w.owner.userID),
				"ViaDesignation": s(w.designation)})
		}, http.StatusConflict, "already_claimed"},
		{"the admin's current grant is no longer the one signed", func(t *testing.T, w *claimWorld) {
			setMemberField(t, w.gid, w.owner.userID, "GrantSortKey", testGrantSortKey(t, w.owner.userID, daysAgo(30)))
		}, http.StatusConflict, "admin_changed"},
		{"the admin is no longer an admin", func(t *testing.T, w *claimWorld) {
			setMemberField(t, w.gid, w.owner.userID, "Role", "member")
		}, http.StatusConflict, "admin_changed"},
		{"the designation predates joining", func(t *testing.T, w *claimWorld) {
			setMemberField(t, w.gid, w.bob.userID, "CreatedAt", daysAgo(50).Format(time.RFC3339))
		}, http.StatusConflict, "designation_before_join"},
		{"the admin logged in within the period", func(t *testing.T, w *claimWorld) {
			setLastLogin(t, w.owner.userID, daysAgo(30))
		}, http.StatusConflict, "not_inactive"},
		{"another admin logged in within the period", func(t *testing.T, w *claimWorld) {
			carol := registerTestUser(t, w.h)
			addMember(t, w.gid, carol, "admin")
			setLastLogin(t, carol.userID, daysAgo(10))
		}, http.StatusConflict, "not_inactive"},
		{"the period has not elapsed since the designation", func(t *testing.T, w *claimWorld) {
			// Both logins are long ago, so only the designation's day (40 days
			// ago) starts the clock: not inactive for 90 days yet.
			setLastLogin(t, w.owner.userID, daysAgo(200))
			old := w.designation
			w.designation = seedDesignation(t, w.h, w.gid, w.owner, w.bob.userID, 90, daysAgo(40), w.ref)
			deleteRaw(t, w.gid, old)
		}, http.StatusConflict, "not_inactive"},
		{"you are already an admin", func(t *testing.T, w *claimWorld) {
			setMemberField(t, w.gid, w.bob.userID, "Role", "admin")
		}, http.StatusConflict, "already_admin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newClaimWorld(t)
			c.setup(t, &w)
			rec := w.claim(t)
			if c.code == "already_admin" {
				if rec.Code != c.status || errCode(t, rec) != c.code {
					t.Fatalf("status = %d code %q: %s", rec.Code, errCode(t, rec), rec.Body.String())
				}
				return
			}
			w.assertRefused(t, rec, c.status, c.code)
		})
	}
}

func putRaw(t *testing.T, gid, sk string, attrs map[string]types.AttributeValue) {
	t.Helper()
	item := map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s(sk), "Type": s("RoleGrant")}
	for k, v := range attrs {
		item[k] = v
	}
	if _, err := rawDDB(t).PutItem(context.Background(), &dynamodb.PutItemInput{TableName: aws.String(testTableName()), Item: item}); err != nil {
		t.Fatal(err)
	}
}

func deleteRaw(t *testing.T, gid, sk string) {
	t.Helper()
	if _, err := rawDDB(t).DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
		TableName: aws.String(testTableName()),
		Key:       map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s(sk)},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestClaimDesignationIgnoresAnotherAdminWhoIsInactive(t *testing.T) {
	w := newClaimWorld(t)
	carol := registerTestUser(t, w.h)
	addMember(t, w.gid, carol, "admin")
	setLastLogin(t, carol.userID, daysAgo(200))
	if rec := w.claim(t); rec.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", rec.Code, rec.Body.String())
	}
}

// The period is measured from the later of the last login and the designation
// day to the claim's signed day, and "at least periodDays" is inclusive.
func TestClaimDesignationPeriodBoundary(t *testing.T) {
	for _, tc := range []struct {
		name     string
		daysAgo  int
		wantCode int
	}{
		{"exactly the period", 90, http.StatusOK},
		{"one day short", 89, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newClaimWorld(t)
			old := w.designation
			setLastLogin(t, w.owner.userID, daysAgo(200))
			w.designation = seedDesignation(t, w.h, w.gid, w.owner, w.bob.userID, 90, daysAgo(tc.daysAgo), w.ref)
			deleteRaw(t, w.gid, old)
			rec := w.claim(t)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantCode, rec.Body.String())
			}
		})
	}
}

// The gate measures to the claim's SIGNED day, from the later of the last
// login and the designation's day. The handler only accepts a signed day within
// a couple of hours of midnight, so the arithmetic is pinned directly.
func TestInactiveFor(t *testing.T) {
	day := func(n int) time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, n) }
	period := 90 * 24 * time.Hour
	cases := []struct {
		name         string
		claim, desig time.Time
		lastLogin    string
		want         bool
	}{
		{"exactly the period from the designation", day(90), day(0), "", true},
		{"a day short", day(89), day(0), "", false},
		{"signed yesterday: judged by yesterday", day(89), day(0), "", false},
		{"an old login does not start the clock before the designation", day(90), day(0), day(-50).Format(dayLayout), true},
		{"a login after the designation does", day(90), day(0), day(10).Format(dayLayout), false},
		{"exactly the period from the login", day(100), day(0), day(10).Format(dayLayout), true},
		{"a login the day before the designation does not delay it", day(90), day(0), day(-1).Format(dayLayout), true},
		{"a malformed login day counts as never", day(90), day(0), "yesterday", true},
		{"a login after the claim day delays it", day(90), day(0), day(91).Format(dayLayout), false},
	}
	for _, c := range cases {
		if got := inactiveFor(c.claim, c.desig, c.lastLogin, period); got != c.want {
			t.Errorf("%s: inactiveFor = %v, want %v", c.name, got, c.want)
		}
	}
}

// A designation fires at most once: after the successor is demoted again, the
// same designation cannot re-promote them.
func TestClaimDesignationFiresOnlyOnce(t *testing.T) {
	w := newClaimWorld(t)
	if rec := w.claim(t); rec.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", rec.Code, rec.Body.String())
	}
	setMemberField(t, w.gid, w.bob.userID, "Role", "member")
	w.assertRefused(t, w.claim(t), http.StatusConflict, "already_claimed")
}

func TestClaimDesignationRefusesTheWrongCaller(t *testing.T) {
	w := newClaimWorld(t)
	carol, carolCookie := loggedInUser(t, w.h)
	addMember(t, w.gid, carol, "member")
	setMemberField(t, w.gid, carol.userID, "CreatedAt", daysAgo(200).Format(time.RFC3339))
	// Carol signs and sends a claim of Bob's designation.
	rec := doClaim(t, w.h, carolCookie, w.gid, signedClaim(t, carol, w.gid, w.designation, time.Now()))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "designation_not_yours" {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if memberRole(t, w.gid, carol.userID) != "member" {
		t.Error("carol was promoted by bob's designation")
	}
}

func TestClaimDesignationRefusesARevocation(t *testing.T) {
	w := newClaimWorld(t)
	deleteRaw(t, w.gid, w.designation)
	w.designation = seedDesignation(t, w.h, w.gid, w.owner, "", 90, daysAgo(100), w.ref)
	w.assertRefused(t, w.claim(t), http.StatusConflict, "designation_not_yours")
}

func TestClaimDesignationBadInput(t *testing.T) {
	w := newClaimWorld(t)
	good := signedClaim(t, w.bob, w.gid, w.designation, time.Now())
	resign := func(r *claimDesignationRequest) {
		sig, _ := crypto.Sign(w.bob.signPriv, crypto.ContextSuccessorClaim,
			crypto.SuccessorClaimPayload(w.gid, w.bob.userID, r.DesignationSortKey, r.ClaimSortKey))
		r.Signature = base64.StdEncoding.EncodeToString(sig)
	}
	cases := []struct {
		name   string
		mutate func(r *claimDesignationRequest)
		status int
		code   string
	}{
		{"malformed designation key", func(r *claimDesignationRequest) { r.DesignationSortKey = "DESIGNATION#nope"; resign(r) }, 400, ""},
		{"claim key for someone else", func(r *claimDesignationRequest) {
			r.ClaimSortKey = testGrantSortKey(t, w.owner.userID, time.Now())
			resign(r)
		}, 400, ""},
		{"claim day far in the past", func(r *claimDesignationRequest) {
			r.ClaimSortKey = testGrantSortKey(t, w.bob.userID, daysAgo(5))
			resign(r)
		}, 400, ""},
		{"claim day in the future", func(r *claimDesignationRequest) {
			r.ClaimSortKey = testGrantSortKey(t, w.bob.userID, time.Now().AddDate(0, 0, 5))
			resign(r)
		}, 400, ""},
		{"malformed signature", func(r *claimDesignationRequest) { r.Signature = "!!" }, 400, ""},
		{"signed for a different designation", func(r *claimDesignationRequest) {
			other := w.designation[:len(w.designation)-1] + "0"
			sig, _ := crypto.Sign(w.bob.signPriv, crypto.ContextSuccessorClaim,
				crypto.SuccessorClaimPayload(w.gid, w.bob.userID, other, r.ClaimSortKey))
			r.Signature = base64.StdEncoding.EncodeToString(sig)
		}, 400, ""},
		{"signed by someone else", func(r *claimDesignationRequest) {
			sig, _ := crypto.Sign(w.owner.signPriv, crypto.ContextSuccessorClaim,
				crypto.SuccessorClaimPayload(w.gid, w.bob.userID, r.DesignationSortKey, r.ClaimSortKey))
			r.Signature = base64.StdEncoding.EncodeToString(sig)
		}, 400, ""},
		{"signed under the role-grant context", func(r *claimDesignationRequest) {
			sig, _ := crypto.Sign(w.bob.signPriv, crypto.ContextRoleGrant,
				crypto.SuccessorClaimPayload(w.gid, w.bob.userID, r.DesignationSortKey, r.ClaimSortKey))
			r.Signature = base64.StdEncoding.EncodeToString(sig)
		}, 400, ""},
		{"no such designation", func(r *claimDesignationRequest) {
			r.DesignationSortKey = testDesignationSortKey(t, w.owner.userID, daysAgo(77))
			resign(r)
		}, 404, "designation_not_found"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := good
			c.mutate(&req)
			rec := doClaim(t, w.h, w.bobCookie, w.gid, req)
			w.assertRefused(t, rec, c.status, c.code)
			if getRow(t, "GROUP#"+w.gid, req.ClaimSortKey) != nil {
				t.Error("a refused claim wrote a row")
			}
		})
	}
	t.Run("claim key already taken", func(t *testing.T) {
		putRaw(t, w.gid, good.ClaimSortKey, map[string]types.AttributeValue{"SubjectUserID": s(w.bob.userID), "GrantedRole": s("member")})
		w.assertRefused(t, doClaim(t, w.h, w.bobCookie, w.gid, good), http.StatusConflict, "grant_key_taken")
	})
}

func TestClaimDesignationNeedsAMemberAndASession(t *testing.T) {
	w := newClaimWorld(t)
	req := signedClaim(t, w.bob, w.gid, w.designation, time.Now())
	if rec := doClaim(t, w.h, nil, w.gid, req); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", rec.Code)
	}
	out, outCookie := loggedInUser(t, w.h)
	rec := doClaim(t, w.h, outCookie, w.gid, signedClaim(t, out, w.gid, w.designation, time.Now()))
	if rec.Code != http.StatusNotFound {
		t.Errorf("non-member: %d, want 404", rec.Code)
	}
	w.assertRefused(t, doClaim(t, w.h, w.bobCookie, "not-a-uuid", req), http.StatusNotFound, "")
}

func TestClaimDesignationRefusesADeletedSuccessor(t *testing.T) {
	w := newClaimWorld(t)
	tombstoneProfile(t, w.bob.userID)
	rec := w.claim(t)
	if rec.Code != http.StatusGone || errCode(t, rec) != "subject_deleted" {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	w.assertRefused(t, rec, http.StatusGone, "subject_deleted")
}
