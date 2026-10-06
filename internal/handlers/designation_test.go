package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

func testDesignationSortKey(t *testing.T, adminUUID string, day time.Time) string {
	t.Helper()
	suffix, err := idgen.DaySuffix(day)
	if err != nil {
		t.Fatal(err)
	}
	return "DESIGNATION#" + adminUUID + "#" + suffix
}

// signedDesignation signs a designation dated today by admin, naming successorID
// (empty to revoke) against adminRef.
func signedDesignation(t *testing.T, admin registeredUser, groupID, successorID string, periodDays int, adminRef string) putDesignationRequest {
	t.Helper()
	sk := testDesignationSortKey(t, admin.userID, time.Now())
	sig, err := crypto.Sign(admin.signPriv, crypto.ContextSuccessorDesignation,
		crypto.SuccessorDesignationPayload(groupID, admin.userID, successorID, periodDays, sk, adminRef))
	if err != nil {
		t.Fatal(err)
	}
	return putDesignationRequest{
		DesignationSortKey: sk,
		SuccessorUserID:    successorID,
		PeriodDays:         periodDays,
		AdminGrantRef:      adminRef,
		Signature:          base64.StdEncoding.EncodeToString(sig),
	}
}

func doPutDesignation(t *testing.T, h *Handler, cookie *http.Cookie, groupID string, req putDesignationRequest) *httptest.ResponseRecorder {
	t.Helper()
	return doGroupRequest(t, h, cookie, http.MethodPut, groupID+"/designation", req)
}

func doListDesignations(t *testing.T, h *Handler, cookie *http.Cookie, groupID, query string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/groups/"+groupID+"/designations"+query, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func TestPutDesignationAppendsASignedRow(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob := registerTestUser(t, h)
	addMember(t, gid, bob, "member")

	req := signedDesignation(t, owner, gid, bob.userID, 90, backdatedRef(t, gid, owner))
	rec := doPutDesignation(t, h, ownerCookie, gid, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put designation: %d %s", rec.Code, rec.Body.String())
	}
	row := getRow(t, "GROUP#"+gid, req.DesignationSortKey)
	if row == nil {
		t.Fatal("designation row not written")
	}
	if strAttr(row, "AdminUserID") != owner.userID || strAttr(row, "SuccessorUserID") != bob.userID ||
		strAttr(row, "AdminGrantRef") != req.AdminGrantRef || strAttr(row, "Type") != "SuccessorDesignation" {
		t.Errorf("row: %v", row)
	}
	if n, ok := row["PeriodDays"].(*types.AttributeValueMemberN); !ok || n.Value != "90" {
		t.Errorf("PeriodDays: %v", row["PeriodDays"])
	}
	if _, has := row["CreatedAt"]; has {
		t.Error("designation row carries CreatedAt; the sort key already carries the day (#147)")
	}
	if _, has := row["SigningPublicKey"]; has {
		t.Error("designation row stores a signing key; nothing signed binds one")
	}
}

func TestPutDesignationRevocationHasNoSuccessor(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)

	req := signedDesignation(t, owner, gid, "", 30, backdatedRef(t, gid, owner))
	if rec := doPutDesignation(t, h, ownerCookie, gid, req); rec.Code != http.StatusOK {
		t.Fatalf("revocation: %d %s", rec.Code, rec.Body.String())
	}
	row := getRow(t, "GROUP#"+gid, req.DesignationSortKey)
	if row == nil {
		t.Fatal("revocation row not written")
	}
	if _, has := row["SuccessorUserID"]; has {
		t.Errorf("revocation stores a successor: %v", row)
	}
}

func TestPutDesignationRejections(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob := registerTestUser(t, h)
	outsider := registerTestUser(t, h)
	gone := registerTestUser(t, h)
	addMember(t, gid, bob, "member")
	addMember(t, gid, gone, "member")
	tombstoneProfile(t, gone.userID)
	ref := backdatedRef(t, gid, owner)

	cases := []struct {
		name   string
		mutate func(r *putDesignationRequest)
		status int
		code   string
	}{
		{"period too short", func(r *putDesignationRequest) { r.PeriodDays = 29 }, http.StatusBadRequest, ""},
		{"period too long", func(r *putDesignationRequest) { r.PeriodDays = 366 }, http.StatusBadRequest, ""},
		{"yourself", func(r *putDesignationRequest) { r.SuccessorUserID = owner.userID }, http.StatusBadRequest, ""},
		{"not a uuid", func(r *putDesignationRequest) { r.SuccessorUserID = "nobody" }, http.StatusBadRequest, ""},
		{"not a member", func(r *putDesignationRequest) { r.SuccessorUserID = outsider.userID }, http.StatusBadRequest, ""},
		{"deleted member", func(r *putDesignationRequest) { r.SuccessorUserID = gone.userID }, http.StatusGone, "subject_deleted"},
		{"stale admin ref", func(r *putDesignationRequest) {
			r.AdminGrantRef = testGrantSortKey(t, owner.userID, time.Now().AddDate(0, 0, -9))
		}, http.StatusConflict, "grantor_ref_stale"},
		{"sort key for someone else", func(r *putDesignationRequest) {
			r.DesignationSortKey = testDesignationSortKey(t, bob.userID, time.Now())
		}, http.StatusBadRequest, ""},
		{"day far in the past", func(r *putDesignationRequest) {
			r.DesignationSortKey = testDesignationSortKey(t, owner.userID, time.Now().AddDate(0, 0, -5))
		}, http.StatusBadRequest, ""},
		{"malformed signature", func(r *putDesignationRequest) { r.Signature = "!!" }, http.StatusBadRequest, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Re-sign the mutated fields except where the case is about the signature itself,
			// so each case fails for its own reason and not for a stale signature.
			req := signedDesignation(t, owner, gid, bob.userID, 90, ref)
			tc.mutate(&req)
			if tc.name != "malformed signature" {
				sig, err := crypto.Sign(owner.signPriv, crypto.ContextSuccessorDesignation,
					crypto.SuccessorDesignationPayload(gid, owner.userID, req.SuccessorUserID, req.PeriodDays, req.DesignationSortKey, req.AdminGrantRef))
				if err != nil {
					t.Fatal(err)
				}
				req.Signature = base64.StdEncoding.EncodeToString(sig)
			}
			rec := doPutDesignation(t, h, ownerCookie, gid, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			if tc.code != "" && errCode(t, rec) != tc.code {
				t.Fatalf("code = %q, want %q", errCode(t, rec), tc.code)
			}
			if getRow(t, "GROUP#"+gid, req.DesignationSortKey) != nil {
				t.Fatal("a refused designation was written")
			}
		})
	}

	t.Run("signature over different fields", func(t *testing.T) {
		req := signedDesignation(t, owner, gid, bob.userID, 90, ref)
		req.PeriodDays = 365 // the admin signed 90
		rec := doPutDesignation(t, h, ownerCookie, gid, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("signed by someone else", func(t *testing.T) {
		req := signedDesignation(t, bob, gid, bob.userID, 90, ref)
		req.SuccessorUserID = bob.userID
		req.DesignationSortKey = testDesignationSortKey(t, owner.userID, time.Now())
		sig, _ := crypto.Sign(bob.signPriv, crypto.ContextSuccessorDesignation,
			crypto.SuccessorDesignationPayload(gid, owner.userID, bob.userID, 90, req.DesignationSortKey, ref))
		req.Signature = base64.StdEncoding.EncodeToString(sig)
		if rec := doPutDesignation(t, h, ownerCookie, gid, req); rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("signed under the role-grant context", func(t *testing.T) {
		req := signedDesignation(t, owner, gid, bob.userID, 90, ref)
		sig, _ := crypto.Sign(owner.signPriv, crypto.ContextRoleGrant,
			crypto.SuccessorDesignationPayload(gid, owner.userID, bob.userID, 90, req.DesignationSortKey, ref))
		req.Signature = base64.StdEncoding.EncodeToString(sig)
		if rec := doPutDesignation(t, h, ownerCookie, gid, req); rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestPutDesignationNeedsAdminAndASession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob, bobCookie := loggedInUser(t, h)
	outsider, outsiderCookie := loggedInUser(t, h)
	addMember(t, gid, bob, "member")

	req := signedDesignation(t, bob, gid, owner.userID, 90, testGrantSortKey(t, bob.userID, time.Now().AddDate(0, 0, -3)))
	if rec := doPutDesignation(t, h, bobCookie, gid, req); rec.Code != http.StatusForbidden {
		t.Errorf("plain member: %d, want 403", rec.Code)
	}
	req = signedDesignation(t, outsider, gid, owner.userID, 90, "x")
	if rec := doPutDesignation(t, h, outsiderCookie, gid, req); rec.Code != http.StatusNotFound {
		t.Errorf("non-member: %d, want 404", rec.Code)
	}
	if rec := doPutDesignation(t, h, nil, gid, req); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", rec.Code)
	}
}

// The verifier rejects a designation if the admin has a grant dated the same
// day, so the server refuses to store one (the same rule as a role change).
func TestPutDesignationRefusedWhenAdminsGrantIsDatedToday(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob := registerTestUser(t, h)
	addMember(t, gid, bob, "member")

	req := signedDesignation(t, owner, gid, bob.userID, 90, rootRef(t, gid, owner))
	rec := doPutDesignation(t, h, ownerCookie, gid, req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "grantor_granted_today" {
		t.Fatalf("status = %d, body: %s, want 409 grantor_granted_today", rec.Code, rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, req.DesignationSortKey) != nil {
		t.Error("an unverifiable designation was written")
	}
}

// Order within a day is unknowable, so a second designation the same day is
// refused, whether it names someone else or revokes the first.
func TestPutDesignationRefusesASecondOneTheSameDay(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob := registerTestUser(t, h)
	addMember(t, gid, bob, "member")
	ref := backdatedRef(t, gid, owner)

	if rec := doPutDesignation(t, h, ownerCookie, gid, signedDesignation(t, owner, gid, bob.userID, 90, ref)); rec.Code != http.StatusOK {
		t.Fatalf("first: %d %s", rec.Code, rec.Body.String())
	}
	second := signedDesignation(t, owner, gid, "", 90, ref)
	rec := doPutDesignation(t, h, ownerCookie, gid, second)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "designation_today" {
		t.Fatalf("second: %d %s, want 409 designation_today", rec.Code, rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, second.DesignationSortKey) != nil {
		t.Error("the refused second designation was written")
	}
}

func TestListDesignations(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob, bobCookie := loggedInUser(t, h)
	_, outsiderCookie := loggedInUser(t, h)
	addMember(t, gid, bob, "member")
	ref := backdatedRef(t, gid, owner)

	// Three days of designations by the owner. The handler only accepts today's
	// date, so the two older rows go in through the db layer, which is also what
	// a real group holds after a few days.
	c := testDB(t)
	var sks []string
	for i, day := range []int{-2, -1, 0} {
		sk := testDesignationSortKey(t, owner.userID, time.Now().AddDate(0, 0, day))
		succ := bob.userID
		if i == 2 {
			succ = ""
		}
		sig, _ := crypto.Sign(owner.signPriv, crypto.ContextSuccessorDesignation,
			crypto.SuccessorDesignationPayload(gid, owner.userID, succ, 60, sk, ref))
		if day < 0 {
			if err := c.PutDesignation(context.Background(), db.PutDesignationInput{
				GroupID: gid, AdminUserID: owner.userID, SortKey: sk, SuccessorUserID: succ,
				PeriodDays: 60, AdminGrantRef: ref, AdminHasStoredGrant: true, Signature: sig,
			}); err != nil {
				t.Fatalf("seed %d: %v", day, err)
			}
		} else {
			req := putDesignationRequest{DesignationSortKey: sk, SuccessorUserID: succ, PeriodDays: 60, AdminGrantRef: ref, Signature: base64.StdEncoding.EncodeToString(sig)}
			if rec := doPutDesignation(t, h, ownerCookie, gid, req); rec.Code != http.StatusOK {
				t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
			}
		}
		sks = append(sks, sk)
	}

	// Any member can read them, not only admins.
	rec := doListDesignations(t, h, bobCookie, gid, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var got listDesignationsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Designations) != 3 || got.NextCursor != "" {
		t.Fatalf("designations = %d, cursor %q", len(got.Designations), got.NextCursor)
	}
	for i, d := range got.Designations {
		if d.SortKey != sks[i] || d.AdminUserID != owner.userID || d.PeriodDays != 60 || d.AdminGrantRef != ref || d.Signature == "" {
			t.Errorf("entry %d: %+v", i, d)
		}
	}
	if got.Designations[0].SuccessorUserID != bob.userID || got.Designations[2].SuccessorUserID != "" {
		t.Errorf("successors: %q ... %q", got.Designations[0].SuccessorUserID, got.Designations[2].SuccessorUserID)
	}

	// Paging walks the same rows.
	rec = doListDesignations(t, h, bobCookie, gid, "?limit=2")
	var page1 listDesignationsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &page1)
	if len(page1.Designations) != 2 || page1.NextCursor != sks[1] {
		t.Fatalf("page 1: %d rows, cursor %q", len(page1.Designations), page1.NextCursor)
	}
	rec = doListDesignations(t, h, bobCookie, gid, "?limit=2&cursor="+page1.NextCursor)
	var page2 listDesignationsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &page2)
	if len(page2.Designations) != 1 || page2.Designations[0].SortKey != sks[2] || page2.NextCursor != "" {
		t.Fatalf("page 2: %+v", page2)
	}

	if rec := doListDesignations(t, h, outsiderCookie, gid, ""); rec.Code != http.StatusNotFound {
		t.Errorf("non-member: %d, want 404", rec.Code)
	}
	if rec := doListDesignations(t, h, nil, gid, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", rec.Code)
	}
	if rec := doListDesignations(t, h, bobCookie, gid, "?cursor=GRANT%23x"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad cursor: %d, want 400", rec.Code)
	}
	if rec := doListDesignations(t, h, bobCookie, gid, "?limit=0"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad limit: %d, want 400", rec.Code)
	}
}

// Login stamps the day of the last login, and only moves it forward.
func TestLoginRecordsLastLoginDay(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, _ := loggedInUser(t, h)
	today := time.Now().UTC().Format("2006-01-02")
	if got := strAttr(getRow(t, "USER#"+user.userID, "PROFILE"), "LastLoginDay"); got != today {
		t.Fatalf("LastLoginDay = %q, want %q", got, today)
	}

	// A later day moves it; an earlier one does not.
	c := testDB(t)
	if err := c.RecordLogin(context.Background(), user.userID, "2999-01-01"); err != nil {
		t.Fatal(err)
	}
	if err := c.RecordLogin(context.Background(), user.userID, "2000-01-01"); err != nil {
		t.Fatal(err)
	}
	if got := strAttr(getRow(t, "USER#"+user.userID, "PROFILE"), "LastLoginDay"); got != "2999-01-01" {
		t.Fatalf("LastLoginDay = %q after a later then an earlier day, want 2999-01-01", got)
	}

	// A missing profile is not an error: the condition fails, and no row is created.
	if err := c.RecordLogin(context.Background(), "00000000-0000-4000-8000-000000000000", today); err != nil {
		t.Fatalf("missing profile: %v", err)
	}
	if getRow(t, "USER#00000000-0000-4000-8000-000000000000", "PROFILE") != nil {
		t.Error("RecordLogin created a PROFILE row")
	}
}

// A login whose LastLoginDay stamp fails must fail, with no session: a missed
// stamp would make an active admin look inactive to the claim check. The write
// is failed by a proxy in front of DynamoDB Local, because db.Client exposes no
// way to reach its SDK client.
func TestLoginFailsWhenTheLastLoginStampFails(t *testing.T) {
	good := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, good)

	target, err := url.Parse(testEndpoint(t))
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	injected := 0
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if r.Header.Get("X-Amz-Target") == "DynamoDB_20120810.UpdateItem" && bytes.Contains(body, []byte("LastLoginDay")) {
			injected++
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			w.WriteHeader(http.StatusBadRequest) // not retried by the SDK
			_, _ = w.Write([]byte(`{"__type":"com.amazon.coral.validate#ValidationException","message":"injected"}`))
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer front.Close()
	c, err := db.New(context.Background(), testTableName(), front.URL)
	if err != nil {
		t.Fatal(err)
	}

	rec := completeLogin(t, New(config.FromEnv(), c), user)
	if injected == 0 {
		t.Fatal("the stamp write was never attempted, so this tested nothing")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("login = %d, want 500: %s", rec.Code, rec.Body.String())
	}
	if sessionCookieFrom(rec) != nil {
		t.Fatal("a session was issued although the stamp failed")
	}
	if got := strAttr(getRow(t, "USER#"+user.userID, "PROFILE"), "LastLoginDay"); got != "" {
		t.Errorf("LastLoginDay = %q after a failed stamp", got)
	}
}
