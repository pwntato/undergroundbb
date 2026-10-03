package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
)

func doListGrants(t *testing.T, h *Handler, cookie *http.Cookie, groupID, query string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/groups/"+groupID+"/grants"+query, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func decodeGrants(t *testing.T, rec *httptest.ResponseRecorder) listGrantsResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var resp listGrantsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestListGrantsServesAnchorAndSignedHistory(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob := registerTestUser(t, h)
	addMember(t, gid, bob, "member")
	root := rootRef(t, gid, owner)

	ownerRef := backdatedRef(t, gid, owner)
	req := signedRoleRequest(t, owner, gid, bob.userID, "admin", ownerRef)
	if rec := doChangeRole(t, h, ownerCookie, gid, bob.userID, req); rec.Code != http.StatusOK {
		t.Fatalf("promote: %d %s", rec.Code, rec.Body.String())
	}

	resp := decodeGrants(t, doListGrants(t, h, ownerCookie, gid, ""))
	enc := base64.StdEncoding.EncodeToString
	if resp.Anchor.CreatorUserID != owner.userID ||
		resp.Anchor.CreatorSigningPublicKey != enc(owner.signPub) ||
		resp.Anchor.RootGrantSortKey != root || resp.Anchor.TrustAnchorSignature == "" {
		t.Errorf("anchor = %+v", resp.Anchor)
	}
	bySK := map[string]grantEntry{}
	for _, g := range resp.Grants {
		bySK[g.SortKey] = g
	}
	if len(resp.Grants) != 2 || resp.NextCursor != "" {
		t.Fatalf("grants = %d cursor %q, want 2 and none", len(resp.Grants), resp.NextCursor)
	}
	rg, ok := bySK[root]
	if !ok || rg.SubjectUserID != owner.userID || rg.GrantorUserID != owner.userID || rg.GrantedRole != "admin" || rg.GrantorGrantRef != "" {
		t.Errorf("root grant = %+v", rg)
	}
	pg, ok := bySK[req.GrantSortKey]
	if !ok || pg.SubjectUserID != bob.userID || pg.GrantorUserID != owner.userID ||
		pg.GrantedRole != "admin" || pg.GrantorGrantRef != ownerRef ||
		pg.GrantorSigningPublicKey != enc(owner.signPub) || pg.Signature != req.Signature {
		t.Errorf("promotion grant = %+v, want the signed request's fields", pg)
	}
}

func TestListGrantsPaginates(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	bob := registerTestUser(t, h)
	addMember(t, gid, bob, "member")
	req := signedRoleRequest(t, owner, gid, bob.userID, "ambassador", backdatedRef(t, gid, owner))
	if rec := doChangeRole(t, h, ownerCookie, gid, bob.userID, req); rec.Code != http.StatusOK {
		t.Fatalf("promote: %d", rec.Code)
	}

	first := decodeGrants(t, doListGrants(t, h, ownerCookie, gid, "?limit=1"))
	if len(first.Grants) != 1 || first.NextCursor == "" {
		t.Fatalf("first page = %d grants cursor %q", len(first.Grants), first.NextCursor)
	}
	second := decodeGrants(t, doListGrants(t, h, ownerCookie, gid, "?limit=1&cursor="+first.NextCursor))
	if len(second.Grants) != 1 || second.NextCursor != "" || second.Grants[0].SortKey == first.Grants[0].SortKey {
		t.Fatalf("second page = %+v", second)
	}
	if second.Anchor != first.Anchor {
		t.Error("anchor differs between pages")
	}
}

func TestListGrantsAuthAndValidation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	pub := createPublicGroup(t, h, owner, ownerCookie)
	_, strangerCookie := loggedInUser(t, h)

	if rec := doListGrants(t, h, nil, gid, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", rec.Code)
	}
	a := doListGrants(t, h, strangerCookie, gid, "")
	b := doListGrants(t, h, strangerCookie, pub, "")
	c := doListGrants(t, h, strangerCookie, "3f0c7a52-1111-4222-8333-444455556666", "")
	if a.Code != 404 || b.Code != 404 || c.Code != 404 {
		t.Fatalf("statuses = %d %d %d, want 404 all (grant history is members-only, even for a public group)", a.Code, b.Code, c.Code)
	}
	if a.Body.String() != b.Body.String() || a.Body.String() != c.Body.String() {
		t.Error("404 bodies differ")
	}
	for _, q := range []string{"?limit=0", "?limit=201", "?limit=x", "?cursor=nope", "?cursor=GRANT%23short", "?cursor=" + "GRANT%23" + "0123456789abcdef0123456789abcdef0123"} {
		if rec := doListGrants(t, h, ownerCookie, gid, q); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", q, rec.Code)
		}
	}
}
