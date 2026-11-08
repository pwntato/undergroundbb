package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

// The public group directory (#71). The index is shared by every public group in the table, so each
// test searches under a name prefix of its own.

func createNamedPublicGroup(t *testing.T, h *Handler, user registeredUser, cookie *http.Cookie, name, description string) string {
	t.Helper()
	req := signedCreateGroupRequest(t, user)
	req.Visibility = "public"
	req.NameCiphertext, req.DescriptionCiphertext = wrappedBlob{}, wrappedBlob{}
	req.NamePlaintext, req.DescriptionPlaintext = name, description
	req.RevocationMode = "open"
	if rec := doCreateGroup(t, h, cookie, req); rec.Code != http.StatusCreated {
		t.Fatalf("create public group: %d %s", rec.Code, rec.Body.String())
	}
	return req.GroupID
}

func uniquePrefix(t *testing.T) string {
	t.Helper()
	id, err := idgen.UUID()
	if err != nil {
		t.Fatal(err)
	}
	return id + "-"
}

func directoryGet(t *testing.T, h *Handler, cookie *http.Cookie, q url.Values) (int, directoryResponse) {
	t.Helper()
	rec := doJSON(t, h, http.MethodGet, "/api/groups/public?"+q.Encode(), cookie, nil)
	var resp directoryResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v: %s", err, rec.Body.String())
		}
	}
	return rec.Code, resp
}

func TestDirectoryRequiresASession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	if code, _ := directoryGet(t, h, nil, url.Values{}); code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", code)
	}
}

func TestDirectoryListsPublicGroupsOnlyAndShowsDuplicateNames(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	admin, cookie := loggedInUser(t, h)
	p := uniquePrefix(t)
	g1 := createNamedPublicGroup(t, h, admin, cookie, p+"Book Club", "We read")
	g2 := createNamedPublicGroup(t, h, admin, cookie, p+"Book Club", "We also read")
	// A private group has no directory entry at all, whatever it is called.
	priv := signedCreateGroupRequest(t, admin)
	if rec := doCreateGroup(t, h, cookie, priv); rec.Code != http.StatusCreated {
		t.Fatalf("create private group: %d %s", rec.Code, rec.Body.String())
	}

	// Another user, who is in none of these groups, sees them.
	_, other := loggedInUser(t, h)
	code, resp := directoryGet(t, h, other, url.Values{"q": {p}})
	if code != http.StatusOK || len(resp.Groups) != 2 {
		t.Fatalf("status %d groups %+v", code, resp.Groups)
	}
	seen := map[string]string{}
	for _, g := range resp.Groups {
		if g.Name != p+"Book Club" {
			t.Errorf("name = %q", g.Name)
		}
		seen[g.GroupID] = g.Description
	}
	if seen[g1] != "We read" || seen[g2] != "We also read" {
		t.Errorf("entries = %v, want %s and %s", seen, g1, g2)
	}
	// Nothing about the group beyond its id, name and description crosses the wire.
	rec := doJSON(t, h, http.MethodGet, "/api/groups/public?q="+url.QueryEscape(p), other, nil)
	for _, leaked := range []string{"role", "member", "wrappedGroupKey", "creator", priv.GroupID} {
		if strings.Contains(strings.ToLower(rec.Body.String()), strings.ToLower(leaked)) {
			t.Errorf("response mentions %q: %s", leaked, rec.Body.String())
		}
	}
}

func TestDirectoryPagesAndSearchesByPrefix(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	admin, cookie := loggedInUser(t, h)
	p := uniquePrefix(t)
	for _, n := range []string{"a", "b", "c"} {
		createNamedPublicGroup(t, h, admin, cookie, p+n, "")
	}
	code, first := directoryGet(t, h, cookie, url.Values{"q": {p}, "limit": {"2"}})
	if code != http.StatusOK || len(first.Groups) != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %d %+v", code, first)
	}
	code, second := directoryGet(t, h, cookie, url.Values{"q": {p}, "limit": {"2"}, "cursor": {first.NextCursor}})
	if code != http.StatusOK || len(second.Groups) != 1 || second.NextCursor != "" || second.Groups[0].Name != p+"c" {
		t.Errorf("second page = %d %+v", code, second)
	}
	if _, narrowed := directoryGet(t, h, cookie, url.Values{"q": {p + "b"}}); len(narrowed.Groups) != 1 || narrowed.Groups[0].Name != p+"b" {
		t.Errorf("prefix b = %+v", narrowed.Groups)
	}
}

// A prefix longer than any name can be is not an error: nothing matches, and the screen says so. The
// cursor is not looked at either, since no page of it could exist.
func TestDirectoryOverLongQueryIsAnEmptyPage(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	_, cookie := loggedInUser(t, h)
	gid, _ := idgen.UUID()
	long := strings.Repeat("a", maxGroupNameLen+1)
	for name, q := range map[string]url.Values{
		"no cursor":   {"q": {long}},
		"with cursor": {"q": {long}, "cursor": {"NAME#" + long + "#" + gid}},
	} {
		code, resp := directoryGet(t, h, cookie, q)
		if code != http.StatusOK || len(resp.Groups) != 0 || resp.NextCursor != "" {
			t.Errorf("%s: got %d %+v, want 200 and an empty page", name, code, resp)
		}
	}
	if code, _ := directoryGet(t, h, cookie, url.Values{"q": {strings.Repeat("a", maxGroupNameLen)}}); code != http.StatusOK {
		t.Errorf("exactly maxGroupNameLen bytes: status = %d, want 200", code)
	}
}

func TestDirectoryRefusesBadInput(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	_, cookie := loggedInUser(t, h)
	gid, _ := idgen.UUID()
	cases := map[string]url.Values{
		"limit zero":         {"limit": {"0"}},
		"limit too big":      {"limit": {"51"}},
		"limit not a number": {"limit": {"x"}},
		"query not utf8":     {"q": {"\xff\xfe"}},
		"cursor garbage":     {"cursor": {"garbage"}},
		"cursor wrong range": {"q": {"Zed"}, "cursor": {"NAME#Abe#" + gid}},
	}
	for name, q := range cases {
		if code, _ := directoryGet(t, h, cookie, q); code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, code)
		}
	}
}
