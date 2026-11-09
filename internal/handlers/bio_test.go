package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pwntato/undergroundbb/internal/config"
)

func putBioReq(t *testing.T, h *Handler, cookie *http.Cookie, bio string) int {
	t.Helper()
	return doJSON(t, h, http.MethodPut, "/api/account/bio", cookie, map[string]string{"bio": bio}).Code
}

func readProjection(t *testing.T, h *Handler, cookie *http.Cookie, id string) userProjection {
	t.Helper()
	rec := doGetUser(t, h, cookie, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("get user = %d: %s", rec.Code, rec.Body.String())
	}
	var got userProjection
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestPutBioRequiresSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	if code := putBioReq(t, h, nil, "hello"); code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

func TestPutBioIsServedToOtherUsersAndCanBeCleared(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	author, authorCookie := loggedInUser(t, h)
	_, viewerCookie := loggedInUser(t, h)

	if code := putBioReq(t, h, authorCookie, "  Hello there\nsecond line  "); code != http.StatusOK {
		t.Fatalf("put = %d", code)
	}
	got := readProjection(t, h, viewerCookie, author.userID)
	if got.Bio != "Hello there\nsecond line" {
		t.Errorf("bio = %q, want it trimmed and served", got.Bio)
	}
	if want := time.Now().UTC().Format("2006-01-02"); got.CreatedDay != want {
		t.Errorf("createdDay = %q, want today %q", got.CreatedDay, want)
	}

	if code := putBioReq(t, h, authorCookie, "   "); code != http.StatusOK {
		t.Fatalf("clear = %d", code)
	}
	if got := readProjection(t, h, viewerCookie, author.userID); got.Bio != "" {
		t.Errorf("bio after clearing = %q, want empty", got.Bio)
	}
}

func TestPutBioRefusesBadText(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	if code := putBioReq(t, h, cookie, "keep me"); code != http.StatusOK {
		t.Fatalf("seed = %d", code)
	}
	for name, bio := range map[string]string{
		"too many characters": strings.Repeat("a", MaxBioRunes+1),
		"too many bytes":      strings.Repeat("😀", MaxBioRunes),
		"control character":   "bell\x07",
		"escape":              "\x1b[31mred",
	} {
		if code := putBioReq(t, h, cookie, bio); code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, code)
		}
	}
	if got := readProjection(t, h, cookie, user.userID); got.Bio != "keep me" {
		t.Errorf("a refused bio changed the stored one: %q", got.Bio)
	}
	if code := putBioReq(t, h, cookie, strings.Repeat("é", MaxBioRunes)); code != http.StatusOK {
		t.Errorf("a bio at the character cap = %d, want 200", code)
	}
}

// A tab is easy to paste and renders fine, so it is allowed with newline.
func TestPutBioAllowsTabsAndTrimsABOMLikeTheBrowser(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	if code := putBioReq(t, h, cookie, "col1\tcol2"); code != http.StatusOK {
		t.Fatalf("tab = %d, want 200", code)
	}
	if got := readProjection(t, h, cookie, user.userID); got.Bio != "col1\tcol2" {
		t.Errorf("bio = %q, want the tab kept", got.Bio)
	}
	// JS trim() strips U+FEFF, so the web counts this as 280 characters; the
	// server must agree rather than count 281 and refuse it.
	bom := "\uFEFF" + strings.Repeat("a", MaxBioRunes)
	if code := putBioReq(t, h, cookie, bom); code != http.StatusOK {
		t.Fatalf("BOM + %d characters = %d, want 200", MaxBioRunes, code)
	}
	if got := readProjection(t, h, cookie, user.userID); got.Bio != strings.Repeat("a", MaxBioRunes) {
		t.Errorf("stored bio still has the BOM or lost characters: %d bytes", len(got.Bio))
	}
}

func TestDeletedAccountLosesBioAndCannotWriteOne(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	_, viewerCookie := loggedInUser(t, h)
	if code := putBioReq(t, h, cookie, "about me"); code != http.StatusOK {
		t.Fatalf("put = %d", code)
	}
	if rec := doDeleteAccount(t, h, cookie); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body.String())
	}
	got := readProjection(t, h, viewerCookie, user.userID)
	if got.Bio != "" || got.CreatedDay != "" || !got.Deleted {
		t.Errorf("tombstone projection = bio %q createdDay %q deleted %v, want none of it", got.Bio, got.CreatedDay, got.Deleted)
	}
	if code := putBioReq(t, h, cookie, "back from the dead"); code != http.StatusNotFound {
		t.Errorf("stale-cookie put = %d, want 404", code)
	}
	if got := readProjection(t, h, viewerCookie, user.userID); got.Bio != "" {
		t.Errorf("a deleted account got a bio: %q", got.Bio)
	}
}

// The JSON decoder turns invalid UTF-8 into U+FFFD before the handler sees it,
// so the byte check in validBio cannot be reached through the endpoint; it is a
// guard for any other caller, tested directly.
func TestValidBioRefusesInvalidUTF8(t *testing.T) {
	if validBio("bad\xff") {
		t.Error("validBio accepted invalid UTF-8")
	}
	if !validBio("fine\nnewline") {
		t.Error("validBio refused a newline")
	}
}
