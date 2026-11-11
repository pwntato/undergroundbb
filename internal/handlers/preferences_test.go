package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
)

func getPrefs(t *testing.T, h *Handler, cookie *http.Cookie) preferencesResponse {
	t.Helper()
	rec := doJSON(t, h, http.MethodGet, "/api/account/preferences", cookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get preferences = %d: %s", rec.Code, rec.Body.String())
	}
	var got preferencesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func putPrefs(t *testing.T, h *Handler, cookie *http.Cookie, epoch uint64, blob wrappedBlob) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, h, http.MethodPut, "/api/account/preferences", cookie, putPreferencesRequest{ExpectedKeyEpoch: epoch, PreferencesBlob: blob})
}

func TestPreferencesRequireSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	if rec := doJSON(t, h, http.MethodGet, "/api/account/preferences", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("get without a session = %d, want 401", rec.Code)
	}
	if rec := putPrefs(t, h, nil, 0, wrappedBlob{Nonce: b64(12), Ciphertext: b64(40)}); rec.Code != http.StatusUnauthorized {
		t.Errorf("put without a session = %d, want 401", rec.Code)
	}
}

func TestPreferencesRoundTripAndOnlyOwnerReads(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	_, cookie := loggedInUser(t, h)
	_, other := loggedInUser(t, h)

	if got := getPrefs(t, h, cookie); got.PreferencesBlob != nil {
		t.Fatalf("a fresh account has a blob: %+v", got)
	}
	blob := wrappedBlob{Nonce: b64(12), Ciphertext: b64(40)}
	if rec := putPrefs(t, h, cookie, 0, blob); rec.Code != http.StatusNoContent {
		t.Fatalf("put = %d: %s", rec.Code, rec.Body.String())
	}
	got := getPrefs(t, h, cookie)
	if got.PreferencesBlob == nil || *got.PreferencesBlob != blob {
		t.Errorf("read back %+v, want %+v", got.PreferencesBlob, blob)
	}
	if o := getPrefs(t, h, other); o.PreferencesBlob != nil {
		t.Error("another account was served this account's blob")
	}
	// A replacement is a replacement.
	blob2 := wrappedBlob{Nonce: b64(12), Ciphertext: b64(80)}
	if rec := putPrefs(t, h, cookie, 0, blob2); rec.Code != http.StatusNoContent {
		t.Fatalf("second put = %d", rec.Code)
	}
	if got := getPrefs(t, h, cookie); got.PreferencesBlob == nil || *got.PreferencesBlob != blob2 {
		t.Errorf("second blob not stored: %+v", got.PreferencesBlob)
	}
}

func TestPutPreferencesRejectsBadBlobs(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	_, cookie := loggedInUser(t, h)
	cases := map[string]wrappedBlob{
		"short nonce":      {Nonce: b64(11), Ciphertext: b64(40)},
		"empty ciphertext": {Nonce: b64(12), Ciphertext: ""},
		"not base64":       {Nonce: b64(12), Ciphertext: "***"},
		"over the cap":     {Nonce: b64(12), Ciphertext: b64(maxPreferencesCiphertextLen + 1)},
	}
	for name, blob := range cases {
		if rec := putPrefs(t, h, cookie, 0, blob); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, rec.Code)
		}
	}
	if got := getPrefs(t, h, cookie); got.PreferencesBlob != nil {
		t.Error("a rejected write left a blob behind")
	}
	// The largest allowed blob is accepted (five custom themes do not fit the 4 KiB blob cap).
	if rec := putPrefs(t, h, cookie, 0, wrappedBlob{Nonce: b64(12), Ciphertext: b64(maxPreferencesCiphertextLen)}); rec.Code != http.StatusNoContent {
		t.Errorf("largest allowed blob: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPutPreferencesStaleEpochIsRefused(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	rot := signedRotation(t, user, rotateOpts{})
	rotated := doRotateKeys(t, h, cookie, rot.req)
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rotated.Code, rotated.Body.String())
	}
	// The rotation signs the other sessions out and hands this one a fresh cookie.
	cookie = sessionCookieFrom(rotated)
	if cookie == nil {
		t.Fatal("rotation set no session cookie")
	}
	// A blob sealed for epoch 0 would never open under the new key.
	rec := putPrefs(t, h, cookie, 0, wrappedBlob{Nonce: b64(12), Ciphertext: b64(40)})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "key_epoch_stale") {
		t.Fatalf("stale epoch put = %d %s, want 409 key_epoch_stale", rec.Code, rec.Body.String())
	}
	if got := getPrefs(t, h, cookie); got.PreferencesBlob != nil || got.KeyEpoch != 1 {
		t.Errorf("after refusal: %+v, want no blob at epoch 1", got)
	}
	if rec := putPrefs(t, h, cookie, 1, wrappedBlob{Nonce: b64(12), Ciphertext: b64(40)}); rec.Code != http.StatusNoContent {
		t.Errorf("put at the current epoch = %d", rec.Code)
	}
}

func TestPutPreferencesDeletedAccount(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	_, cookie := loggedInUser(t, h)
	if rec := doJSON(t, h, http.MethodDelete, "/api/account", cookie, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := putPrefs(t, h, cookie, 0, wrappedBlob{Nonce: b64(12), Ciphertext: b64(40)}); rec.Code != http.StatusNotFound {
		t.Errorf("put on a deleted account = %d, want 404", rec.Code)
	}
	if rec := doJSON(t, h, http.MethodGet, "/api/account/preferences", cookie, nil); rec.Code != http.StatusNotFound {
		t.Errorf("get on a deleted account = %d, want 404", rec.Code)
	}
}

func TestRotateKeysAcceptsPreferencesLargerThanTheGeneralBlobCap(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	if rec := putPrefs(t, h, cookie, 0, wrappedBlob{Nonce: b64(12), Ciphertext: b64(40)}); rec.Code != http.StatusNoContent {
		t.Fatalf("put: %d", rec.Code)
	}
	big := &wrappedBlob{Nonce: b64(12), Ciphertext: b64(10 * 1024)}
	rot := signedRotation(t, user, rotateOpts{prefs: big})
	if rec := doRotateKeys(t, h, cookie, rot.req); rec.Code != http.StatusOK {
		t.Fatalf("rotate with a 10 KiB blob: %d %s", rec.Code, rec.Body.String())
	}
}
