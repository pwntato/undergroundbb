package handlers

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
)

func pinB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// signedPin builds a pin request signed by pinner over the given fields.
func signedPin(t *testing.T, pinner registeredUser, pinnedID string, wrapping []byte, keys ...[]byte) pinRequest {
	t.Helper()
	payload := crypto.PinPayload(pinner.userID, pinnedID, pinner.signPub, wrapping, keys)
	sig, err := crypto.Sign(pinner.signPriv, crypto.ContextPin, payload)
	if err != nil {
		t.Fatal(err)
	}
	enc := make([]string, 0, len(keys))
	for _, k := range keys {
		enc = append(enc, pinB64(k))
	}
	return pinRequest{
		SigningPublicKeys:      enc,
		WrappingPublicKey:      pinB64(wrapping),
		PinnerSigningPublicKey: pinB64(pinner.signPub),
		Signature:              pinB64(sig),
	}
}

func doPutPin(t *testing.T, h *Handler, cookie *http.Cookie, pinnedID string, body any) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/pins/"+pinnedID, bytes.NewReader(raw))
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func doListPins(t *testing.T, h *Handler, cookie *http.Cookie, query string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/pins"+query, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func decodePins(t *testing.T, rec *httptest.ResponseRecorder) listPinsResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var resp listPinsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestPutPinRoundTripsAndReplaces(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	alice, cookie := loggedInUser(t, h)
	bob := registerTestUser(t, h)

	req := signedPin(t, alice, bob.userID, bob.wrapPub, bob.signPub)
	if rec := doPutPin(t, h, cookie, bob.userID, req); rec.Code != http.StatusNoContent {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	resp := decodePins(t, doListPins(t, h, cookie, ""))
	if len(resp.Pins) != 1 || resp.Pins[0].PinnedUserID != bob.userID ||
		resp.Pins[0].Signature != req.Signature ||
		resp.Pins[0].PinnerSigningPublicKey != pinB64(alice.signPub) ||
		resp.Pins[0].WrappingPublicKey != pinB64(bob.wrapPub) ||
		len(resp.Pins[0].SigningPublicKeys) != 1 || resp.Pins[0].SigningPublicKeys[0] != pinB64(bob.signPub) {
		t.Fatalf("pins = %+v", resp.Pins)
	}

	// Re-pinning replaces rather than duplicates.
	extra, _, _ := crypto.GenerateSigningKey()
	req2 := signedPin(t, alice, bob.userID, bob.wrapPub, bob.signPub, extra)
	if rec := doPutPin(t, h, cookie, bob.userID, req2); rec.Code != http.StatusNoContent {
		t.Fatalf("re-put: %d %s", rec.Code, rec.Body.String())
	}
	resp = decodePins(t, doListPins(t, h, cookie, ""))
	if len(resp.Pins) != 1 || len(resp.Pins[0].SigningPublicKeys) != 2 || resp.Pins[0].Signature != req2.Signature {
		t.Fatalf("after replace pins = %+v", resp.Pins)
	}
}

func TestPutPinRejectsBadInput(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	alice, cookie := loggedInUser(t, h)
	bob := registerTestUser(t, h)
	carol := registerTestUser(t, h)
	good := signedPin(t, alice, bob.userID, bob.wrapPub, bob.signPub)

	if rec := doPutPin(t, h, nil, bob.userID, good); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", rec.Code)
	}
	if rec := doPutPin(t, h, cookie, alice.userID, signedPin(t, alice, alice.userID, alice.wrapPub, alice.signPub)); rec.Code != http.StatusBadRequest {
		t.Errorf("self pin: %d, want 400", rec.Code)
	}
	if rec := doPutPin(t, h, cookie, "not-a-uuid", good); rec.Code != http.StatusNotFound {
		t.Errorf("malformed id: %d, want 404", rec.Code)
	}
	if rec := doPutPin(t, h, cookie, "3f0c7a52-1111-4222-8333-444455556666", signedPin(t, alice, "3f0c7a52-1111-4222-8333-444455556666", bob.wrapPub, bob.signPub)); rec.Code != http.StatusNotFound {
		t.Errorf("unknown pinned user: %d, want 404", rec.Code)
	}

	// Mutation targets: each must fail on the SIGNATURE, so the body is
	// otherwise well-formed.
	copied := good // signed for bob, submitted for carol
	if rec := doPutPin(t, h, cookie, carol.userID, copied); rec.Code != http.StatusBadRequest {
		t.Errorf("pin copied to another pinned user: %d, want 400", rec.Code)
	}
	tampered := good
	tampered.WrappingPublicKey = pinB64(carol.wrapPub)
	if rec := doPutPin(t, h, cookie, bob.userID, tampered); rec.Code != http.StatusBadRequest {
		t.Errorf("tampered wrapping key: %d, want 400", rec.Code)
	}
	otherKey, otherPriv, _ := crypto.GenerateSigningKey()
	forged := signedPin(t, registeredUser{userID: alice.userID, signPub: otherKey, signPriv: otherPriv}, bob.userID, bob.wrapPub, bob.signPub)
	if rec := doPutPin(t, h, cookie, bob.userID, forged); rec.Code != http.StatusConflict {
		t.Errorf("signed under a key that is not my current one: %d, want 409", rec.Code)
	}
	wrongCtxPayload := crypto.PinPayload(alice.userID, bob.userID, alice.signPub, bob.wrapPub, [][]byte{bob.signPub})
	wrongCtx, _ := crypto.Sign(alice.signPriv, crypto.ContextRoleGrant, wrongCtxPayload)
	badCtx := good
	badCtx.Signature = pinB64(wrongCtx)
	if rec := doPutPin(t, h, cookie, bob.userID, badCtx); rec.Code != http.StatusBadRequest {
		t.Errorf("wrong signing context: %d, want 400", rec.Code)
	}

	shape := func(mutate func(*pinRequest)) *httptest.ResponseRecorder {
		r := good
		r.SigningPublicKeys = append([]string(nil), good.SigningPublicKeys...)
		mutate(&r)
		return doPutPin(t, h, cookie, bob.userID, r)
	}
	if rec := shape(func(r *pinRequest) { r.SigningPublicKeys = nil }); rec.Code != http.StatusBadRequest {
		t.Errorf("empty key set: %d, want 400", rec.Code)
	}
	if rec := shape(func(r *pinRequest) { r.SigningPublicKeys = append(r.SigningPublicKeys, r.SigningPublicKeys[0]) }); rec.Code != http.StatusBadRequest {
		t.Errorf("duplicate key: %d, want 400", rec.Code)
	}
	if rec := shape(func(r *pinRequest) { r.SigningPublicKeys[0] = pinB64([]byte("short")) }); rec.Code != http.StatusBadRequest {
		t.Errorf("short key: %d, want 400", rec.Code)
	}
	if rec := shape(func(r *pinRequest) { r.WrappingPublicKey = "!!!" }); rec.Code != http.StatusBadRequest {
		t.Errorf("bad wrapping key: %d, want 400", rec.Code)
	}
	if rec := shape(func(r *pinRequest) { r.Signature = pinB64(make([]byte, ed25519.SignatureSize-1)) }); rec.Code != http.StatusBadRequest {
		t.Errorf("short signature: %d, want 400", rec.Code)
	}
	many := make([]string, maxPinSigningKeys+1)
	for i := range many {
		k, _, _ := crypto.GenerateSigningKey()
		many[i] = pinB64(k)
	}
	if rec := shape(func(r *pinRequest) { r.SigningPublicKeys = many }); rec.Code != http.StatusBadRequest {
		t.Errorf("too many keys: %d, want 400", rec.Code)
	}

	if got := decodePins(t, doListPins(t, h, cookie, "")); len(got.Pins) != 0 {
		t.Errorf("a rejected write stored %d pins, want 0", len(got.Pins))
	}
}

func TestListPinsIsPrivatePaginatedAndValidated(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	alice, aliceCookie := loggedInUser(t, h)
	_, bobCookie := loggedInUser(t, h)
	for i := 0; i < 3; i++ {
		target := registerTestUser(t, h)
		if rec := doPutPin(t, h, aliceCookie, target.userID, signedPin(t, alice, target.userID, target.wrapPub, target.signPub)); rec.Code != http.StatusNoContent {
			t.Fatalf("put %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}

	if rec := doListPins(t, h, nil, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", rec.Code)
	}
	if got := decodePins(t, doListPins(t, h, bobCookie, "")); len(got.Pins) != 0 {
		t.Errorf("another user sees %d of alice's pins, want 0", len(got.Pins))
	}

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		q := "?limit=2"
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		page := decodePins(t, doListPins(t, h, aliceCookie, q))
		for _, p := range page.Pins {
			if seen[p.PinnedUserID] {
				t.Fatalf("pin %s served twice", p.PinnedUserID)
			}
			seen[p.PinnedUserID] = true
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
		t.Errorf("saw %d pins over %d pages, want 3 over 2", len(seen), pages)
	}

	for _, q := range []string{"?limit=0", "?limit=201", "?limit=x", "?cursor=nope"} {
		if rec := doListPins(t, h, aliceCookie, q); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", q, rec.Code)
		}
	}
}
