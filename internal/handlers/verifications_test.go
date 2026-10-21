package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
)

// signedVerification builds a verification request signed by verifier over the
// verified user's real current fingerprint.
func signedVerification(t *testing.T, verifier, verified registeredUser) verificationRequest {
	t.Helper()
	fp, err := crypto.Fingerprint(verified.signPub, verified.wrapPub)
	if err != nil {
		t.Fatal(err)
	}
	return signedVerificationOver(t, verifier, verified.userID, fp)
}

func signedVerificationOver(t *testing.T, verifier registeredUser, verifiedID, fp string) verificationRequest {
	t.Helper()
	return signedVerificationAt(t, verifier, verifiedID, fp, utcToday())
}

// signedVerificationAt is signedVerificationOver with an explicit signed day.
func signedVerificationAt(t *testing.T, verifier registeredUser, verifiedID, fp, day string) verificationRequest {
	t.Helper()
	payload := crypto.VerificationPayload(verifier.userID, verifiedID, verifier.signPub, fp, day)
	sig, err := crypto.Sign(verifier.signPriv, crypto.ContextVerification, payload)
	if err != nil {
		t.Fatal(err)
	}
	return verificationRequest{
		Fingerprint:              fp,
		VerifierSigningPublicKey: base64.StdEncoding.EncodeToString(verifier.signPub),
		Signature:                base64.StdEncoding.EncodeToString(sig),
		SignedDay:                day,
	}
}

func doVerification(t *testing.T, h *Handler, cookie *http.Cookie, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	var rd *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, rd)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func decodeVerifications(t *testing.T, rec *httptest.ResponseRecorder) listVerificationsResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var resp listVerificationsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestVerificationRoundTripReplaceAndDelete(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	alice, cookie := loggedInUser(t, h)
	bob := registerTestUser(t, h)
	req := signedVerification(t, alice, bob)

	if rec := doVerification(t, h, cookie, http.MethodPut, "/api/verifications/"+bob.userID, req); rec.Code != http.StatusNoContent {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	// Putting the same record again replaces rather than duplicates.
	if rec := doVerification(t, h, cookie, http.MethodPut, "/api/verifications/"+bob.userID, req); rec.Code != http.StatusNoContent {
		t.Fatalf("re-put: %d %s", rec.Code, rec.Body.String())
	}
	resp := decodeVerifications(t, doVerification(t, h, cookie, http.MethodGet, "/api/verifications", nil))
	if len(resp.Verifications) != 1 {
		t.Fatalf("verifications = %+v", resp.Verifications)
	}
	got := resp.Verifications[0]
	if got.VerifiedUserID != bob.userID || got.Fingerprint != req.Fingerprint ||
		got.Signature != req.Signature || got.VerifierSigningPublicKey != req.VerifierSigningPublicKey {
		t.Fatalf("entry = %+v, want %+v for %s", got, req, bob.userID)
	}

	if rec := doVerification(t, h, cookie, http.MethodDelete, "/api/verifications/"+bob.userID, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := doVerification(t, h, cookie, http.MethodDelete, "/api/verifications/"+bob.userID, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("second delete: %d, want 204", rec.Code)
	}
	if resp := decodeVerifications(t, doVerification(t, h, cookie, http.MethodGet, "/api/verifications", nil)); len(resp.Verifications) != 0 {
		t.Fatalf("after delete: %+v", resp.Verifications)
	}
}

func TestPutVerificationRejectsBadInput(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	alice, cookie := loggedInUser(t, h)
	bob := registerTestUser(t, h)
	carol := registerTestUser(t, h)
	good := signedVerification(t, alice, bob)
	path := "/api/verifications/" + bob.userID

	put := func(c *http.Cookie, p string, body any) *httptest.ResponseRecorder {
		return doVerification(t, h, c, http.MethodPut, p, body)
	}
	if rec := put(nil, path, good); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", rec.Code)
	}
	if rec := put(cookie, "/api/verifications/"+alice.userID, signedVerification(t, alice, alice)); rec.Code != http.StatusBadRequest {
		t.Errorf("self: %d, want 400", rec.Code)
	}
	if rec := put(cookie, "/api/verifications/not-a-uuid", good); rec.Code != http.StatusNotFound {
		t.Errorf("bad id: %d, want 404", rec.Code)
	}
	if rec := put(cookie, "/api/verifications/"+"00000000-0000-4000-8000-000000000000", good); rec.Code != http.StatusNotFound {
		t.Errorf("unknown user: %d, want 404", rec.Code)
	}

	// A signature made over a different verified user does not verify here.
	forCarol := signedVerification(t, alice, carol)
	if rec := put(cookie, path, forCarol); rec.Code != http.StatusBadRequest {
		t.Errorf("record for another user: %d, want 400", rec.Code)
	}
	// A record signed by someone else's key is rejected as a stale signer.
	other := signedVerification(t, bob, carol)
	other.Signature = good.Signature
	other.VerifierSigningPublicKey = base64.StdEncoding.EncodeToString(bob.signPub)
	if rec := put(cookie, path, other); rec.Code != http.StatusConflict {
		t.Errorf("foreign signer: %d, want 409", rec.Code)
	}
	// A fingerprint that is not Bob's current one is a clear 409, even if signed.
	stale := signedVerificationOver(t, alice, bob.userID, strings.Repeat("00000-", 11)+"00000")
	rec := put(cookie, path, stale)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "fingerprint_stale") {
		t.Errorf("stale fingerprint: %d %s, want 409 fingerprint_stale", rec.Code, rec.Body.String())
	}
	// v2: the signed day is part of the payload and must be today's UTC date
	// within skew. A day changed after signing fails on the signature.
	dayTampered := good
	dayTampered.SignedDay = time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02")
	if rec := put(cookie, path, dayTampered); rec.Code != http.StatusBadRequest {
		t.Errorf("signed day changed after signing: %d, want 400", rec.Code)
	}
	fp, err := crypto.Fingerprint(bob.signPub, bob.wrapPub)
	if err != nil {
		t.Fatal(err)
	}
	for name, day := range map[string]string{
		"backdated":  time.Now().UTC().Add(-72 * time.Hour).Format("2006-01-02"),
		"future":     time.Now().UTC().Add(72 * time.Hour).Format("2006-01-02"),
		"not a date": "yesterday",
	} {
		if rec := put(cookie, path, signedVerificationAt(t, alice, bob.userID, fp, day)); rec.Code != http.StatusBadRequest {
			t.Errorf("signed day %s (%q): %d, want 400", name, day, rec.Code)
		}
	}
	// Malformed fingerprints never reach the signature check.
	bad := good
	bad.Fingerprint = "12345"
	if rec := put(cookie, path, bad); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed fingerprint: %d, want 400", rec.Code)
	}
	bad = good
	bad.Signature = "AAAA"
	if rec := put(cookie, path, bad); rec.Code != http.StatusBadRequest {
		t.Errorf("short signature: %d, want 400", rec.Code)
	}
	bad = good
	bad.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
	if rec := put(cookie, path, bad); rec.Code != http.StatusBadRequest {
		t.Errorf("wrong signature: %d, want 400", rec.Code)
	}
	// Nothing above stored anything.
	if resp := decodeVerifications(t, doVerification(t, h, cookie, http.MethodGet, "/api/verifications", nil)); len(resp.Verifications) != 0 {
		t.Errorf("rejected requests stored %+v", resp.Verifications)
	}
}

func TestListVerificationsIsPrivatePaginatedAndValidated(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	alice, aliceCookie := loggedInUser(t, h)
	bob := registerTestUser(t, h)
	carol := registerTestUser(t, h)
	for _, v := range []registeredUser{bob, carol} {
		if rec := doVerification(t, h, aliceCookie, http.MethodPut, "/api/verifications/"+v.userID, signedVerification(t, alice, v)); rec.Code != http.StatusNoContent {
			t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
		}
	}
	if rec := doVerification(t, h, nil, http.MethodGet, "/api/verifications", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", rec.Code)
	}
	for _, q := range []string{"?limit=0", "?limit=201", "?limit=x", "?cursor=nope"} {
		if rec := doVerification(t, h, aliceCookie, http.MethodGet, "/api/verifications"+q, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", q, rec.Code)
		}
	}
	first := decodeVerifications(t, doVerification(t, h, aliceCookie, http.MethodGet, "/api/verifications?limit=1", nil))
	if len(first.Verifications) != 1 || first.NextCursor == "" {
		t.Fatalf("page 1 = %+v", first)
	}
	second := decodeVerifications(t, doVerification(t, h, aliceCookie, http.MethodGet, "/api/verifications?limit=1&cursor="+first.NextCursor, nil))
	if len(second.Verifications) != 1 || second.Verifications[0].VerifiedUserID == first.Verifications[0].VerifiedUserID {
		t.Fatalf("page 2 = %+v after %+v", second, first)
	}

	// Another user's list is their own, and never includes Alice's.
	_, bobCookie := loggedInUser(t, h)
	if resp := decodeVerifications(t, doVerification(t, h, bobCookie, http.MethodGet, "/api/verifications", nil)); len(resp.Verifications) != 0 {
		t.Errorf("bob sees %+v", resp.Verifications)
	}
}
