package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

func doCreateGroup(t *testing.T, h *Handler, cookie *http.Cookie, req createGroupRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/api/groups", bytes.NewReader(body))
	if cookie != nil {
		httpReq.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, httpReq)
	return rec
}

// signedCreateGroupRequest builds a genuinely-signed createGroupRequest for
// user -- a private group, rotating revocation, the deployment default
// expiration -- signing the trust anchor and root grant with user's real
// private key exactly as a real client would, so the handler's
// crypto.Verify calls exercise real signatures rather than fixture bytes
// the server never checks (contrast validCredentialRewrapFields, whose
// fields the server intentionally never verifies).
func signedCreateGroupRequest(t *testing.T, user registeredUser) createGroupRequest {
	t.Helper()
	groupID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}

	anchorPayload := crypto.TrustAnchorPayload(user.userID, user.signPub, groupID)
	anchorSig, err := crypto.Sign(user.signPriv, crypto.ContextTrustAnchor, anchorPayload)
	if err != nil {
		t.Fatalf("sign trust anchor: %v", err)
	}

	rootGrantSortKey := testGrantSortKey(t, user.userID, time.Now())
	grantPayload := crypto.RoleGrantPayload(groupID, user.userID, "admin", rootGrantSortKey, "")
	grantSig, err := crypto.Sign(user.signPriv, crypto.ContextRoleGrant, grantPayload)
	if err != nil {
		t.Fatalf("sign root grant: %v", err)
	}

	return createGroupRequest{
		GroupID:    groupID,
		Visibility: "private",
		NameCiphertext: wrappedBlob{
			Nonce:      b64(12),
			Ciphertext: b64(32),
		},
		DescriptionCiphertext: wrappedBlob{
			Nonce:      b64(12),
			Ciphertext: b64(32),
		},
		RevocationMode:       "rotating",
		ExpirationDays:       30,
		GroupKeyWrapped:      wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		TrustAnchorSignature: base64.StdEncoding.EncodeToString(anchorSig),
		RootGrantSortKey:     rootGrantSortKey,
		RootGrantSignature:   base64.StdEncoding.EncodeToString(grantSig),
	}
}

// testGrantSortKey builds a well-formed "GRANT#<uuid>#<YYYY-MM-DD>#<rand>"
// sort key for subjectUUID at day, matching idgen.DaySuffix's shape --
// tests need to generate this client-side now that RoleGrantPayload signs
// the grant's own address (see that function's own doc comment), the same
// as a real client's group.ts#generateGrantSortKey would.
func testGrantSortKey(t *testing.T, subjectUUID string, day time.Time) string {
	t.Helper()
	daySuffix, err := idgen.DaySuffix(day)
	if err != nil {
		t.Fatalf("idgen.DaySuffix: %v", err)
	}
	return "GRANT#" + subjectUUID + "#" + daySuffix
}

func TestCreateGroupSuccess(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	req := signedCreateGroupRequest(t, user)

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var resp createGroupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.GroupID != req.GroupID {
		t.Errorf("GroupID = %q, want %q", resp.GroupID, req.GroupID)
	}
	if resp.RootGrantSortKey == "" {
		t.Error("RootGrantSortKey is empty")
	}
}

// TestCreateGroupRetrySucceeds covers the lost-response case PR #142 review
// found. The retry here does NOT resend the byte-for-byte identical
// request -- round 1's version of this test did, and round 2 review caught
// that the real client never does either: CreateGroupScreen's resume path
// calls signGroupCreation again, which calls generateGrantSortKey again, so
// a retry carries a FRESH rootGrantSortKey/rootGrantSignature every time,
// while groupId/trustAnchorSignature (deterministic, no grant-specific
// data) stay the same. This must still return 201, with the FIRST attempt's
// rootGrantSortKey -- the address something was actually written under --
// not the retry's own freshly-signed one, which addresses a GRANT# row
// that was never written.
func TestCreateGroupRetrySucceeds(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	first := signedCreateGroupRequest(t, user)

	firstRec := doCreateGroup(t, h, cookie, first)
	if firstRec.Code != http.StatusCreated {
		t.Fatalf("status (first) = %d, want %d, body: %s", firstRec.Code, http.StatusCreated, firstRec.Body.String())
	}
	var firstResp createGroupResponse
	if err := json.Unmarshal(firstRec.Body.Bytes(), &firstResp); err != nil {
		t.Fatalf("decoding first response: %v", err)
	}
	if firstResp.RootGrantSortKey != first.RootGrantSortKey {
		t.Fatalf("first response RootGrantSortKey = %q, want %q", firstResp.RootGrantSortKey, first.RootGrantSortKey)
	}

	// Build the retry the way a real resumed submission does: same groupId
	// and trust anchor signature (both cached verbatim by CreateGroupScreen
	// and deterministic to re-derive), but signGroupCreation is called
	// again, producing a fresh root grant sort key and signature.
	retry := first
	retryRootGrantSortKey := testGrantSortKey(t, user.userID, time.Now())
	retryGrantPayload := crypto.RoleGrantPayload(first.GroupID, user.userID, "admin", retryRootGrantSortKey, "")
	retryGrantSig, err := crypto.Sign(user.signPriv, crypto.ContextRoleGrant, retryGrantPayload)
	if err != nil {
		t.Fatalf("sign retry root grant: %v", err)
	}
	retry.RootGrantSortKey = retryRootGrantSortKey
	retry.RootGrantSignature = base64.StdEncoding.EncodeToString(retryGrantSig)

	retryRec := doCreateGroup(t, h, cookie, retry)
	if retryRec.Code != http.StatusCreated {
		t.Fatalf("status (retry) = %d, want %d, body: %s", retryRec.Code, http.StatusCreated, retryRec.Body.String())
	}
	var retryResp createGroupResponse
	if err := json.Unmarshal(retryRec.Body.Bytes(), &retryResp); err != nil {
		t.Fatalf("decoding retry response: %v", err)
	}
	if retryResp.RootGrantSortKey != first.RootGrantSortKey {
		t.Errorf("retry RootGrantSortKey = %q, want %q (the FIRST attempt's stored key, not the retry's own fresh one %q)", retryResp.RootGrantSortKey, first.RootGrantSortKey, retry.RootGrantSortKey)
	}
}

// TestCreateGroupRejectsStaleGrantDay covers grantDaySkewTolerance: a
// rootGrantSortKey dated well outside today's UTC day (signed correctly,
// but for a day the server's own clock disagrees with) must be rejected,
// not silently accepted with a day the chain walk could later resolve
// against the wrong superseded signing key.
func TestCreateGroupRejectsStaleGrantDay(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)

	groupID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
	anchorPayload := crypto.TrustAnchorPayload(user.userID, user.signPub, groupID)
	anchorSig, err := crypto.Sign(user.signPriv, crypto.ContextTrustAnchor, anchorPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	staleSortKey := testGrantSortKey(t, user.userID, time.Now().AddDate(0, 0, -10))
	grantPayload := crypto.RoleGrantPayload(groupID, user.userID, "admin", staleSortKey, "")
	grantSig, err := crypto.Sign(user.signPriv, crypto.ContextRoleGrant, grantPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	req := createGroupRequest{
		GroupID:               groupID,
		Visibility:            "private",
		NameCiphertext:        wrappedBlob{Nonce: b64(12), Ciphertext: b64(32)},
		DescriptionCiphertext: wrappedBlob{Nonce: b64(12), Ciphertext: b64(32)},
		RevocationMode:        "rotating",
		ExpirationDays:        30,
		GroupKeyWrapped:       wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		TrustAnchorSignature:  base64.StdEncoding.EncodeToString(anchorSig),
		RootGrantSortKey:      staleSortKey,
		RootGrantSignature:    base64.StdEncoding.EncodeToString(grantSig),
	}

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCreateGroupRequiresSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, _ := loggedInUser(t, h)
	req := signedCreateGroupRequest(t, user)

	rec := doCreateGroup(t, h, nil, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestCreateGroupRejectsInvalidTrustAnchorSignature covers the server-side
// verification decision: a signature that doesn't actually verify against
// the caller's own stored signing key must be rejected before anything is
// written, not merely stored opaquely for a future client to discover was
// wrong.
func TestCreateGroupRejectsInvalidTrustAnchorSignature(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	req := signedCreateGroupRequest(t, user)
	req.TrustAnchorSignature = base64.StdEncoding.EncodeToString(make([]byte, 64))

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateGroupRejectsInvalidRootGrantSignature mirrors
// TestCreateGroupRejectsInvalidTrustAnchorSignature for the second signature
// this handler verifies.
func TestCreateGroupRejectsInvalidRootGrantSignature(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	req := signedCreateGroupRequest(t, user)
	req.RootGrantSignature = base64.StdEncoding.EncodeToString(make([]byte, 64))

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateGroupRejectsSignatureFromAnotherUser covers the reason the
// handler reads the caller's signing key from their OWN session-authenticated
// PROFILE rather than trusting anything the request claims: a signature that
// is perfectly valid, just under a DIFFERENT account's key, must not verify
// as this caller's own trust anchor.
func TestCreateGroupRejectsSignatureFromAnotherUser(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	caller, callerCookie := loggedInUser(t, h)
	other, _ := loggedInUser(t, h)

	groupID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
	// Signed correctly, but under OTHER's key and identity rather than the
	// caller's -- crypto.Verify at the handler will check it against the
	// caller's own stored SigningPublicKey and must fail.
	anchorPayload := crypto.TrustAnchorPayload(other.userID, other.signPub, groupID)
	anchorSig, err := crypto.Sign(other.signPriv, crypto.ContextTrustAnchor, anchorPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rootGrantSortKey := testGrantSortKey(t, caller.userID, time.Now())
	grantPayload := crypto.RoleGrantPayload(groupID, caller.userID, "admin", rootGrantSortKey, "")
	grantSig, err := crypto.Sign(caller.signPriv, crypto.ContextRoleGrant, grantPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	req := createGroupRequest{
		GroupID:               groupID,
		Visibility:            "private",
		NameCiphertext:        wrappedBlob{Nonce: b64(12), Ciphertext: b64(32)},
		DescriptionCiphertext: wrappedBlob{Nonce: b64(12), Ciphertext: b64(32)},
		RevocationMode:        "rotating",
		ExpirationDays:        30,
		GroupKeyWrapped:       wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		TrustAnchorSignature:  base64.StdEncoding.EncodeToString(anchorSig),
		RootGrantSortKey:      rootGrantSortKey,
		RootGrantSignature:    base64.StdEncoding.EncodeToString(grantSig),
	}

	rec := doCreateGroup(t, h, callerCookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCreateGroupRejectsInvalidVisibility(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	req := signedCreateGroupRequest(t, user)
	req.Visibility = "sorta-private"

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCreateGroupRejectsInvalidRevocationMode(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	req := signedCreateGroupRequest(t, user)
	req.RevocationMode = "sometimes"

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateGroupRejectsInvalidGroupID covers idgen.ValidUUID's shape check
// on the client-supplied GroupID, the same validation register.go applies
// to UserID.
func TestCreateGroupRejectsInvalidGroupID(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	req := signedCreateGroupRequest(t, user)
	req.GroupID = "not-a-uuid"

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateGroupExpirationOffRejectedByDefault covers
// validateExpirationDays: config.FromEnv()'s default
// (DefaultAllowGroupExpirationOff = true) actually permits 0, so this test
// pins a Config with it disabled to exercise the rejection path -- the
// deployment-forbids-it branch config.FromEnv()'s own default would never
// reach.
func TestCreateGroupExpirationOffRejectedByDefault(t *testing.T) {
	cfg := config.FromEnv()
	cfg.AllowGroupExpirationOff = false
	h := New(cfg, testDB(t))
	user, cookie := loggedInUser(t, h)
	req := signedCreateGroupRequest(t, user)
	req.ExpirationDays = 0

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateGroupExpirationOffAllowedWhenConfigured is the positive
// counterpart: with AllowGroupExpirationOff true (the default), 0 is a
// legitimate "never expire" policy, not a validation error.
func TestCreateGroupExpirationOffAllowedWhenConfigured(t *testing.T) {
	cfg := config.FromEnv()
	cfg.AllowGroupExpirationOff = true
	h := New(cfg, testDB(t))
	user, cookie := loggedInUser(t, h)
	req := signedCreateGroupRequest(t, user)
	req.ExpirationDays = 0

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
}

func TestCreateGroupRejectsNegativeExpirationDays(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	req := signedCreateGroupRequest(t, user)
	req.ExpirationDays = -1

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateGroupRejectsExcessiveExpirationDays covers maxExpirationDays --
// PR #142 review: without an upper bound, a huge ExpirationDays risks
// overflowing a future days*86400 TTL computation.
func TestCreateGroupRejectsExcessiveExpirationDays(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	req := signedCreateGroupRequest(t, user)
	req.ExpirationDays = maxExpirationDays + 1

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateGroupRejectsWrongSizeGroupKeyCiphertext covers
// wrappedGroupKeyCiphertextSize: an ECIES-wrapped 32-byte group key under
// AES-GCM is always exactly 48 bytes, so any other length is a client that
// wrapped the wrong thing, not a legitimate wrap of unusual size.
func TestCreateGroupRejectsWrongSizeGroupKeyCiphertext(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	req := signedCreateGroupRequest(t, user)
	req.GroupKeyWrapped.Ciphertext = b64(32) // wrong size: not 48

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateGroupPublicRejectsWhitespaceOnlyName covers validateGroupText's
// strings.TrimSpace check -- PR #142 review: an all-whitespace name would
// otherwise pass length validation and become a directory entry with no
// visible name.
func TestCreateGroupPublicRejectsWhitespaceOnlyName(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	groupID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
	anchorPayload := crypto.TrustAnchorPayload(user.userID, user.signPub, groupID)
	anchorSig, err := crypto.Sign(user.signPriv, crypto.ContextTrustAnchor, anchorPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rootGrantSortKey := testGrantSortKey(t, user.userID, time.Now())
	grantPayload := crypto.RoleGrantPayload(groupID, user.userID, "admin", rootGrantSortKey, "")
	grantSig, err := crypto.Sign(user.signPriv, crypto.ContextRoleGrant, grantPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	req := createGroupRequest{
		GroupID:              groupID,
		Visibility:           "public",
		NamePlaintext:        "   ", // whitespace only -- must be rejected like empty
		RevocationMode:       "rotating",
		ExpirationDays:       30,
		GroupKeyWrapped:      wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		TrustAnchorSignature: base64.StdEncoding.EncodeToString(anchorSig),
		RootGrantSortKey:     rootGrantSortKey,
		RootGrantSignature:   base64.StdEncoding.EncodeToString(grantSig),
	}

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateGroupPrivateRejectsPlaintextFields covers the oneof rejection
// PR #142 review added: a private group's request carrying
// namePlaintext/descriptionPlaintext (the PUBLIC pair) must be rejected,
// not silently ignored -- ignoring it would still have let a buggy client
// send a private group's plaintext name over the wire with no error.
func TestCreateGroupPrivateRejectsPlaintextFields(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	req := signedCreateGroupRequest(t, user)
	req.NamePlaintext = "should not be here"

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateGroupPublicRejectsCiphertextFields is
// TestCreateGroupPrivateRejectsPlaintextFields' mirror image: a public
// group's request carrying nameCiphertext/descriptionCiphertext (the
// PRIVATE pair) must also be rejected.
func TestCreateGroupPublicRejectsCiphertextFields(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	groupID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
	anchorPayload := crypto.TrustAnchorPayload(user.userID, user.signPub, groupID)
	anchorSig, err := crypto.Sign(user.signPriv, crypto.ContextTrustAnchor, anchorPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rootGrantSortKey := testGrantSortKey(t, user.userID, time.Now())
	grantPayload := crypto.RoleGrantPayload(groupID, user.userID, "admin", rootGrantSortKey, "")
	grantSig, err := crypto.Sign(user.signPriv, crypto.ContextRoleGrant, grantPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	req := createGroupRequest{
		GroupID:              groupID,
		Visibility:           "public",
		NamePlaintext:        "Book Club",
		NameCiphertext:       wrappedBlob{Nonce: b64(12), Ciphertext: b64(32)}, // should not be here
		RevocationMode:       "rotating",
		ExpirationDays:       30,
		GroupKeyWrapped:      wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		TrustAnchorSignature: base64.StdEncoding.EncodeToString(anchorSig),
		RootGrantSortKey:     rootGrantSortKey,
		RootGrantSignature:   base64.StdEncoding.EncodeToString(grantSig),
	}

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateGroupPublicRequiresName covers validateGroupText's allowEmpty=false
// branch for a public group's name.
func TestCreateGroupPublicRequiresName(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	groupID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
	anchorPayload := crypto.TrustAnchorPayload(user.userID, user.signPub, groupID)
	anchorSig, err := crypto.Sign(user.signPriv, crypto.ContextTrustAnchor, anchorPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rootGrantSortKey := testGrantSortKey(t, user.userID, time.Now())
	grantPayload := crypto.RoleGrantPayload(groupID, user.userID, "admin", rootGrantSortKey, "")
	grantSig, err := crypto.Sign(user.signPriv, crypto.ContextRoleGrant, grantPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	req := createGroupRequest{
		GroupID:              groupID,
		Visibility:           "public",
		NamePlaintext:        "", // missing -- required for a public group
		RevocationMode:       "rotating",
		ExpirationDays:       30,
		GroupKeyWrapped:      wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		TrustAnchorSignature: base64.StdEncoding.EncodeToString(anchorSig),
		RootGrantSortKey:     rootGrantSortKey,
		RootGrantSignature:   base64.StdEncoding.EncodeToString(grantSig),
	}

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateGroupPublicSuccess covers the public-group path end to end: a
// plaintext name/description, and the directory GSI1 entry db.CreateGroup
// writes for it (verified at the db layer in
// TestCreateGroupPublicWritesDirectoryEntry -- this test only checks the
// handler accepts and creates it).
func TestCreateGroupPublicSuccess(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	groupID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
	anchorPayload := crypto.TrustAnchorPayload(user.userID, user.signPub, groupID)
	anchorSig, err := crypto.Sign(user.signPriv, crypto.ContextTrustAnchor, anchorPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rootGrantSortKey := testGrantSortKey(t, user.userID, time.Now())
	grantPayload := crypto.RoleGrantPayload(groupID, user.userID, "admin", rootGrantSortKey, "")
	grantSig, err := crypto.Sign(user.signPriv, crypto.ContextRoleGrant, grantPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	req := createGroupRequest{
		GroupID:              groupID,
		Visibility:           "public",
		NamePlaintext:        "Book Club",
		DescriptionPlaintext: "We read books",
		RevocationMode:       "open",
		ExpirationDays:       30,
		GroupKeyWrapped:      wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		TrustAnchorSignature: base64.StdEncoding.EncodeToString(anchorSig),
		RootGrantSortKey:     rootGrantSortKey,
		RootGrantSignature:   base64.StdEncoding.EncodeToString(grantSig),
	}

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
}

func doListGroups(t *testing.T, h *Handler, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodGet, "/api/groups", nil)
	if cookie != nil {
		httpReq.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, httpReq)
	return rec
}

func TestListGroupsRequiresSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))

	rec := doListGroups(t, h, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestListGroupsEmpty(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	_, cookie := loggedInUser(t, h)

	rec := doListGroups(t, h, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp listGroupsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(resp.Groups) != 0 {
		t.Errorf("len(Groups) = %d, want 0", len(resp.Groups))
	}
}

// TestListGroupsReturnsPublicAndPrivate covers the field-set split each
// entry must carry -- a public group's plaintext name/description and
// nothing else, a private group's ciphertext and the caller's own
// WrappedGroupKey and no plaintext, matching createGroupRequest's own
// opposite-direction split (see that type's doc comment).
func TestListGroupsReturnsPublicAndPrivate(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)

	privateReq := signedCreateGroupRequest(t, user)
	privateRec := doCreateGroup(t, h, cookie, privateReq)
	if privateRec.Code != http.StatusCreated {
		t.Fatalf("create private group status = %d, body: %s", privateRec.Code, privateRec.Body.String())
	}

	publicGroupID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
	anchorPayload := crypto.TrustAnchorPayload(user.userID, user.signPub, publicGroupID)
	anchorSig, err := crypto.Sign(user.signPriv, crypto.ContextTrustAnchor, anchorPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	publicRootGrantSortKey := testGrantSortKey(t, user.userID, time.Now())
	grantPayload := crypto.RoleGrantPayload(publicGroupID, user.userID, "admin", publicRootGrantSortKey, "")
	grantSig, err := crypto.Sign(user.signPriv, crypto.ContextRoleGrant, grantPayload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	publicReq := createGroupRequest{
		GroupID:              publicGroupID,
		Visibility:           "public",
		NamePlaintext:        "Book Club",
		DescriptionPlaintext: "We read books",
		RevocationMode:       "rotating",
		ExpirationDays:       30,
		GroupKeyWrapped:      wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		TrustAnchorSignature: base64.StdEncoding.EncodeToString(anchorSig),
		RootGrantSortKey:     publicRootGrantSortKey,
		RootGrantSignature:   base64.StdEncoding.EncodeToString(grantSig),
	}
	publicRec := doCreateGroup(t, h, cookie, publicReq)
	if publicRec.Code != http.StatusCreated {
		t.Fatalf("create public group status = %d, body: %s", publicRec.Code, publicRec.Body.String())
	}

	rec := doListGroups(t, h, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp listGroupsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(resp.Groups) != 2 {
		t.Fatalf("len(Groups) = %d, want 2, body: %s", len(resp.Groups), rec.Body.String())
	}

	byID := make(map[string]groupListEntry, len(resp.Groups))
	for _, g := range resp.Groups {
		byID[g.GroupID] = g
	}

	priv, ok := byID[privateReq.GroupID]
	if !ok {
		t.Fatalf("private group %q missing from response", privateReq.GroupID)
	}
	if priv.Visibility != "private" {
		t.Errorf("private entry Visibility = %q, want %q", priv.Visibility, "private")
	}
	if priv.Role != "admin" {
		t.Errorf("private entry Role = %q, want %q", priv.Role, "admin")
	}
	if priv.NameCiphertext == nil || priv.WrappedGroupKey == nil {
		t.Errorf("private entry missing NameCiphertext/WrappedGroupKey: %+v", priv)
	}
	if priv.NamePlaintext != "" || priv.DescriptionPlaintext != "" {
		t.Errorf("private entry carries plaintext fields it must not: NamePlaintext=%q DescriptionPlaintext=%q",
			priv.NamePlaintext, priv.DescriptionPlaintext)
	}

	pub, ok := byID[publicGroupID]
	if !ok {
		t.Fatalf("public group %q missing from response", publicGroupID)
	}
	if pub.Visibility != "public" {
		t.Errorf("public entry Visibility = %q, want %q", pub.Visibility, "public")
	}
	if pub.NamePlaintext != "Book Club" {
		t.Errorf("public entry NamePlaintext = %q, want %q", pub.NamePlaintext, "Book Club")
	}
	if pub.NameCiphertext != nil || pub.WrappedGroupKey != nil {
		t.Errorf("public entry carries ciphertext/wrapped-key fields it must not: %+v", pub)
	}
}

// TestListGroupsOnlyReturnsCallersOwnGroups covers the session boundary:
// one user's groups must never appear in a different, unrelated user's
// list, even though both live in the same table.
func TestListGroupsOnlyReturnsCallersOwnGroups(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	userA, cookieA := loggedInUser(t, h)
	_, cookieB := loggedInUser(t, h)

	reqA := signedCreateGroupRequest(t, userA)
	if rec := doCreateGroup(t, h, cookieA, reqA); rec.Code != http.StatusCreated {
		t.Fatalf("create group for userA status = %d, body: %s", rec.Code, rec.Body.String())
	}

	recB := doListGroups(t, h, cookieB)
	if recB.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", recB.Code, http.StatusOK, recB.Body.String())
	}
	var respB listGroupsResponse
	if err := json.Unmarshal(recB.Body.Bytes(), &respB); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(respB.Groups) != 0 {
		t.Errorf("userB's Groups = %+v, want empty (userA's group must not appear)", respB.Groups)
	}
}
