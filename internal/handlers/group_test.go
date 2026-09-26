package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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

	grantPayload := crypto.RoleGrantPayload(groupID, user.userID, "admin", "")
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
		RootGrantSignature:   base64.StdEncoding.EncodeToString(grantSig),
	}
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
	grantPayload := crypto.RoleGrantPayload(groupID, caller.userID, "admin", "")
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
	grantPayload := crypto.RoleGrantPayload(groupID, user.userID, "admin", "")
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
	grantPayload := crypto.RoleGrantPayload(groupID, user.userID, "admin", "")
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
		RootGrantSignature:   base64.StdEncoding.EncodeToString(grantSig),
	}

	rec := doCreateGroup(t, h, cookie, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
}
