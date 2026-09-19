package handlers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/models"
)

// registeredUser bundles a registered account's response with the real
// Ed25519 signing key it was registered under, so login tests can produce
// genuine signatures.
type registeredUser struct {
	username string
	userID   string
	signPub  ed25519.PublicKey
	signPriv ed25519.PrivateKey
}

func registerTestUser(t *testing.T, h *Handler) registeredUser {
	t.Helper()
	pub, priv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}

	username := randomUsername(t)
	req := validRegisterRequest(username)
	req.SigningPublicKey = base64.StdEncoding.EncodeToString(pub)

	rec := doRegister(t, h, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var resp registerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding register response: %v", err)
	}

	return registeredUser{username: username, userID: resp.UserID, signPub: pub, signPriv: priv}
}

func doChallenge(t *testing.T, h *Handler, username string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(challengeRequest{Username: username})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/challenge", bytes.NewReader(body)))
	return rec
}

func doVerify(t *testing.T, h *Handler, req verifyRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/verify", bytes.NewReader(body)))
	return rec
}

// completeLogin runs challenge+sign+verify for user against h, failing the
// test on any unexpected error. Returns the verify response recorder so
// callers can inspect the cookie/status themselves.
func completeLogin(t *testing.T, h *Handler, user registeredUser) *httptest.ResponseRecorder {
	t.Helper()
	chRec := doChallenge(t, h, user.username)
	if chRec.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, body: %s", chRec.Code, chRec.Body.String())
	}
	var ch challengeResponse
	if err := json.Unmarshal(chRec.Body.Bytes(), &ch); err != nil {
		t.Fatalf("decoding challenge response: %v", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(ch.Nonce)
	if err != nil {
		t.Fatalf("decoding nonce: %v", err)
	}
	sig, err := crypto.Sign(user.signPriv, crypto.ContextLoginChallenge, nonce)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	return doVerify(t, h, verifyRequest{
		Username:  user.username,
		Nonce:     ch.Nonce,
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
}

func TestLoginHappyPath(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)

	rec := completeLogin(t, h, user)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie set")
	}
	if !sessionCookie.HttpOnly {
		t.Error("session cookie is not HttpOnly")
	}
	if !sessionCookie.Secure {
		t.Error("session cookie is not Secure")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie SameSite = %v, want Lax", sessionCookie.SameSite)
	}

	userID, err := h.sessions.Verify(sessionCookie.Value)
	if err != nil {
		t.Fatalf("session token does not verify: %v", err)
	}
	if userID != user.userID {
		t.Errorf("session names user %q, want %q", userID, user.userID)
	}
}

func TestChallengeUnknownUsername(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	rec := doChallenge(t, h, randomUsername(t))

	// Must still return 200 with a plausible-shaped response -- see
	// challenge's own doc comment on why an unknown username isn't a
	// distinct status/shape.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var ch challengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if ch.Nonce == "" {
		t.Error("Nonce is empty")
	}
	if ch.Salt == "" {
		t.Error("Salt is empty")
	}
}

func TestVerifyUnknownUsername(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	_, priv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	nonce := make([]byte, challengeNonceSize)
	sig, err := crypto.Sign(priv, crypto.ContextLoginChallenge, nonce)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	rec := doVerify(t, h, verifyRequest{
		Username:  randomUsername(t),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestVerifyWrongSignature(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)

	chRec := doChallenge(t, h, user.username)
	var ch challengeResponse
	if err := json.Unmarshal(chRec.Body.Bytes(), &ch); err != nil {
		t.Fatalf("decoding challenge response: %v", err)
	}

	// Sign with a DIFFERENT keypair -- a real signature, just the wrong key,
	// which is what should actually fail verification against the stored
	// public key (as opposed to a malformed/garbage signature, covered
	// elsewhere).
	_, otherPriv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	nonce, _ := base64.StdEncoding.DecodeString(ch.Nonce)
	wrongSig, err := crypto.Sign(otherPriv, crypto.ContextLoginChallenge, nonce)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	rec := doVerify(t, h, verifyRequest{
		Username:  user.username,
		Nonce:     ch.Nonce,
		Signature: base64.StdEncoding.EncodeToString(wrongSig),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestVerifyReplayFails(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)

	chRec := doChallenge(t, h, user.username)
	var ch challengeResponse
	if err := json.Unmarshal(chRec.Body.Bytes(), &ch); err != nil {
		t.Fatalf("decoding challenge response: %v", err)
	}
	nonce, _ := base64.StdEncoding.DecodeString(ch.Nonce)
	sig, err := crypto.Sign(user.signPriv, crypto.ContextLoginChallenge, nonce)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verifyReq := verifyRequest{Username: user.username, Nonce: ch.Nonce, Signature: base64.StdEncoding.EncodeToString(sig)}

	first := doVerify(t, h, verifyReq)
	if first.Code != http.StatusOK {
		t.Fatalf("first verify status = %d, want %d, body: %s", first.Code, http.StatusOK, first.Body.String())
	}

	// Replaying the exact same (valid!) request a second time must fail --
	// the nonce is already consumed. Must NOT be treated as a signature
	// failure (see verify's own doc comment): asserting the specific message
	// here, not just non-200, to catch a regression that conflates the two.
	second := doVerify(t, h, verifyReq)
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want %d, body: %s", second.Code, http.StatusUnauthorized, second.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(second.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["error"] != verifyErrorChallengeInvalid {
		t.Errorf("error = %q, want %q", body["error"], verifyErrorChallengeInvalid)
	}
}

func TestVerifyWithoutChallengeFails(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)

	// Sign a nonce the server never issued -- no matching CHALLENGE item
	// exists at all.
	nonce := make([]byte, challengeNonceSize)
	sig, err := crypto.Sign(user.signPriv, crypto.ContextLoginChallenge, nonce)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	rec := doVerify(t, h, verifyRequest{
		Username:  user.username,
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestLockoutAfterFiveFailures covers docs/DESIGN.md's
// "five-attempts-in-five-minutes" and the round-26 review comment: the lock
// is enforced at verify, and a locked account's valid-credential login is
// rejected -- distinctly from a bad signature -- while the lock holds.
func TestLockoutAfterFiveFailures(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)
	_, otherPriv, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}

	for i := range lockThreshold {
		chRec := doChallenge(t, h, user.username)
		var ch challengeResponse
		if err := json.Unmarshal(chRec.Body.Bytes(), &ch); err != nil {
			t.Fatalf("decoding challenge response: %v", err)
		}
		nonce, _ := base64.StdEncoding.DecodeString(ch.Nonce)
		wrongSig, err := crypto.Sign(otherPriv, crypto.ContextLoginChallenge, nonce)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		rec := doVerify(t, h, verifyRequest{
			Username:  user.username,
			Nonce:     ch.Nonce,
			Signature: base64.StdEncoding.EncodeToString(wrongSig),
		})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: status = %d, want %d, body: %s", i+1, rec.Code, http.StatusUnauthorized, rec.Body.String())
		}
	}

	// Now attempt a REAL login with the correct key -- must be rejected as
	// locked, not accepted, even though the signature would otherwise be
	// valid.
	rec := completeLogin(t, h, user)
	if rec.Code != http.StatusForbidden {
		t.Errorf("locked-account login status = %d, want %d, body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// TestChallengeFloodDoesNotLockout covers issue #27's round-24 comment
// directly: repeatedly requesting (and thereby invalidating) a challenge
// must not increment the lockout counter, since a failed conditional
// delete is not a signature failure.
func TestChallengeFloodDoesNotLockout(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)

	// Issue a challenge, then immediately overwrite it several times --
	// simulating a flood that invalidates the first nonce before it's used.
	first := doChallenge(t, h, user.username)
	var firstCh challengeResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstCh); err != nil {
		t.Fatalf("decoding challenge response: %v", err)
	}
	for range lockThreshold + 2 {
		doChallenge(t, h, user.username)
	}

	// Try to verify against the now-stale first nonce -- this must fail
	// (challenge mismatch) but must NOT have moved the lockout counter.
	nonce, _ := base64.StdEncoding.DecodeString(firstCh.Nonce)
	sig, err := crypto.Sign(user.signPriv, crypto.ContextLoginChallenge, nonce)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	rec := doVerify(t, h, verifyRequest{
		Username:  user.username,
		Nonce:     firstCh.Nonce,
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale-challenge verify status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	// A real login (fresh challenge, correct signature) must still succeed
	// -- confirming no lockout was triggered by the flood above.
	final := completeLogin(t, h, user)
	if final.Code != http.StatusOK {
		t.Errorf("post-flood login status = %d, want %d, body: %s", final.Code, http.StatusOK, final.Body.String())
	}
}

func TestVerifyMalformedRequests(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)

	cases := []struct {
		name string
		req  verifyRequest
	}{
		{"empty nonce", verifyRequest{Username: user.username, Nonce: "", Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}},
		{"not base64 nonce", verifyRequest{Username: user.username, Nonce: "not-valid-base64!!", Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}},
		{"wrong length nonce", verifyRequest{Username: user.username, Nonce: base64.StdEncoding.EncodeToString([]byte("short")), Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))}},
		{"empty signature", verifyRequest{Username: user.username, Nonce: base64.StdEncoding.EncodeToString(make([]byte, challengeNonceSize)), Signature: ""}},
		{"wrong length signature", verifyRequest{Username: user.username, Nonce: base64.StdEncoding.EncodeToString(make([]byte, challengeNonceSize)), Signature: base64.StdEncoding.EncodeToString([]byte("short"))}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doVerify(t, h, tc.req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

// TestChallengeReturnsUserSpecificMaterial confirms the happy-path response
// actually carries this user's real salt/params/wrapped keys, not the
// unknown-username placeholder shape -- reading the stored item directly
// via a raw client, independent of the handler under test.
func TestChallengeReturnsUserSpecificMaterial(t *testing.T) {
	table := testTableName()
	ddb := rawDDB(t)
	h := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, h)

	out, err := ddb.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + user.userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("GetItem: %v", err)
	}
	var stored models.User
	if err := attributevalue.UnmarshalMap(out.Item, &stored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rec := doChallenge(t, h, user.username)
	var ch challengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatalf("decoding challenge response: %v", err)
	}

	if ch.Salt != base64.StdEncoding.EncodeToString(stored.Salt) {
		t.Errorf("Salt does not match the stored value")
	}
	if ch.WrappedPrivateKeys.Ciphertext != base64.StdEncoding.EncodeToString(stored.WrappedPrivateKeys.Ciphertext) {
		t.Errorf("WrappedPrivateKeys.Ciphertext does not match the stored value")
	}
	if ch.Argon2Params.MemoryKiB != stored.Argon2Params.MemoryKiB {
		t.Errorf("Argon2Params.MemoryKiB = %d, want %d", ch.Argon2Params.MemoryKiB, stored.Argon2Params.MemoryKiB)
	}
}
