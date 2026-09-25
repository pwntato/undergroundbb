package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"golang.org/x/crypto/argon2"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// deriveTestVerifier computes what a client's WASM Argon2id call would
// produce for a recovery verifier -- the same derivation
// crypto.CheckRecoveryVerifier performs when checking one, duplicated here
// deliberately rather than imported, so a bug in that derivation can't
// cancel itself out against the same bug in this fixture.
func deriveTestVerifier(code string, salt []byte, params argon2Params) []byte {
	const verifierLen = 32
	return argon2.IDKey([]byte(code), salt, uint32(params.Iterations), uint32(params.MemoryKiB), uint8(params.Parallelism), verifierLen)
}

// recoveryFixture is a registered account plus the plaintext recovery code
// it was registered with and the verifier fields derived from it -- the
// full picture validRegisterRequest's random verifier blob doesn't carry,
// since most register.go tests never need the plaintext code a real
// verifier was computed from. Recovery tests do.
type recoveryFixture struct {
	username     string
	userID       string
	recoveryCode string
}

// registerWithRecoveryCode registers a fresh account with a real,
// self-consistent recovery verifier: it generates a code, derives a
// verifier from it via argon2.IDKey directly (the same computation a
// client's WASM Argon2id call would do -- see crypto.CheckRecoveryVerifier,
// which this must match), and registers with that code's verifier fields.
// Returns the code so tests can present it back to the release/reset
// endpoints.
func registerWithRecoveryCode(t *testing.T, h *Handler) recoveryFixture {
	t.Helper()
	pub, _, err := crypto.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}

	const code = "TESTCODE-1234-5678-ABCD-EFGHJK"
	verifierSalt := []byte("recovery-verifier-salt!")
	// Must meet the same floor register.go's validateArgon2Params enforces
	// on every Argon2id field, including this one -- see
	// decodeCredentialRewrapFields, which applies it uniformly.
	verifierParams := argon2Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 1}
	verifier := deriveTestVerifier(code, verifierSalt, verifierParams)

	username := randomUsername(t)
	req := validRegisterRequest(username)
	req.SigningPublicKey = base64.StdEncoding.EncodeToString(pub)
	req.RecoveryVerifierSalt = base64.StdEncoding.EncodeToString(verifierSalt)
	req.RecoveryVerifierParams = verifierParams
	req.RecoveryVerifier = base64.StdEncoding.EncodeToString(verifier)

	rec := doRegister(t, h, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var resp registerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding register response: %v", err)
	}

	return recoveryFixture{username: username, userID: resp.UserID, recoveryCode: code}
}

func doRecoveryRelease(t *testing.T, h *Handler, req recoveryReleaseRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/account/recovery-code/release", bytes.NewReader(body)))
	return rec
}

func doRecoveryReset(t *testing.T, h *Handler, req recoveryResetRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/account/recovery-code", bytes.NewReader(body)))
	return rec
}

func TestRecoveryReleaseSuccess(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)

	rec := doRecoveryRelease(t, h, recoveryReleaseRequest{
		Username:     fixture.username,
		RecoveryCode: fixture.recoveryCode,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp recoveryReleaseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.CredentialVersion != 1 {
		t.Errorf("CredentialVersion = %d, want 1", resp.CredentialVersion)
	}
	if resp.UserID != fixture.userID {
		t.Errorf("UserID = %q, want %q", resp.UserID, fixture.userID)
	}
	if resp.Salt == "" {
		t.Error("Salt is empty")
	}
	if resp.WrappedPrivateKeys.Ciphertext == "" {
		t.Error("WrappedPrivateKeys.Ciphertext is empty")
	}
}

func TestRecoveryReleaseWrongCodeFails(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)

	rec := doRecoveryRelease(t, h, recoveryReleaseRequest{
		Username:     fixture.username,
		RecoveryCode: "WRONGCODE-0000-0000-0000-000000",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["error"] != errRecoveryCodeInvalid {
		t.Errorf("error = %q, want %q", body["error"], errRecoveryCodeInvalid)
	}
}

// TestRecoveryLockoutAfterThreshold covers issue #136: resolveRecovery's own
// account-level guard on recovery-code guessing, mirroring
// TestLockoutAfterFiveFailures in login_test.go -- recovery uses its own,
// much looser recoveryLockThreshold/recoveryLockDuration rather than
// login's five-attempts-in-five-minutes (round 2 review: at 128 bits, a
// tight lock buys the code no real brute-force resistance it doesn't
// already have, but does add a griefing vector against a known username).
// Unlike login, a locked RECOVERY item does NOT get a distinguishable
// status -- resolveRecovery returns the same errInvalidRecoveryAttempt/401
// uniform response as a wrong code, deliberately (see resolveRecovery's own
// doc comment on why a distinguishable "locked" response would be a new
// oracle). So this pins the externally-observable behavior: after
// recoveryLockThreshold wrong-code attempts, even the CORRECT code is
// rejected with the same uniform error, until the lock would expire.
func TestRecoveryLockoutAfterThreshold(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)

	for i := range recoveryLockThreshold {
		rec := doRecoveryRelease(t, h, recoveryReleaseRequest{
			Username:     fixture.username,
			RecoveryCode: "WRONGCODE-0000-0000-0000-000000",
		})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: status = %d, want %d, body: %s", i+1, rec.Code, http.StatusUnauthorized, rec.Body.String())
		}
	}

	// Now present the REAL code -- must still be rejected as locked, exactly
	// like a wrong code, even though it would otherwise succeed.
	rec := doRecoveryRelease(t, h, recoveryReleaseRequest{
		Username:     fixture.username,
		RecoveryCode: fixture.recoveryCode,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("locked-account release status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["error"] != errRecoveryCodeInvalid {
		t.Errorf("error = %q, want %q (uniform, no lockout-specific message)", body["error"], errRecoveryCodeInvalid)
	}
}

// TestRecoveryLockoutDoesNotAffectLogin confirms RECOVERY's lockout is
// independent of login's -- the entire reason #136 added a separate counter
// (see resolveRecovery's doc comment) rather than reusing
// User.FailedVerifyCount/LockUntil. Asserts on PROFILE directly rather than
// going through /auth/challenge: that endpoint never consults LockUntil at
// all (the lock is enforced at verify, step 4, only -- DESIGN.md, "the lock
// is enforced at step 4 only"), so a challenge call can't actually detect a
// regression that routes recovery failures into User's counter instead of
// RECOVERY's -- round 1 review, caught by mutating resolveRecovery to call
// RecordFailedVerify and finding this test still passed.
func TestRecoveryLockoutDoesNotAffectLogin(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)

	for range recoveryLockThreshold {
		doRecoveryRelease(t, h, recoveryReleaseRequest{
			Username:     fixture.username,
			RecoveryCode: "WRONGCODE-0000-0000-0000-000000",
		})
	}

	user, err := h.db.LookupUserByUsername(context.Background(), fixture.username)
	if err != nil {
		t.Fatalf("LookupUserByUsername: %v", err)
	}
	if user.FailedVerifyCount != 0 {
		t.Errorf("User.FailedVerifyCount = %d, want 0 -- recovery failures must not touch the login counter", user.FailedVerifyCount)
	}
	if user.LockUntil != "" {
		t.Errorf("User.LockUntil = %q, want empty -- recovery failures must never lock login", user.LockUntil)
	}
}

// TestRecoveryReleaseSuccessClearsLockoutCounter confirms a successful
// release resets RECOVERY's FailedVerifyCount/LockUntil (issue #136,
// mirroring login's ClearFailedVerify-on-success), so a legitimate user who
// mistyped their code a few times before getting it right isn't left with a
// partially-spent guessing budget indefinitely.
func TestRecoveryReleaseSuccessClearsLockoutCounter(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)

	for i := 0; i < recoveryLockThreshold-1; i++ {
		rec := doRecoveryRelease(t, h, recoveryReleaseRequest{
			Username:     fixture.username,
			RecoveryCode: "WRONGCODE-0000-0000-0000-000000",
		})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: status = %d, want %d", i+1, rec.Code, http.StatusUnauthorized)
		}
	}

	// One below threshold, then a real success -- must succeed (not yet
	// locked) and must clear the counter rather than leaving it primed.
	success := doRecoveryRelease(t, h, recoveryReleaseRequest{
		Username:     fixture.username,
		RecoveryCode: fixture.recoveryCode,
	})
	if success.Code != http.StatusOK {
		t.Fatalf("success status = %d, want %d, body: %s", success.Code, http.StatusOK, success.Body.String())
	}

	// Confirm the counter actually reset: it should now take a fresh
	// recoveryLockThreshold-many failures to lock, not just one more.
	for i := range recoveryLockThreshold - 1 {
		rec := doRecoveryRelease(t, h, recoveryReleaseRequest{
			Username:     fixture.username,
			RecoveryCode: "WRONGCODE-0000-0000-0000-000000",
		})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("post-clear failure %d: status = %d, want %d", i+1, rec.Code, http.StatusUnauthorized)
		}
	}
	stillGood := doRecoveryRelease(t, h, recoveryReleaseRequest{
		Username:     fixture.username,
		RecoveryCode: fixture.recoveryCode,
	})
	if stillGood.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (counter should have been cleared by the earlier success, not still primed toward a lock)", stillGood.Code, http.StatusOK)
	}
}

// TestRecoveryReleaseUnknownUsernameSameError confirms an unknown username
// gets the exact same response as a wrong code for a real one -- see
// errRecoveryCodeInvalid's own doc comment on why the two must be
// indistinguishable.
func TestRecoveryReleaseUnknownUsernameSameError(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))

	rec := doRecoveryRelease(t, h, recoveryReleaseRequest{
		Username:     randomUsername(t),
		RecoveryCode: "SOME-CODE-0000-0000-0000-000000",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["error"] != errRecoveryCodeInvalid {
		t.Errorf("error = %q, want %q", body["error"], errRecoveryCodeInvalid)
	}
}

func TestRecoveryReleaseMissingCode(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	rec := doRecoveryRelease(t, h, recoveryReleaseRequest{Username: randomUsername(t), RecoveryCode: ""})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestRecoveryResetSuccess(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)

	rec := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              fixture.recoveryCode,
		ExpectedCredentialVersion: 1,
		credentialRewrapFields:    validCredentialRewrapFields(),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp changePasswordResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.CredentialVersion != 2 {
		t.Errorf("CredentialVersion = %d, want 2", resp.CredentialVersion)
	}

	// The old code must no longer work -- reset issues a new one and
	// invalidates the old, per docs/DESIGN.md.
	staleRelease := doRecoveryRelease(t, h, recoveryReleaseRequest{
		Username:     fixture.username,
		RecoveryCode: fixture.recoveryCode,
	})
	if staleRelease.Code != http.StatusUnauthorized {
		t.Errorf("release with old code after reset: status = %d, want %d, body: %s", staleRelease.Code, http.StatusUnauthorized, staleRelease.Body.String())
	}
}

func TestRecoveryResetWrongCodeFails(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)

	rec := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              "WRONGCODE-0000-0000-0000-000000",
		ExpectedCredentialVersion: 1,
		credentialRewrapFields:    validCredentialRewrapFields(),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestRecoveryResetStaleVersionConflicts mirrors
// TestChangePasswordStaleVersionConflicts for the recovery-reset path --
// the same contested write, reached from the other authenticating flow.
func TestRecoveryResetStaleVersionConflicts(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)

	first := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              fixture.recoveryCode,
		ExpectedCredentialVersion: 1,
		credentialRewrapFields:    validCredentialRewrapFields(),
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first reset status = %d, want %d, body: %s", first.Code, http.StatusOK, first.Body.String())
	}

	// Second attempt with the (now stale) old code AND the old expected
	// version both fail -- the code fails first (it no longer matches the
	// rotated verifier), which is the more informative rejection to check.
	second := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              fixture.recoveryCode,
		ExpectedCredentialVersion: 1,
		credentialRewrapFields:    validCredentialRewrapFields(),
	})
	if second.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d, body: %s", second.Code, http.StatusUnauthorized, second.Body.String())
	}
}

func TestRecoveryResetValidation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)

	cases := []struct {
		name string
		mod  func(*recoveryResetRequest)
	}{
		{"empty code", func(r *recoveryResetRequest) { r.RecoveryCode = "" }},
		{"zero expected version", func(r *recoveryResetRequest) { r.ExpectedCredentialVersion = 0 }},
		{"missing salt", func(r *recoveryResetRequest) { r.Salt = "" }},
		{"missing recovery verifier", func(r *recoveryResetRequest) { r.RecoveryVerifier = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := recoveryResetRequest{
				Username:                  fixture.username,
				RecoveryCode:              fixture.recoveryCode,
				ExpectedCredentialVersion: 1,
				credentialRewrapFields:    validCredentialRewrapFields(),
			}
			tc.mod(&req)
			rec := doRecoveryReset(t, h, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

// TestRecoveryDoesNotRequireSession confirms the whole point of this flow:
// it must work with no session cookie at all, since a user who forgot their
// password has none -- see docs/DESIGN.md, "a user recovering has no
// session and no password."
func TestRecoveryDoesNotRequireSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	body, _ := json.Marshal(recoveryReleaseRequest{Username: fixture.username, RecoveryCode: fixture.recoveryCode})
	req := httptest.NewRequest(http.MethodPost, "/api/account/recovery-code/release", bytes.NewReader(body))
	// Deliberately no cookie added.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// writeLegacyAccount writes a PROFILE + RECOVERY + USERNAME claim directly
// via a raw DynamoDB client, bypassing register.go entirely -- simulating
// an account created before this PR (or before register.go's zero-byte
// decode fix), whose RECOVERY item has no Verifier/VerifierSalt attributes
// at all. attributevalue.UnmarshalMap leaves those as a nil []byte and a
// zero-value models.Argon2Params on read, which is exactly the input PR
// #118 review found crashed crypto.CheckRecoveryVerifier.
func writeLegacyAccount(t *testing.T, table string, ddb *dynamodb.Client) (username, userID string) {
	t.Helper()
	userID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
	username = randomUsername(t)
	usernameLower := lowerASCII(username)

	user := models.User{
		Record:             models.Record{PK: "USER#" + userID, SK: "PROFILE", Type: "User"},
		Username:           username,
		SigningPublicKey:   make([]byte, 32),
		WrappingPublicKey:  make([]byte, 32),
		Salt:               []byte("legacy-salt"),
		Argon2Params:       models.Argon2Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 1},
		WrappedPrivateKeys: models.WrappedBlob{Nonce: make([]byte, 12), Ciphertext: []byte("legacy-ciphertext")},
		CredentialVersion:  1,
	}
	// Deliberately NOT setting VerifierSalt/VerifierArgon2Params/Verifier --
	// that absence is the whole point of this fixture.
	recovery := models.Recovery{
		Record:             models.Record{PK: "USER#" + userID, SK: "RECOVERY", Type: "Recovery"},
		Salt:               []byte("legacy-recovery-salt"),
		Argon2Params:       models.Argon2Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 1},
		WrappedPrivateKeys: models.WrappedBlob{Nonce: make([]byte, 12), Ciphertext: []byte("legacy-recovery-ciphertext")},
		CredentialVersion:  1,
	}
	claim := models.UsernameClaim{
		Record: models.Record{PK: "USERNAME#" + usernameLower, SK: "CLAIM", Type: "UsernameClaim"},
		UserID: userID,
	}

	for _, item := range []any{user, recovery, claim} {
		av, err := attributevalue.MarshalMap(item)
		if err != nil {
			t.Fatalf("MarshalMap: %v", err)
		}
		if _, err := ddb.PutItem(context.Background(), &dynamodb.PutItemInput{
			TableName: aws.String(table),
			Item:      av,
		}); err != nil {
			t.Fatalf("PutItem: %v", err)
		}
	}
	return username, userID
}

// TestRecoveryReleaseLegacyAccountNoVerifierFails is the direct end-to-end
// regression test for PR #118's blocking finding: a release attempt
// against an account with no stored verifier must return 401 with the same
// errRecoveryCodeInvalid every other failure mode uses, not panic. Before
// crypto.VerifierLen was pinned, this crashed inside
// crypto.CheckRecoveryVerifier's argon2.IDKey call (keyLen derived from a
// nil verifier's zero length) -- cmd/lambda's top-level recover() would
// have turned that into a 500 rather than a dead container, but a 500 is
// still not what this endpoint is supposed to return for "no such recovery
// material," which resolveRecovery's own doc comment already promises a
// uniform answer for.
func TestRecoveryReleaseLegacyAccountNoVerifierFails(t *testing.T) {
	table := testTableName()
	ddb := rawDDB(t)
	h := New(config.FromEnv(), testDB(t))

	username, _ := writeLegacyAccount(t, table, ddb)

	rec := doRecoveryRelease(t, h, recoveryReleaseRequest{
		Username:     username,
		RecoveryCode: "ANY-CODE-0000-0000-0000-000000",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["error"] != errRecoveryCodeInvalid {
		t.Errorf("error = %q, want %q", body["error"], errRecoveryCodeInvalid)
	}
}

// TestRecoveryResetLegacyAccountNoVerifierFails is the reset-path mirror of
// the release-path regression above -- same legacy fixture, same panic
// risk (recoveryCodeReset also calls resolveRecovery), different endpoint.
func TestRecoveryResetLegacyAccountNoVerifierFails(t *testing.T) {
	table := testTableName()
	ddb := rawDDB(t)
	h := New(config.FromEnv(), testDB(t))

	username, _ := writeLegacyAccount(t, table, ddb)

	rec := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  username,
		RecoveryCode:              "ANY-CODE-0000-0000-0000-000000",
		ExpectedCredentialVersion: 1,
		credentialRewrapFields:    validCredentialRewrapFields(),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// testIdempotencyToken returns a base64-encoded value of exactly
// idempotencyTokenLen decoded bytes -- what a real IdempotencyToken looks
// like on the wire.
func testIdempotencyToken(seed byte) string {
	token := make([]byte, idempotencyTokenLen)
	for i := range token {
		token[i] = seed
	}
	return base64.StdEncoding.EncodeToString(token)
}

// TestRecoveryResetRetryWithTokenSucceeds is issue #130's fix: a reset
// retry that presents the same (now-stale, since the first attempt's
// success already rotated it) recovery code, but the same IdempotencyToken
// as the first attempt, must be treated as that attempt's own response
// landing late -- not a fresh authentication failure. Mirrors
// TestRegisterRetryAfterLostResponseSucceeds's shape (#124) at the handler
// layer.
func TestRecoveryResetRetryWithTokenSucceeds(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)
	token := testIdempotencyToken(0xAB)
	fields := validCredentialRewrapFields()

	first := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              fixture.recoveryCode,
		ExpectedCredentialVersion: 1,
		IdempotencyToken:          token,
		credentialRewrapFields:    fields,
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first reset status = %d, want %d, body: %s", first.Code, http.StatusOK, first.Body.String())
	}
	var firstResp changePasswordResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstResp); err != nil {
		t.Fatalf("decoding first response: %v", err)
	}

	// The identical retry: same (now-stale) code, same token, same
	// expectedCredentialVersion, same credential fields -- exactly what a
	// client resending after a lost response sends, per runRecovery.ts's own
	// comment on why the code is unchanged (the client never learned the
	// new one).
	second := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              fixture.recoveryCode,
		ExpectedCredentialVersion: 1,
		IdempotencyToken:          token,
		credentialRewrapFields:    fields,
	})
	if second.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want %d (idempotent success), body: %s", second.Code, http.StatusOK, second.Body.String())
	}
	var secondResp changePasswordResponse
	if err := json.Unmarshal(second.Body.Bytes(), &secondResp); err != nil {
		t.Fatalf("decoding retry response: %v", err)
	}
	if secondResp.CredentialVersion != firstResp.CredentialVersion {
		t.Errorf("retry CredentialVersion = %d, want %d (same as first attempt's, not bumped again)", secondResp.CredentialVersion, firstResp.CredentialVersion)
	}

	// GetRecovery directly confirms the retry did not write anything a
	// second time -- CredentialVersion must still be exactly 2, not bumped
	// again by a second successful RewrapCredentials call.
	rec, err := h.db.GetRecovery(context.Background(), fixture.userID)
	if err != nil {
		t.Fatalf("GetRecovery: %v", err)
	}
	if rec.CredentialVersion != 2 {
		t.Errorf("RECOVERY CredentialVersion = %d, want 2 (retry must not re-run the write)", rec.CredentialVersion)
	}
}

// TestRecoveryResetRetrySucceedsWhileLocked pins issue #136's round 1 review
// finding: enough #130 retries DO trip the new (post-reset) RECOVERY item's
// own lockout -- each retry necessarily fails resolveRecovery's verifier
// check first, same as any wrong code would -- but that lockout never blocks
// the retry itself. recoveryCodeReset's IsOwnRewrap fallback is reached on
// every errInvalidRecoveryAttempt, including the locked case, since
// resolveRecovery collapses both into the same uniform error and
// recoveryCodeReset never short-circuits on "locked" before checking the
// fallback. So retries keep succeeding even once they've locked the item
// they're retrying against -- see resolveRecovery's own doc comment for why
// that's safe rather than a bypass (the fallback only replays a success for
// an exact token+version+material match and writes nothing new).
func TestRecoveryResetRetrySucceedsWhileLocked(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)
	token := testIdempotencyToken(0xCD)
	fields := validCredentialRewrapFields()

	first := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              fixture.recoveryCode,
		ExpectedCredentialVersion: 1,
		IdempotencyToken:          token,
		credentialRewrapFields:    fields,
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first reset status = %d, want %d, body: %s", first.Code, http.StatusOK, first.Body.String())
	}

	// More retries than recoveryLockThreshold -- enough that the new
	// RECOVERY item's own lockout counter should trip partway through. Every
	// one of them must still succeed: the retry fallback doesn't care
	// whether resolveRecovery failed because the code is merely stale or
	// because the item is locked.
	for i := 0; i < recoveryLockThreshold+2; i++ {
		retry := doRecoveryReset(t, h, recoveryResetRequest{
			Username:                  fixture.username,
			RecoveryCode:              fixture.recoveryCode,
			ExpectedCredentialVersion: 1,
			IdempotencyToken:          token,
			credentialRewrapFields:    fields,
		})
		if retry.Code != http.StatusOK {
			t.Fatalf("retry %d status = %d, want %d (idempotent success even once locked), body: %s", i+1, retry.Code, http.StatusOK, retry.Body.String())
		}
	}

	// Confirm the item really did lock along the way -- otherwise this test
	// wouldn't actually be exercising the interaction it claims to.
	rec, err := h.db.GetRecovery(context.Background(), fixture.userID)
	if err != nil {
		t.Fatalf("GetRecovery: %v", err)
	}
	if rec.LockUntil == "" {
		t.Error("RECOVERY LockUntil is empty after more than recoveryLockThreshold retries -- test setup didn't actually trip the lockout, so it isn't testing the intended interaction")
	}
}

// TestRecoveryResetRetryWithoutTokenStillFails confirms a retry that
// presents the same stale code but NO token gets the plain, uniform 401 --
// the fallback issue #130 adds must never trigger for a caller that hasn't
// opted in.
func TestRecoveryResetRetryWithoutTokenStillFails(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)
	fields := validCredentialRewrapFields()

	first := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              fixture.recoveryCode,
		ExpectedCredentialVersion: 1,
		credentialRewrapFields:    fields,
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first reset status = %d, want %d, body: %s", first.Code, http.StatusOK, first.Body.String())
	}

	second := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              fixture.recoveryCode,
		ExpectedCredentialVersion: 1,
		credentialRewrapFields:    fields,
	})
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("retry (no token) status = %d, want %d, body: %s", second.Code, http.StatusUnauthorized, second.Body.String())
	}
}

// TestRecoveryResetRetryWithWrongTokenStillFails confirms a retry presenting
// a DIFFERENT token than the first attempt used is not mistaken for that
// attempt's own retry -- a genuinely different (if oddly timed) request must
// still fail like any other wrong code.
func TestRecoveryResetRetryWithWrongTokenStillFails(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)
	fields := validCredentialRewrapFields()

	first := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              fixture.recoveryCode,
		ExpectedCredentialVersion: 1,
		IdempotencyToken:          testIdempotencyToken(0xAB),
		credentialRewrapFields:    fields,
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first reset status = %d, want %d, body: %s", first.Code, http.StatusOK, first.Body.String())
	}

	second := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              fixture.recoveryCode,
		ExpectedCredentialVersion: 1,
		IdempotencyToken:          testIdempotencyToken(0xCD),
		credentialRewrapFields:    fields,
	})
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("retry (wrong token) status = %d, want %d, body: %s", second.Code, http.StatusUnauthorized, second.Body.String())
	}
}

// TestRecoveryResetRetryWithDifferentMaterialStillFails is the handler-level
// twin of db.TestIsOwnRewrapWrongMaterialFails: a retry presenting the SAME
// token but DIFFERENT credential fields than the first attempt must not be
// told "success" for a write that never actually happened with those
// fields -- PR #133 round 1's finding, applied to this fallback too.
func TestRecoveryResetRetryWithDifferentMaterialStillFails(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)
	token := testIdempotencyToken(0xAB)
	fields := validCredentialRewrapFields()

	first := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              fixture.recoveryCode,
		ExpectedCredentialVersion: 1,
		IdempotencyToken:          token,
		credentialRewrapFields:    fields,
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first reset status = %d, want %d, body: %s", first.Code, http.StatusOK, first.Body.String())
	}

	// Same (now-stale) code, same token -- but different credential fields,
	// exactly what a client that re-derived between attempts would send.
	differentFields := validCredentialRewrapFields()
	second := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              fixture.recoveryCode,
		ExpectedCredentialVersion: 1,
		IdempotencyToken:          token,
		credentialRewrapFields:    differentFields,
	})
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("retry (different material) status = %d, want %d, body: %s", second.Code, http.StatusUnauthorized, second.Body.String())
	}

	// The original write's material must be exactly what the FIRST attempt
	// wrote -- the rejected retry must not have overwritten it (it never
	// even reaches RewrapCredentials on this fallback path).
	rec, err := h.db.GetRecovery(context.Background(), fixture.userID)
	if err != nil {
		t.Fatalf("GetRecovery: %v", err)
	}
	if base64.StdEncoding.EncodeToString(rec.Verifier) != fields.RecoveryVerifier {
		t.Errorf("RECOVERY Verifier = %q, want first attempt's %q (unchanged)",
			base64.StdEncoding.EncodeToString(rec.Verifier), fields.RecoveryVerifier)
	}
}

// TestRecoveryResetInvalidTokenLength confirms IdempotencyToken is validated
// like every other base64 field -- a present-but-wrong-length value is a
// 400, not silently ignored or accepted as "no token."
func TestRecoveryResetInvalidTokenLength(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	fixture := registerWithRecoveryCode(t, h)

	rec := doRecoveryReset(t, h, recoveryResetRequest{
		Username:                  fixture.username,
		RecoveryCode:              fixture.recoveryCode,
		ExpectedCredentialVersion: 1,
		IdempotencyToken:          base64.StdEncoding.EncodeToString([]byte("too-short")),
		credentialRewrapFields:    validCredentialRewrapFields(),
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}
