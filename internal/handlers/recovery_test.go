package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
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
