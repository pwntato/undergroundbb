package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/models"
)

// validCredentialRewrapFields returns a plausible, valid re-wrap payload --
// the same shape validRegisterRequest uses for the identical fields, since
// decodeCredentialRewrapFields applies the exact same checks register.go's
// handler does.
func validCredentialRewrapFields() credentialRewrapFields {
	params := argon2Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 1}
	return credentialRewrapFields{
		Salt:               b64(16),
		Argon2Params:       params,
		WrappedPrivateKeys: wrappedBlob{Nonce: b64(12), Ciphertext: b64(48)},

		RecoverySalt:               b64(16),
		RecoveryArgon2Params:       params,
		RecoveryWrappedPrivateKeys: wrappedBlob{Nonce: b64(12), Ciphertext: b64(48)},

		RecoveryVerifierSalt:   b64(16),
		RecoveryVerifierParams: params,
		RecoveryVerifier:       b64(32),
	}
}

func doChangePassword(t *testing.T, h *Handler, cookie *http.Cookie, req changePasswordRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPut, "/api/account/password", bytes.NewReader(body))
	if cookie != nil {
		httpReq.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, httpReq)
	return rec
}

// loggedInUser registers and logs in a fresh user, returning both the
// registered identity and a valid session cookie -- the fixture every
// changePassword test needs, since the endpoint requires both.
func loggedInUser(t *testing.T, h *Handler) (registeredUser, *http.Cookie) {
	t.Helper()
	user := registerTestUser(t, h)
	loginRec := completeLogin(t, h, user)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d, body: %s", loginRec.Code, http.StatusOK, loginRec.Body.String())
	}
	cookie := sessionCookieFrom(loginRec)
	if cookie == nil {
		t.Fatal("no session cookie set by login")
	}
	return user, cookie
}

func TestChangePasswordSuccess(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	_, cookie := loggedInUser(t, h)

	rec := doChangePassword(t, h, cookie, changePasswordRequest{
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
}

// TestChangePasswordStaleVersionConflicts covers the HTTP-layer mapping of
// db.ErrCredentialVersionStale -> 409, with the exact message
// docs/DESIGN.md requires the user be told.
func TestChangePasswordStaleVersionConflicts(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	_, cookie := loggedInUser(t, h)

	first := doChangePassword(t, h, cookie, changePasswordRequest{
		ExpectedCredentialVersion: 1,
		credentialRewrapFields:    validCredentialRewrapFields(),
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first change status = %d, want %d, body: %s", first.Code, http.StatusOK, first.Body.String())
	}

	// Second call still claims version 1 -- stale, since the first call
	// already bumped it to 2.
	second := doChangePassword(t, h, cookie, changePasswordRequest{
		ExpectedCredentialVersion: 1,
		credentialRewrapFields:    validCredentialRewrapFields(),
	})
	if second.Code != http.StatusConflict {
		t.Fatalf("second change status = %d, want %d, body: %s", second.Code, http.StatusConflict, second.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(second.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["error"] != errCredentialVersionStale {
		t.Errorf("error = %q, want %q", body["error"], errCredentialVersionStale)
	}
}

func TestChangePasswordRequiresSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))

	rec := doChangePassword(t, h, nil, changePasswordRequest{
		ExpectedCredentialVersion: 1,
		credentialRewrapFields:    validCredentialRewrapFields(),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestChangePasswordCannotActOnAnotherAccount confirms the session cookie,
// not a client-supplied field, is what decides whose credentials get
// rewritten -- there is no userId field in changePasswordRequest at all,
// but this pins the property rather than leaving it merely implicit in the
// request shape. Asserts the victim's own PROFILE.Salt is untouched by the
// attacker's own successful change.
func TestChangePasswordCannotActOnAnotherAccount(t *testing.T) {
	table := testTableName()
	ddb := rawDDB(t)
	h := New(config.FromEnv(), testDB(t))
	victim := registerTestUser(t, h)
	_, attackerCookie := loggedInUser(t, h)

	victimBefore, err := ddb.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + victim.userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("GetItem victim PROFILE before: %v", err)
	}
	var beforeUser models.User
	if err := attributevalue.UnmarshalMap(victimBefore.Item, &beforeUser); err != nil {
		t.Fatalf("unmarshal victim PROFILE before: %v", err)
	}

	rec := doChangePassword(t, h, attackerCookie, changePasswordRequest{
		ExpectedCredentialVersion: 1,
		credentialRewrapFields:    validCredentialRewrapFields(),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	victimAfter, err := ddb.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + victim.userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("GetItem victim PROFILE after: %v", err)
	}
	var afterUser models.User
	if err := attributevalue.UnmarshalMap(victimAfter.Item, &afterUser); err != nil {
		t.Fatalf("unmarshal victim PROFILE after: %v", err)
	}
	if string(afterUser.Salt) != string(beforeUser.Salt) {
		t.Error("victim's PROFILE Salt changed as a side effect of the attacker's own password change")
	}
	if afterUser.CredentialVersion != beforeUser.CredentialVersion {
		t.Errorf("victim's CredentialVersion changed: before=%d after=%d", beforeUser.CredentialVersion, afterUser.CredentialVersion)
	}
}

// TestChangePasswordThenLoginReflectsNewVersion covers the end-to-end
// contract the change-password UI depends on: verifyResponse.CredentialVersion
// is the only route by which a client that logs in normally (as opposed to
// recovering) learns the value to submit as changePasswordRequest's
// ExpectedCredentialVersion. If a change-password re-wrap bumped the stored
// version but a subsequent login's verify response did not reflect it, the
// client's next password change would submit a stale value and fail its
// condition every time.
func TestChangePasswordThenLoginReflectsNewVersion(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)

	changeRec := doChangePassword(t, h, cookie, changePasswordRequest{
		ExpectedCredentialVersion: 1,
		credentialRewrapFields:    validCredentialRewrapFields(),
	})
	if changeRec.Code != http.StatusOK {
		t.Fatalf("change status = %d, want %d, body: %s", changeRec.Code, http.StatusOK, changeRec.Body.String())
	}

	loginRec := completeLogin(t, h, user)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("re-login status = %d, want %d, body: %s", loginRec.Code, http.StatusOK, loginRec.Body.String())
	}
	var resp verifyResponse
	if err := json.Unmarshal(loginRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding verify response: %v", err)
	}
	if resp.CredentialVersion != 2 {
		t.Errorf("post-change login CredentialVersion = %d, want 2", resp.CredentialVersion)
	}
}

func doGetAccountCredentials(t *testing.T, h *Handler, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodGet, "/api/account/credentials", nil)
	if cookie != nil {
		httpReq.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, httpReq)
	return rec
}

// TestGetAccountCredentialsSuccess covers #131's bootstrap endpoint: a
// logged-in caller reading back exactly the Salt/Argon2Params/
// WrappedPrivateKeys/CredentialVersion register() wrote, the same shape
// challengeResponse hands an unauthenticated login attempt plus the
// CredentialVersion field that response omits. Compares Salt against a
// fresh doChallenge call for the same username -- both read the identical
// PROFILE item, so they must agree, and challengeResponse is already the
// established way these tests pin a registered user's stored salt.
func TestGetAccountCredentialsSuccess(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)

	rec := doGetAccountCredentials(t, h, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp accountCredentialsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.CredentialVersion != 1 {
		t.Errorf("CredentialVersion = %d, want 1", resp.CredentialVersion)
	}
	if resp.UserID != user.userID {
		t.Errorf("UserID = %q, want %q", resp.UserID, user.userID)
	}

	challengeRec := doChallenge(t, h, user.username)
	var challengeResp challengeResponse
	if err := json.Unmarshal(challengeRec.Body.Bytes(), &challengeResp); err != nil {
		t.Fatalf("decoding challenge response: %v", err)
	}
	if resp.Salt != challengeResp.Salt {
		t.Errorf("Salt = %q, want %q (from challenge for the same user)", resp.Salt, challengeResp.Salt)
	}
}

// TestGetAccountCredentialsReflectsChangedVersion confirms a caller who
// changes their password and then re-reads this endpoint sees the bumped
// CredentialVersion and new Salt -- the property a change-password screen
// that re-opens after a successful change (or a second device) depends on.
func TestGetAccountCredentialsReflectsChangedVersion(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	_, cookie := loggedInUser(t, h)

	fields := validCredentialRewrapFields()
	changeRec := doChangePassword(t, h, cookie, changePasswordRequest{
		ExpectedCredentialVersion: 1,
		credentialRewrapFields:    fields,
	})
	if changeRec.Code != http.StatusOK {
		t.Fatalf("change status = %d, want %d, body: %s", changeRec.Code, http.StatusOK, changeRec.Body.String())
	}

	rec := doGetAccountCredentials(t, h, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp accountCredentialsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.CredentialVersion != 2 {
		t.Errorf("CredentialVersion = %d, want 2", resp.CredentialVersion)
	}
	if resp.Salt != fields.Salt {
		t.Errorf("Salt = %q, want %q (the salt just written by change-password)", resp.Salt, fields.Salt)
	}
}

func TestGetAccountCredentialsRequiresSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))

	rec := doGetAccountCredentials(t, h, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestGetAccountCredentialsCannotReadAnotherAccount confirms the session
// cookie is what decides whose credentials come back -- there is no userId
// query param or body field at all, but this pins the property the same way
// TestChangePasswordCannotActOnAnotherAccount pins it for the write side.
// Compares against the victim's real salt via doChallenge, the established
// way these tests read back a registered user's stored salt.
func TestGetAccountCredentialsCannotReadAnotherAccount(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	victim := registerTestUser(t, h)
	_, attackerCookie := loggedInUser(t, h)

	victimChallengeRec := doChallenge(t, h, victim.username)
	var victimChallengeResp challengeResponse
	if err := json.Unmarshal(victimChallengeRec.Body.Bytes(), &victimChallengeResp); err != nil {
		t.Fatalf("decoding victim challenge response: %v", err)
	}

	rec := doGetAccountCredentials(t, h, attackerCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp accountCredentialsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Salt == victimChallengeResp.Salt {
		t.Error("attacker's own GET /api/account/credentials returned the victim's salt")
	}
	if resp.UserID == victim.userID {
		t.Error("attacker's own GET /api/account/credentials returned the victim's userId")
	}
}

func TestChangePasswordValidation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	_, cookie := loggedInUser(t, h)

	cases := []struct {
		name string
		mod  func(*changePasswordRequest)
	}{
		{"zero expected version", func(r *changePasswordRequest) { r.ExpectedCredentialVersion = 0 }},
		{"negative expected version", func(r *changePasswordRequest) { r.ExpectedCredentialVersion = -1 }},
		{"missing salt", func(r *changePasswordRequest) { r.Salt = "" }},
		{"zero argon2 params", func(r *changePasswordRequest) { r.Argon2Params.Iterations = 0 }},
		{"argon2 below floor", func(r *changePasswordRequest) { r.Argon2Params.MemoryKiB = 1024 }},
		{"missing recovery salt", func(r *changePasswordRequest) { r.RecoverySalt = "" }},
		{"missing recovery verifier", func(r *changePasswordRequest) { r.RecoveryVerifier = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := changePasswordRequest{ExpectedCredentialVersion: 1, credentialRewrapFields: validCredentialRewrapFields()}
			tc.mod(&req)
			rec := doChangePassword(t, h, cookie, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}
