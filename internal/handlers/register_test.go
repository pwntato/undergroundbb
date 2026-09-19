package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/models"
)

// testDB builds a *db.Client against DYNAMODB_ENDPOINT, skipping when unset
// -- same convention as internal/db's own tests, since register needs a
// real table to exercise the transaction against.
func testDB(t *testing.T) *db.Client {
	t.Helper()
	c, err := db.New(context.Background(), testTableName(), testEndpoint(t))
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	return c
}

// testEndpoint returns DYNAMODB_ENDPOINT, skipping the test when it isn't
// set.
func testEndpoint(t *testing.T) string {
	t.Helper()
	endpoint := os.Getenv("DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Skip("DYNAMODB_ENDPOINT not set; run `docker compose up -d && ./scripts/local-setup.sh`")
	}
	return endpoint
}

func testTableName() string {
	if table := os.Getenv("TABLE_NAME"); table != "" {
		return table
	}
	return "undergroundbb"
}

// rawDDB builds a plain SDK client against the same DynamoDB Local instance
// db.Client uses. db.Client deliberately exposes no way to reach its
// underlying *dynamodb.Client -- it is a data-access layer, not a general
// escape hatch -- so a test that needs to read back exactly what got stored
// (bypassing any application-level read path, which doesn't exist yet for
// PROFILE/CLAIM) builds its own client the same way db.New does internally.
func rawDDB(t *testing.T) *dynamodb.Client {
	t.Helper()
	endpoint := testEndpoint(t)
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	return dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})
}

func b64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func randomUsername(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("randomUsername: %v", err)
	}
	return "user" + hex.EncodeToString(b[:])
}

func validRegisterRequest(username string) registerRequest {
	params := argon2Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 1}
	return registerRequest{
		Username:          username,
		SigningPublicKey:  b64(32),
		WrappingPublicKey: b64(32),

		Salt:               b64(16),
		Argon2Params:       params,
		WrappedPrivateKeys: wrappedBlob{Nonce: b64(12), Ciphertext: b64(48)},

		RecoverySalt:               b64(16),
		RecoveryArgon2Params:       params,
		RecoveryWrappedPrivateKeys: wrappedBlob{Nonce: b64(12), Ciphertext: b64(48)},
	}
}

func doRegister(t *testing.T, h *Handler, req registerRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(body)))
	return rec
}

func TestRegisterSuccess(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	rec := doRegister(t, h, validRegisterRequest(randomUsername(t)))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var body registerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body.UserID == "" {
		t.Error("userId was empty")
	}
}

func TestRegisterClosedPolicy(t *testing.T) {
	t.Setenv("REGISTRATION_POLICY", "closed")
	h := New(config.FromEnv(), testDB(t))
	rec := doRegister(t, h, validRegisterRequest(randomUsername(t)))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRegisterUsernameConflict(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	username := randomUsername(t)

	first := doRegister(t, h, validRegisterRequest(username))
	if first.Code != http.StatusCreated {
		t.Fatalf("first register status = %d, want %d, body: %s", first.Code, http.StatusCreated, first.Body.String())
	}

	// Same username, different case -- claims fold case, so this must
	// conflict too, per docs/DESIGN.md "Usernames are unique
	// case-insensitively."
	second := doRegister(t, h, validRegisterRequest(upperFirst(username)))
	if second.Code != http.StatusConflict {
		t.Errorf("second register status = %d, want %d, body: %s", second.Code, http.StatusConflict, second.Body.String())
	}
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'a' && b[0] <= 'z' {
		b[0] -= 'a' - 'A'
	}
	return string(b)
}

func TestRegisterValidation(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))

	cases := []struct {
		name string
		mod  func(*registerRequest)
	}{
		{"empty username", func(r *registerRequest) { r.Username = "" }},
		{"short username", func(r *registerRequest) { r.Username = "ab" }},
		{"username with spaces", func(r *registerRequest) { r.Username = "has space" }},
		{"missing signing key", func(r *registerRequest) { r.SigningPublicKey = "" }},
		{"wrong length signing key", func(r *registerRequest) { r.SigningPublicKey = b64(16) }},
		{"not base64 signing key", func(r *registerRequest) { r.SigningPublicKey = "not-valid-base64!!" }},
		{"missing wrapping key", func(r *registerRequest) { r.WrappingPublicKey = "" }},
		{"missing salt", func(r *registerRequest) { r.Salt = "" }},
		{"zero argon2 memory", func(r *registerRequest) { r.Argon2Params.MemoryKiB = 0 }},
		{"negative argon2 iterations", func(r *registerRequest) { r.Argon2Params.Iterations = -1 }},
		{"wrong nonce length", func(r *registerRequest) { r.WrappedPrivateKeys.Nonce = b64(4) }},
		{"missing recovery salt", func(r *registerRequest) { r.RecoverySalt = "" }},
		{"zero recovery argon2 params", func(r *registerRequest) { r.RecoveryArgon2Params.Parallelism = 0 }},
		{"argon2 memory below floor", func(r *registerRequest) { r.Argon2Params.MemoryKiB = 1024 }},
		{"argon2 iterations below floor", func(r *registerRequest) { r.Argon2Params.Iterations = 1 }},
		{"recovery argon2 below floor", func(r *registerRequest) { r.RecoveryArgon2Params.MemoryKiB = 1024 }},
		{"salt over max length", func(r *registerRequest) { r.Salt = b64(maxSaltLen + 1) }},
		{"ciphertext over max length", func(r *registerRequest) {
			r.WrappedPrivateKeys.Ciphertext = b64(maxCiphertextLen + 1)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validRegisterRequest(randomUsername(t))
			tc.mod(&req)
			rec := doRegister(t, h, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

func TestRegisterMalformedBody(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader([]byte("not json"))))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// TestRegisterBodyTooLarge covers the maxRegisterBodyBytes cap -- a body
// this oversized couldn't be a legitimate request (the real payload is a
// handful of ~32-100 byte fields), and without the cap it would previously
// reach DynamoDB's own 400 KB item-size limit and surface as an
// unactionable 500 rather than a 400 the caller could act on.
func TestRegisterBodyTooLarge(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	req := validRegisterRequest(randomUsername(t))
	req.WrappedPrivateKeys.Ciphertext = b64(maxRegisterBodyBytes + 1024)

	rec := doRegister(t, h, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestRegisterPreservesUsernameCase covers the split docs/DESIGN.md
// requires: the PROFILE item's Username is stored and displayed as typed,
// while uniqueness and login lookup go through the lowercased claim.
// internal/db's TestRegisterWritesAllThreeItems already checks that all
// three items exist; this checks the handler's actual stored *values* on
// the success path, since a case-folding bug (e.g. lowercasing before
// storing on PROFILE too) wouldn't fail any existing assertion.
func TestRegisterPreservesUsernameCase(t *testing.T) {
	table := testTableName()
	ddb := rawDDB(t)
	h := New(config.FromEnv(), testDB(t))

	mixedCase := "MixedCase" + randomUsername(t)
	rec := doRegister(t, h, validRegisterRequest(mixedCase))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var resp registerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding body: %v", err)
	}

	userOut, err := ddb.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + resp.UserID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("GetItem PROFILE: %v", err)
	}
	var user models.User
	if err := attributevalue.UnmarshalMap(userOut.Item, &user); err != nil {
		t.Fatalf("unmarshal PROFILE: %v", err)
	}
	if user.Username != mixedCase {
		t.Errorf("PROFILE Username = %q, want %q (typed case preserved)", user.Username, mixedCase)
	}

	claimOut, err := ddb.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USERNAME#" + lowerASCII(mixedCase)},
			"SK": &types.AttributeValueMemberS{Value: "CLAIM"},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("GetItem CLAIM: %v", err)
	}
	var claim models.UsernameClaim
	if err := attributevalue.UnmarshalMap(claimOut.Item, &claim); err != nil {
		t.Fatalf("unmarshal CLAIM: %v", err)
	}
	if claim.UserID != resp.UserID {
		t.Errorf("CLAIM UserID = %q, want %q", claim.UserID, resp.UserID)
	}
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
