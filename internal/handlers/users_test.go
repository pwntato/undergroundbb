package handlers

import (
	"context"
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
	"github.com/pwntato/undergroundbb/internal/models"
)

func doGetUser(t *testing.T, h *Handler, cookie *http.Cookie, id string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/users/"+id, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func TestGetUserProjection(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	target := registerTestUser(t, h)
	_, cookie := loggedInUser(t, h)

	rec := doGetUser(t, h, cookie, target.userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var got userProjection
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.UserID != target.userID || got.Username != target.username {
		t.Errorf("identity = %q/%q, want %q/%q", got.UserID, got.Username, target.userID, target.username)
	}
	if got.SigningPublicKey != base64.StdEncoding.EncodeToString(target.signPub) ||
		got.WrappingPublicKey != base64.StdEncoding.EncodeToString(target.wrapPub) {
		t.Errorf("keys do not match registered keys: %+v", got)
	}
	if got.SupersededSigningKeys == nil || len(got.SupersededSigningKeys) != 0 {
		t.Errorf("supersededSigningKeys = %#v, want empty non-nil (serialises as [])", got.SupersededSigningKeys)
	}
}

// The projection is an allowlist: none of the item's secret-bearing fields
// may appear in the body, whatever their JSON names.
func TestGetUserProjectionLeaksNothingElse(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	target := registerTestUser(t, h)
	_, cookie := loggedInUser(t, h)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(doGetUser(t, h, cookie, target.userID).Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"userId": true, "username": true, "signingPublicKey": true, "wrappingPublicKey": true, "supersededSigningKeys": true}
	for k := range raw {
		if !want[k] {
			t.Errorf("unexpected field %q in projection", k)
		}
	}
	if len(raw) != len(want) {
		t.Errorf("got %d fields, want %d", len(raw), len(want))
	}
}

func TestGetUserAuthAndNotFound(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	target := registerTestUser(t, h)
	_, cookie := loggedInUser(t, h)

	if rec := doGetUser(t, h, nil, target.userID); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", rec.Code)
	}
	unknown := doGetUser(t, h, cookie, "3f0c7a52-1111-4222-8333-444455556666")
	malformed := doGetUser(t, h, cookie, "not-a-uuid")
	if unknown.Code != 404 || malformed.Code != 404 {
		t.Fatalf("statuses = %d %d, want 404 both", unknown.Code, malformed.Code)
	}
	if unknown.Body.String() != malformed.Body.String() {
		t.Error("404 bodies differ")
	}
}

// Key rotation (#62) does not exist yet, so the history is written directly.
func TestGetUserServesSupersededKeys(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	target := registerTestUser(t, h)
	_, cookie := loggedInUser(t, h)

	old := []models.SupersededKey{{PublicKey: []byte("old-key-one-32-bytes-long-000000"), From: "2026-01-01T00:00:00Z", Until: "2026-06-01T00:00:00Z"}}
	list, err := attributevalue.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + target.userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		UpdateExpression:          aws.String("SET SupersededSigningKeys = :k"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":k": list},
	})
	if err != nil {
		t.Fatal(err)
	}

	var got userProjection
	if err := json.Unmarshal(doGetUser(t, h, cookie, target.userID).Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.SupersededSigningKeys) != 1 ||
		got.SupersededSigningKeys[0].PublicKey != base64.StdEncoding.EncodeToString(old[0].PublicKey) ||
		got.SupersededSigningKeys[0].From != old[0].From || got.SupersededSigningKeys[0].Until != old[0].Until {
		t.Errorf("superseded = %+v, want %+v", got.SupersededSigningKeys, old)
	}
}
