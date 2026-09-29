package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

func doGroupRequest(t *testing.T, h *Handler, cookie *http.Cookie, method, groupID string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, "/api/groups/"+groupID, &buf)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func createPrivateGroup(t *testing.T, h *Handler, user registeredUser, cookie *http.Cookie) string {
	t.Helper()
	req := signedCreateGroupRequest(t, user)
	if rec := doCreateGroup(t, h, cookie, req); rec.Code != http.StatusCreated {
		t.Fatalf("create private group: %d %s", rec.Code, rec.Body.String())
	}
	return req.GroupID
}

func createPublicGroup(t *testing.T, h *Handler, user registeredUser, cookie *http.Cookie) string {
	t.Helper()
	req := signedCreateGroupRequest(t, user)
	req.Visibility = "public"
	req.NameCiphertext, req.DescriptionCiphertext = wrappedBlob{}, wrappedBlob{}
	req.NamePlaintext, req.DescriptionPlaintext = "Book Club", "We read books"
	req.RevocationMode = "open"
	if rec := doCreateGroup(t, h, cookie, req); rec.Code != http.StatusCreated {
		t.Fatalf("create public group: %d %s", rec.Code, rec.Body.String())
	}
	return req.GroupID
}

func decodeDetail(t *testing.T, rec *httptest.ResponseRecorder) groupDetailResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var d groupDetailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return d
}

func TestGetGroupRequiresSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	id, _ := idgen.UUID()
	if rec := doGroupRequest(t, h, nil, http.MethodGet, id, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET status = %d", rec.Code)
	}
	if rec := doGroupRequest(t, h, nil, http.MethodPut, id, updateGroupRequest{}); rec.Code != http.StatusUnauthorized {
		t.Errorf("PUT status = %d", rec.Code)
	}
}

func TestGetGroupMemberPrivate(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, user, cookie)

	d := decodeDetail(t, doGroupRequest(t, h, cookie, http.MethodGet, gid, nil))
	if d.Role != "admin" || d.Visibility != "private" || d.RevocationMode != "rotating" || d.ExpirationDays != 30 || d.Version != 0 {
		t.Errorf("unexpected detail: %+v", d)
	}
	if d.NameCiphertext == nil || d.DescriptionCiphertext == nil || d.WrappedGroupKey == nil {
		t.Error("private detail must carry ciphertext and the caller's wrapped key")
	}
	if d.NamePlaintext != "" {
		t.Error("private detail leaked plaintext")
	}
}

func TestGetGroupPrivateHiddenFromNonMember(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	_, otherCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)

	missing, _ := idgen.UUID()
	rec := doGroupRequest(t, h, otherCookie, http.MethodGet, gid, nil)
	recMissing := doGroupRequest(t, h, otherCookie, http.MethodGet, missing, nil)
	if rec.Code != http.StatusNotFound || recMissing.Code != http.StatusNotFound {
		t.Fatalf("statuses = %d, %d, want 404 both", rec.Code, recMissing.Code)
	}
	if rec.Body.String() != recMissing.Body.String() {
		t.Errorf("private-group 404 differs from nonexistent-group 404:\n%s\n%s", rec.Body.String(), recMissing.Body.String())
	}
	if rec := doGroupRequest(t, h, otherCookie, http.MethodGet, "not-a-uuid", nil); rec.Code != http.StatusNotFound {
		t.Errorf("malformed id status = %d", rec.Code)
	}
}

func TestGetGroupPublicVisibleToNonMember(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	_, otherCookie := loggedInUser(t, h)
	gid := createPublicGroup(t, h, owner, ownerCookie)

	d := decodeDetail(t, doGroupRequest(t, h, otherCookie, http.MethodGet, gid, nil))
	if d.NamePlaintext != "Book Club" || d.RevocationMode != "open" {
		t.Errorf("unexpected detail: %+v", d)
	}
	if d.Role != "" || d.WrappedGroupKey != nil {
		t.Errorf("non-member must get no role or key: %+v", d)
	}
}

func updateReq(version int64) updateGroupRequest {
	return updateGroupRequest{
		Version:               version,
		NameCiphertext:        wrappedBlob{Nonce: b64(12), Ciphertext: b64(40)},
		DescriptionCiphertext: wrappedBlob{Nonce: b64(12), Ciphertext: b64(44)},
		ExpirationDays:        90,
	}
}

func TestUpdateGroupPrivate(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, user, cookie)

	req := updateReq(0)
	if rec := doGroupRequest(t, h, cookie, http.MethodPut, gid, req); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	d := decodeDetail(t, doGroupRequest(t, h, cookie, http.MethodGet, gid, nil))
	if d.Version != 1 || d.ExpirationDays != 90 || d.RevocationMode != "rotating" {
		t.Errorf("after edit: %+v", d)
	}
	if d.NameCiphertext.Ciphertext != req.NameCiphertext.Ciphertext {
		t.Error("name ciphertext was not replaced")
	}

	// A second edit with the now-stale version 0 must conflict.
	rec := doGroupRequest(t, h, cookie, http.MethodPut, gid, updateReq(0))
	if rec.Code != http.StatusConflict {
		t.Errorf("stale PUT status = %d, want 409, body: %s", rec.Code, rec.Body.String())
	}
	if rec := doGroupRequest(t, h, cookie, http.MethodPut, gid, updateReq(1)); rec.Code != http.StatusOK {
		t.Errorf("PUT at current version: %d %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateGroupPublic(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	gid := createPublicGroup(t, h, user, cookie)

	rec := doGroupRequest(t, h, cookie, http.MethodPut, gid, updateGroupRequest{
		NamePlaintext: "Renamed Club", ExpirationDays: 7,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	d := decodeDetail(t, doGroupRequest(t, h, cookie, http.MethodGet, gid, nil))
	if d.NamePlaintext != "Renamed Club" || d.DescriptionPlaintext != "" || d.ExpirationDays != 7 || d.RevocationMode != "open" {
		t.Errorf("after edit: %+v", d)
	}
}

func TestUpdateGroupNonMemberAccess(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	_, otherCookie := loggedInUser(t, h)
	priv := createPrivateGroup(t, h, owner, ownerCookie)
	pub := createPublicGroup(t, h, owner, ownerCookie)

	if rec := doGroupRequest(t, h, otherCookie, http.MethodPut, priv, updateReq(0)); rec.Code != http.StatusNotFound {
		t.Errorf("private, non-member: %d, want 404", rec.Code)
	}
	rec := doGroupRequest(t, h, otherCookie, http.MethodPut, pub, updateGroupRequest{NamePlaintext: "Mine now", ExpirationDays: 30})
	if rec.Code != http.StatusForbidden {
		t.Errorf("public, non-member: %d, want 403", rec.Code)
	}
}

func TestUpdateGroupValidation(t *testing.T) {
	cfg := config.FromEnv()
	cfg.AllowGroupExpirationOff = false
	h := New(cfg, testDB(t))
	user, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, user, cookie)

	cases := map[string]func(*updateGroupRequest){
		"expiration off":       func(r *updateGroupRequest) { r.ExpirationDays = 0 },
		"expiration too large": func(r *updateGroupRequest) { r.ExpirationDays = maxExpirationDays + 1 },
		"plaintext on private": func(r *updateGroupRequest) { r.NamePlaintext = "x" },
		"wrong generation":     func(r *updateGroupRequest) { r.NameGeneration = 3 },
		"missing ciphertext":   func(r *updateGroupRequest) { r.NameCiphertext = wrappedBlob{} },
		"negative version":     func(r *updateGroupRequest) { r.Version = -1 },
	}
	for name, mutate := range cases {
		req := updateReq(0)
		mutate(&req)
		if rec := doGroupRequest(t, h, cookie, http.MethodPut, gid, req); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400, body: %s", name, rec.Code, rec.Body.String())
		}
	}
	// Nothing above may have been written.
	if d := decodeDetail(t, doGroupRequest(t, h, cookie, http.MethodGet, gid, nil)); d.Version != 0 || d.ExpirationDays != 30 {
		t.Errorf("rejected edits changed the group: %+v", d)
	}
}

// Revocation mode is not editable: a body that tries to set it is ignored.
func TestUpdateGroupIgnoresRevocationMode(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, user, cookie)

	body := map[string]any{
		"version":               0,
		"nameCiphertext":        updateReq(0).NameCiphertext,
		"descriptionCiphertext": updateReq(0).DescriptionCiphertext,
		"expirationDays":        30,
		"revocationMode":        "open",
	}
	if rec := doGroupRequest(t, h, cookie, http.MethodPut, gid, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	if d := decodeDetail(t, doGroupRequest(t, h, cookie, http.MethodGet, gid, nil)); d.RevocationMode != "rotating" {
		t.Errorf("revocationMode = %q, want rotating", d.RevocationMode)
	}
}

func TestUpdateGroupExpirationOffAllowedWhenConfigured(t *testing.T) {
	cfg := config.FromEnv()
	cfg.AllowGroupExpirationOff = true
	h := New(cfg, testDB(t))
	user, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, user, cookie)

	req := updateReq(0)
	req.ExpirationDays = 0
	if rec := doGroupRequest(t, h, cookie, http.MethodPut, gid, req); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
}

// The list entry must carry nameGeneration (PR #148 review): the name's AAD
// uses it, not the member's generation, once rotation makes them differ.
func TestListGroupsIncludesNameGeneration(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	createPrivateGroup(t, h, user, cookie)

	rec := doListGroups(t, h, cookie)
	var raw struct {
		Groups []map[string]any `json:"groups"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil || len(raw.Groups) != 1 {
		t.Fatalf("decode: %v, body: %s", err, rec.Body.String())
	}
	if _, ok := raw.Groups[0]["nameGeneration"]; !ok {
		t.Errorf("list entry has no nameGeneration: %v", raw.Groups[0])
	}
}

func TestUpdateGroupRejectsDirectMessage(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, user, cookie)

	_, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + gid},
			"SK": &types.AttributeValueMemberS{Value: "META"},
		},
		UpdateExpression:          aws.String("SET GroupType = :dm"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":dm": &types.AttributeValueMemberS{Value: "dm"}},
	})
	if err != nil {
		t.Fatalf("mark as dm: %v", err)
	}

	rec := doGroupRequest(t, h, cookie, http.MethodPut, gid, updateReq(0))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body: %s", rec.Code, rec.Body.String())
	}
	if d := decodeDetail(t, doGroupRequest(t, h, cookie, http.MethodGet, gid, nil)); d.Version != 0 || d.ExpirationDays != 30 {
		t.Errorf("rejected DM edit changed the group: %+v", d)
	}
}
