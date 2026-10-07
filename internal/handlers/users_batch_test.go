package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sort"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

func doBatchUsers(t *testing.T, h *Handler, cookie *http.Cookie, ids []string) (int, batchUsersResponse, string) {
	t.Helper()
	rec := doJSON(t, h, http.MethodPost, "/api/users:batch", cookie, batchUsersRequest{IDs: ids})
	var resp batchUsersResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding: %v: %s", err, rec.Body.String())
		}
	}
	return rec.Code, resp, rec.Body.String()
}

func newUUID(t *testing.T) string {
	t.Helper()
	id, err := idgen.UUID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Each id is answered once: found users carry exactly the projection the
// single read serves, and unknown, malformed and duplicate ids do not
// produce a second or a wrong answer.
func TestBatchUsersMatchesTheSingleRead(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	a := registerTestUser(t, h)
	b := registerTestUser(t, h)
	deleted := registerTestUser(t, h)
	setUserField(t, deleted.userID, "SET DeletedAt = :d REMOVE Username", map[string]types.AttributeValue{":d": s("2026-10-01T00:00:00Z")})
	_, cookie := loggedInUser(t, h)
	unknown := newUUID(t)

	code, resp, body := doBatchUsers(t, h, cookie, []string{a.userID, b.userID, deleted.userID, unknown, "not-a-uuid", a.userID})
	if code != http.StatusOK {
		t.Fatalf("status = %d: %s", code, body)
	}
	if len(resp.Users) != 3 {
		t.Fatalf("users = %d, want 3: %s", len(resp.Users), body)
	}
	for _, u := range resp.Users {
		single := doGetUser(t, h, cookie, u.UserID)
		var want userProjection
		if err := json.Unmarshal(single.Body.Bytes(), &want); err != nil {
			t.Fatal(err)
		}
		gotJSON, _ := json.Marshal(u)
		wantJSON, _ := json.Marshal(want)
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("batch projection of %s = %s, single read = %s", u.UserID, gotJSON, wantJSON)
		}
	}
	notFound := append([]string(nil), resp.NotFound...)
	sort.Strings(notFound)
	wantNF := []string{unknown, "not-a-uuid"}
	sort.Strings(wantNF)
	if fmt.Sprint(notFound) != fmt.Sprint(wantNF) {
		t.Errorf("notFound = %v, want %v", notFound, wantNF)
	}
	var sawDeleted bool
	for _, u := range resp.Users {
		if u.UserID == deleted.userID {
			sawDeleted = u.Deleted && u.Username == ""
		}
	}
	if !sawDeleted {
		t.Error("the tombstoned account is not served as deleted with an empty username")
	}
}

func TestBatchUsersLeaksNothingElse(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	target := registerTestUser(t, h)
	_, cookie := loggedInUser(t, h)
	rec := doJSON(t, h, http.MethodPost, "/api/users:batch", cookie, batchUsersRequest{IDs: []string{target.userID}})
	var raw struct {
		Users []map[string]json.RawMessage `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil || len(raw.Users) != 1 {
		t.Fatalf("decoding: %v: %s", err, rec.Body.String())
	}
	want := map[string]bool{"userId": true, "username": true, "signingPublicKey": true, "wrappingPublicKey": true, "supersededSigningKeys": true}
	for k := range raw.Users[0] {
		if !want[k] {
			t.Errorf("unexpected field %q in projection", k)
		}
	}
	if len(raw.Users[0]) != len(want) {
		t.Errorf("got %d fields, want %d", len(raw.Users[0]), len(want))
	}
}

func TestBatchUsersAuthAndLimits(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	target := registerTestUser(t, h)
	_, cookie := loggedInUser(t, h)

	if code, _, _ := doBatchUsers(t, h, nil, []string{target.userID}); code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", code)
	}
	if code, _, _ := doBatchUsers(t, h, cookie, nil); code != http.StatusBadRequest {
		t.Errorf("no ids: %d, want 400", code)
	}
	rec := doJSON(t, h, http.MethodPost, "/api/users:batch", cookie, "not an object")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("malformed body: %d, want 400", rec.Code)
	}

	ids := make([]string, db.MaxBatchUsers)
	for i := range ids {
		ids[i] = newUUID(t)
	}
	if code, resp, body := doBatchUsers(t, h, cookie, ids); code != http.StatusOK || len(resp.NotFound) != db.MaxBatchUsers {
		t.Errorf("exactly the cap: %d, notFound=%d: %.200s", code, len(resp.NotFound), body)
	}
	if code, _, _ := doBatchUsers(t, h, cookie, append(ids, newUUID(t))); code != http.StatusBadRequest {
		t.Errorf("one over the cap: %d, want 400", code)
	}
}

// throttlingFront is a proxy in front of DynamoDB Local that answers the first
// `throttled` BatchGetItem calls with every requested key unprocessed (what
// throttling looks like) and forwards the rest. It returns a Handler on it and
// the number of BatchGetItem calls seen.
func throttlingFront(t *testing.T, throttled int) (*Handler, *int) {
	t.Helper()
	target, err := url.Parse(testEndpoint(t))
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	calls := new(int)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if r.Header.Get("X-Amz-Target") == "DynamoDB_20120810.BatchGetItem" {
			*calls++
			if *calls <= throttled {
				var req struct {
					RequestItems json.RawMessage `json:"RequestItems"`
				}
				if err := json.Unmarshal(body, &req); err != nil {
					t.Errorf("decoding the batch request: %v", err)
				}
				w.Header().Set("Content-Type", "application/x-amz-json-1.0")
				_, _ = fmt.Fprintf(w, `{"Responses":{},"UnprocessedKeys":%s}`, req.RequestItems)
				return
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	c, err := db.New(context.Background(), testTableName(), front.URL)
	if err != nil {
		t.Fatal(err)
	}
	return New(config.FromEnv(), c), calls
}

// Throttled keys are retried, so a transient throttle still returns everyone.
func TestBatchUsersRetriesUnprocessedKeys(t *testing.T) {
	good := New(config.FromEnv(), testDB(t))
	a := registerTestUser(t, good)
	b := registerTestUser(t, good)
	_, cookie := loggedInUser(t, good)

	h, calls := throttlingFront(t, 2)
	// The session cookie is verified by the same SESSION_SECRET, so it works on h.
	code, resp, body := doBatchUsers(t, h, cookie, []string{a.userID, b.userID})
	if code != http.StatusOK || len(resp.Users) != 2 || len(resp.NotFound) != 0 {
		t.Fatalf("status %d users %d notFound %v: %s", code, len(resp.Users), resp.NotFound, body)
	}
	if *calls != 3 {
		t.Errorf("BatchGetItem calls = %d, want 3 (two throttled, one served)", *calls)
	}
}

// Keys still unprocessed after the retries must fail the request. Reporting
// them as notFound would tell the roster and the pin check that real users do
// not exist.
func TestBatchUsersFailsRatherThanReportingThrottledKeysAsUnknown(t *testing.T) {
	good := New(config.FromEnv(), testDB(t))
	a := registerTestUser(t, good)
	_, cookie := loggedInUser(t, good)

	h, calls := throttlingFront(t, 1000)
	code, resp, body := doBatchUsers(t, h, cookie, []string{a.userID})
	if *calls == 0 {
		t.Fatal("no BatchGetItem was attempted, so this tested nothing")
	}
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (notFound=%v): %s", code, resp.NotFound, body)
	}
}
