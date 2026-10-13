package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/db"
)

// conflictingDB returns a db.Client whose TransactWriteItems calls are
// answered the way real DynamoDB answers a write that overlaps a concurrent
// transaction: a TransactionCanceledException with reason TransactionConflict.
// DynamoDB Local does not produce that, so every other call is proxied to it
// untouched. This drives the real SDK error type through the real handler.
func conflictingDB(t *testing.T) *db.Client {
	t.Helper()
	return conflictingDBOn(t, "TransactWriteItems", "TransactionCanceledException",
		`{"__type":"com.amazonaws.dynamodb.v20120810#TransactionCanceledException","Message":"Transaction cancelled, please refer cancellation reasons for specific reasons [TransactionConflict]","CancellationReasons":[{"Code":"TransactionConflict","Message":"Transaction is ongoing for the item"}]}`)
}

// conflictingDBOn answers calls to one DynamoDB operation with the given
// error type and body, and proxies everything else to DynamoDB Local.
func conflictingDBOn(t *testing.T, operation, errType, body string) *db.Client {
	t.Helper()
	target, err := url.Parse(testEndpoint(t))
	if err != nil {
		t.Fatalf("parsing DYNAMODB_ENDPOINT: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.Header.Get("X-Amz-Target"), "."+operation) {
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			w.Header().Set("X-Amzn-Errortype", errType)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(body))
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	c, err := db.New(context.Background(), testTableName(), srv.URL)
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	return c
}

func assertRetryable409(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"conflict_retry"`) {
		t.Errorf("body = %s, want code conflict_retry", rec.Body.String())
	}
}

// #150: Register and CreateGroup were two of the writes that answered 500.
func TestTransactionConflictIsRetryable409OnRegisterAndCreateGroup(t *testing.T) {
	good := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, good)
	cookie := sessionCookieFrom(completeLogin(t, good, user))
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	conflicting := New(config.FromEnv(), conflictingDB(t))

	assertRetryable409(t, doRegister(t, conflicting, validRegisterRequest(randomUsername(t))))
	assertRetryable409(t, doCreateGroup(t, conflicting, cookie, signedCreateGroupRequest(t, user)))
}

// A plain PutItem that lands on an item mid-transaction fails with
// TransactionConflictException, not a cancellation; the challenge write is one.
func TestNonTransactionalItemConflictIsRetryable409(t *testing.T) {
	good := New(config.FromEnv(), testDB(t))
	user := registerTestUser(t, good)
	conflicting := New(config.FromEnv(), conflictingDBOn(t, "PutItem", "TransactionConflictException",
		`{"__type":"com.amazonaws.dynamodb.v20120810#TransactionConflictException","message":"Operation was rejected because there is an ongoing transaction for the item"}`))

	assertRetryable409(t, doChallenge(t, conflicting, user.username))
}
