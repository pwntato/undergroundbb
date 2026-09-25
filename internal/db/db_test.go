package db

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// TestPingSucceedsAgainstRealTable is the positive case: a Client pointed at
// a table that actually exists and is reachable. Ping should not itself be a
// source of false failures.
func TestPingSucceedsAgainstRealTable(t *testing.T) {
	c := testClient(t)
	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("Ping: %v", err)
	}
}

// TestPingFailsAgainstMissingTable is the whole point of #86: New cannot
// fail for a wrong table name, since it never contacts AWS. Ping must be the
// thing that does, or cold start keeps reporting healthy for a deployment
// pointed at a table that was never created (or was mistyped).
//
// Asserting the specific error type, not just err != nil, matters here: a
// bad endpoint or bad credentials would also make Ping return a non-nil
// error, and this test would still pass while pinning nothing about the
// "table missing" case #86 is actually about. ResourceNotFoundException is
// what DescribeTable returns for that case specifically.
func TestPingFailsAgainstMissingTable(t *testing.T) {
	good := testClient(t)
	bad := &Client{ddb: good.ddb, table: "table-that-does-not-exist"}

	err := bad.Ping(context.Background())
	var notFound *types.ResourceNotFoundException
	if !errors.As(err, &notFound) {
		t.Errorf("Ping against a nonexistent table: err = %v, want a ResourceNotFoundException", err)
	}
}
