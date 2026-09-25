package db

import (
	"context"
	"testing"
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
func TestPingFailsAgainstMissingTable(t *testing.T) {
	good := testClient(t)
	bad := &Client{ddb: good.ddb, table: "table-that-does-not-exist"}

	if err := bad.Ping(context.Background()); err == nil {
		t.Error("Ping against a nonexistent table = nil error, want an error")
	}
}
