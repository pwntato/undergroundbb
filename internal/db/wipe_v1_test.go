package db

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// putV1Row writes a PIN# or VERIFIED# row the way the v1 handlers did: the
// same attributes, no SignedDay.
func putV1Row(t *testing.T, c *Client, uid, sk string) {
	t.Helper()
	_, err := c.ddb.PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName: &c.table,
		Item: map[string]types.AttributeValue{
			"PK":        &types.AttributeValueMemberS{Value: "USER#" + uid},
			"SK":        &types.AttributeValueMemberS{Value: sk},
			"Signature": &types.AttributeValueMemberB{Value: make([]byte, 64)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func rowExists(t *testing.T, c *Client, uid, sk string) bool {
	t.Helper()
	out, err := c.ddb.GetItem(context.Background(), getItemInput(c.table, "USER#"+uid, sk))
	if err != nil {
		t.Fatal(err)
	}
	return len(out.Item) > 0
}

func TestWipeV1KeyRowsDeletesOnlyRowsWithoutSignedDay(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	uid := "wipe-" + randomSuffix(t)
	other := "wipe-keep-" + randomSuffix(t)

	putV1Row(t, c, uid, "PIN#a")
	putV1Row(t, c, uid, "VERIFIED#a")
	putV1Row(t, c, other, "PIN#b") // v1 row of a user outside the run's scope
	// v2 rows, written by the real code paths, must survive.
	if err := c.PutPin(ctx, uid, "pinned-v2", [][]byte{make([]byte, 32)}, make([]byte, 32), make([]byte, 32), make([]byte, 64), 0, "2026-10-21"); err != nil {
		t.Fatal(err)
	}
	if err := c.PutVerification(ctx, uid, "verified-v2", "00000-00000-00000-00000-00000-00000-00000-00000-00000-00000-00000-00000", make([]byte, 32), make([]byte, 64), "2026-10-21"); err != nil {
		t.Fatal(err)
	}
	scope := map[string]bool{uid: true}

	rep, err := c.WipeV1KeyRows(ctx, WipeV1Options{DryRun: true, onlyUsers: scope})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Pins != 1 || rep.Verified != 1 || !rep.DryRun {
		t.Fatalf("dry run report = %+v, want 1 pin and 1 verification", rep)
	}
	if !rowExists(t, c, uid, "PIN#a") || !rowExists(t, c, uid, "VERIFIED#a") {
		t.Fatal("a dry run deleted rows")
	}

	rep, err = c.WipeV1KeyRows(ctx, WipeV1Options{onlyUsers: scope})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Pins != 1 || rep.Verified != 1 {
		t.Fatalf("report = %+v, want 1 pin and 1 verification", rep)
	}
	if rowExists(t, c, uid, "PIN#a") || rowExists(t, c, uid, "VERIFIED#a") {
		t.Fatal("v1 rows survived the wipe")
	}
	if !rowExists(t, c, uid, "PIN#pinned-v2") || !rowExists(t, c, uid, "VERIFIED#verified-v2") {
		t.Fatal("v2 rows were deleted")
	}
	if !rowExists(t, c, other, "PIN#b") {
		t.Fatal("a row outside the run's scope was deleted")
	}

	rep, err = c.WipeV1KeyRows(ctx, WipeV1Options{onlyUsers: scope})
	if err != nil || rep.Pins != 0 || rep.Verified != 0 {
		t.Fatalf("second run = %+v, %v; want a no-op", rep, err)
	}
}
