package main

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDryRunFailsSafe(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"unset", nil, true},
		{"empty", map[string]string{"WIPE_DRY_RUN": ""}, true},
		{"garbage", map[string]string{"WIPE_DRY_RUN": "0"}, true},
		{"true", map[string]string{"WIPE_DRY_RUN": "true"}, true},
		{"capitalised false is not false", map[string]string{"WIPE_DRY_RUN": "False"}, true},
		{"false deletes", map[string]string{"WIPE_DRY_RUN": "false"}, false},
	} {
		if got := dryRun(env(tc.env)); got != tc.want {
			t.Errorf("%s: dryRun = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func s(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

func localClient(t *testing.T) (*dynamodb.Client, string) {
	t.Helper()
	endpoint, table := os.Getenv("DYNAMODB_ENDPOINT"), os.Getenv("TABLE_NAME")
	if endpoint == "" || table == "" {
		t.Skip("DYNAMODB_ENDPOINT / TABLE_NAME not set")
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(endpoint) }), table
}

func put(t *testing.T, ddb *dynamodb.Client, table, uid, sk string, v2 bool) {
	t.Helper()
	item := map[string]types.AttributeValue{"PK": s("USER#" + uid), "SK": s(sk), "Signature": &types.AttributeValueMemberB{Value: make([]byte, 64)}}
	if v2 {
		item["SignedDay"] = s("2026-10-21")
	}
	if _, err := ddb.PutItem(context.Background(), &dynamodb.PutItemInput{TableName: &table, Item: item}); err != nil {
		t.Fatal(err)
	}
}

func exists(t *testing.T, ddb *dynamodb.Client, table, uid, sk string) bool {
	t.Helper()
	out, err := ddb.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: &table, Key: map[string]types.AttributeValue{"PK": s("USER#" + uid), "SK": s(sk)}, ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	return len(out.Item) > 0
}

func TestWipeDeletesOnlyRowsWithoutSignedDay(t *testing.T) {
	ddb, table := localClient(t)
	ctx := context.Background()
	uid, other := "wipe-"+t.Name()+"-a", "wipe-"+t.Name()+"-b"

	put(t, ddb, table, uid, "PIN#a", false)
	put(t, ddb, table, uid, "VERIFIED#a", false)
	put(t, ddb, table, uid, "PIN#v2", true)
	put(t, ddb, table, uid, "VERIFIED#v2", true)
	put(t, ddb, table, other, "PIN#b", false) // v1 row of a user outside the run's scope
	scope := map[string]bool{uid: true}

	rep, err := wipeV1KeyRows(ctx, ddb, table, wipeOptions{dryRun: true, onlyUsers: scope})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Pins != 1 || rep.Verified != 1 || !rep.DryRun {
		t.Fatalf("dry run report = %+v, want 1 pin and 1 verification", rep)
	}
	if !exists(t, ddb, table, uid, "PIN#a") || !exists(t, ddb, table, uid, "VERIFIED#a") {
		t.Fatal("a dry run deleted rows")
	}

	rep, err = wipeV1KeyRows(ctx, ddb, table, wipeOptions{onlyUsers: scope})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Pins != 1 || rep.Verified != 1 {
		t.Fatalf("report = %+v, want 1 pin and 1 verification", rep)
	}
	if exists(t, ddb, table, uid, "PIN#a") || exists(t, ddb, table, uid, "VERIFIED#a") {
		t.Fatal("v1 rows survived the wipe")
	}
	if !exists(t, ddb, table, uid, "PIN#v2") || !exists(t, ddb, table, uid, "VERIFIED#v2") {
		t.Fatal("v2 rows were deleted")
	}
	if !exists(t, ddb, table, other, "PIN#b") {
		t.Fatal("a row outside the run's scope was deleted")
	}

	rep, err = wipeV1KeyRows(ctx, ddb, table, wipeOptions{onlyUsers: scope})
	if err != nil || rep.Pins != 0 || rep.Verified != 0 {
		t.Fatalf("second run = %+v, %v; want a no-op", rep, err)
	}
}
