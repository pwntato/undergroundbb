package main

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/idgen"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDryRunFailsSafe(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"unset", nil, true},
		{"empty", map[string]string{"REKEY_DRY_RUN": ""}, true},
		{"garbage", map[string]string{"REKEY_DRY_RUN": "0"}, true},
		{"true", map[string]string{"REKEY_DRY_RUN": "true"}, true},
		{"capitalised false is not false", map[string]string{"REKEY_DRY_RUN": "False"}, true},
		{"false writes", map[string]string{"REKEY_DRY_RUN": "false"}, false},
	} {
		if got := dryRun(env(tc.env)); got != tc.want {
			t.Errorf("%s: dryRun = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestOldHash(t *testing.T) {
	h := "0123456789abcdef0123456789abcdef"
	if got, ok := oldHash("NOTIF#0000-00-00#" + h); !ok || got != h {
		t.Errorf("old key: %q %v", got, ok)
	}
	for _, sk := range []string{
		"NOTIF#0000-00-00#2026-10-01#" + h,  // already the new shape
		"NOTIF#2026-10-01#" + h,             // a reply
		"NOTIF#0000-00-00#0123456789abcdef", // wrong length
	} {
		if _, ok := oldHash(sk); ok {
			t.Errorf("%q taken for an old key", sk)
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

func put(t *testing.T, ddb *dynamodb.Client, table string, item map[string]types.AttributeValue) {
	t.Helper()
	if _, err := ddb.PutItem(context.Background(), &dynamodb.PutItemInput{TableName: &table, Item: item}); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, ddb *dynamodb.Client, table, uid, sk string) map[string]types.AttributeValue {
	t.Helper()
	out, err := ddb.GetItem(context.Background(), &dynamodb.GetItemInput{TableName: &table, ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{"PK": s("USER#" + uid), "SK": s(sk)}})
	if err != nil {
		t.Fatal(err)
	}
	return out.Item
}

func TestRekeyMovesOldRowsAndLeavesTheRest(t *testing.T) {
	ddb, table := localClient(t)
	uid, err := idgen.UUID()
	if err != nil {
		t.Fatal(err)
	}
	gid, _ := idgen.UUID()
	pid := gid + "#2026-10-15#00112233445566a1"
	h1, h2, h3 := "00000000000000000000000000000001", "00000000000000000000000000000002", "00000000000000000000000000000003"
	row := func(sk, kind string, read bool) map[string]types.AttributeValue {
		return map[string]types.AttributeValue{
			"PK": s("USER#" + uid), "SK": s(sk), "Type": s("NOTIFICATION"), "Kind": s(kind),
			"ActorUserID": s("actor"), "GroupID": s(gid), "PostID": s(pid), "CmtPath": s("0000"),
			"Read": &types.AttributeValueMemberBOOL{Value: read}, "TTL": &types.AttributeValueMemberN{Value: "4102444800"},
		}
	}
	old1, new1 := "NOTIF#0000-00-00#"+h1, "NOTIF#0000-00-00#2026-10-15#"+h1
	old2, new2 := "NOTIF#0000-00-00#"+h2, "NOTIF#0000-00-00#2026-10-15#"+h2
	reply := "NOTIF#2026-10-20#" + h3
	put(t, ddb, table, row(old1, "reaction", true))
	// old2's reaction was given again after the deploy: the new row exists, unread, and must win.
	put(t, ddb, table, row(old2, "reaction", true))
	put(t, ddb, table, row(new2, "reaction", false))
	put(t, ddb, table, row(reply, "reply", false))
	only := map[string]bool{uid: true}

	dry, err := rekeyReactionNotifications(context.Background(), ddb, table, rekeyOptions{dryRun: true, onlyUsers: only})
	if err != nil || dry.Moved != 1 || dry.Superseded != 1 || !dry.DryRun {
		t.Fatalf("dry run: %+v, %v", dry, err)
	}
	if get(t, ddb, table, uid, old1) == nil || get(t, ddb, table, uid, new1) != nil {
		t.Fatal("a dry run changed a row")
	}

	rep, err := rekeyReactionNotifications(context.Background(), ddb, table, rekeyOptions{onlyUsers: only})
	if err != nil || rep.Moved != 1 || rep.Superseded != 1 {
		t.Fatalf("run: %+v, %v", rep, err)
	}
	if get(t, ddb, table, uid, old1) != nil || get(t, ddb, table, uid, old2) != nil {
		t.Fatal("an old row is still there")
	}
	moved := get(t, ddb, table, uid, new1)
	if moved == nil {
		t.Fatal("the moved row is missing")
	}
	if r := moved["Read"].(*types.AttributeValueMemberBOOL); !r.Value {
		t.Error("the moved row lost its Read flag")
	}
	for _, k := range []string{"ActorUserID", "GroupID", "PostID", "CmtPath", "Kind", "Type", "TTL"} {
		if moved[k] == nil || get(t, ddb, table, uid, new2)[k] == nil {
			t.Errorf("attribute %s not carried", k)
		}
	}
	if r := get(t, ddb, table, uid, new2)["Read"].(*types.AttributeValueMemberBOOL); r.Value {
		t.Error("the row written after the deploy was overwritten by the old one")
	}
	if get(t, ddb, table, uid, reply) == nil {
		t.Error("a reply row was touched")
	}

	again, err := rekeyReactionNotifications(context.Background(), ddb, table, rekeyOptions{onlyUsers: only})
	if err != nil || again.Moved != 0 || again.Superseded != 0 {
		t.Fatalf("second run is not a no-op: %+v, %v", again, err)
	}
}

func TestRekeySkipsARowWithNoReadablePostID(t *testing.T) {
	ddb, table := localClient(t)
	uid, _ := idgen.UUID()
	sk := "NOTIF#0000-00-00#00000000000000000000000000000009"
	put(t, ddb, table, map[string]types.AttributeValue{
		"PK": s("USER#" + uid), "SK": s(sk), "Type": s("NOTIFICATION"), "Kind": s("reaction"), "PostID": s("garbage"),
	})
	rep, err := rekeyReactionNotifications(context.Background(), ddb, table, rekeyOptions{onlyUsers: map[string]bool{uid: true}})
	if err != nil || rep.Moved != 0 || len(rep.Skipped) != 1 {
		t.Fatalf("%+v, %v", rep, err)
	}
	if get(t, ddb, table, uid, sk) == nil {
		t.Fatal("the unreadable row was removed")
	}
}
