package main

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go/middleware"

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
		"NOTIF#0000-00-00#2026-10-01#" + h,                  // already the new shape
		"NOTIF#2026-10-01#" + h,                             // a reply
		"NOTIF#0000-00-00#0123456789abcdef",                 // wrong length
		"NOTIF#0000-00-00#0123456789abcdef#123456789abcdef", // 32 characters, but a "#" inside
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
	// The reaction these notifications announce (RXN#<target>#<reactor> under the post): both are on
	// the post itself ("0000") by "actor".
	put(t, ddb, table, map[string]types.AttributeValue{"PK": s("POST#" + pid), "SK": s("RXN#0000#actor"), "Type": s("REACTION")})
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
	// The row written after the deploy is the one kept, and it carries the old row's read flag.
	if r := get(t, ddb, table, uid, new2)["Read"].(*types.AttributeValueMemberBOOL); !r.Value {
		t.Error("the new row did not take over the old row's read flag")
	}
	if get(t, ddb, table, uid, reply) == nil {
		t.Error("a reply row was touched")
	}

	again, err := rekeyReactionNotifications(context.Background(), ddb, table, rekeyOptions{onlyUsers: only})
	if err != nil || again.Moved != 0 || again.Superseded != 0 {
		t.Fatalf("second run is not a no-op: %+v, %v", again, err)
	}
}

// A reaction taken back before the migration ran left its old notification behind (the delete
// computed the new key and missed it). Moving that row would strand it where nothing can delete it,
// so the migration deletes it and reports it.
func TestRekeyDeletesAnOrphanedRowInsteadOfMovingIt(t *testing.T) {
	ddb, table := localClient(t)
	uid, _ := idgen.UUID()
	gid, _ := idgen.UUID()
	pid := gid + "#2026-10-15#00112233445566a1"
	hash := "00000000000000000000000000000007"
	oldSK, newSK := "NOTIF#0000-00-00#"+hash, "NOTIF#0000-00-00#2026-10-15#"+hash
	put(t, ddb, table, map[string]types.AttributeValue{
		"PK": s("USER#" + uid), "SK": s(oldSK), "Type": s("NOTIFICATION"), "Kind": s("reaction"),
		"ActorUserID": s("bob"), "GroupID": s(gid), "PostID": s(pid), "CmtPath": s("0001"),
	}) // no RXN#0001#bob row under the post: bob took the reaction back
	only := map[string]bool{uid: true}

	dry, err := rekeyReactionNotifications(context.Background(), ddb, table, rekeyOptions{dryRun: true, onlyUsers: only})
	if err != nil || dry.Orphaned != 1 || dry.Moved != 0 {
		t.Fatalf("dry run: %+v, %v", dry, err)
	}
	if get(t, ddb, table, uid, oldSK) == nil {
		t.Fatal("a dry run deleted the orphan")
	}
	rep, err := rekeyReactionNotifications(context.Background(), ddb, table, rekeyOptions{onlyUsers: only})
	if err != nil || rep.Orphaned != 1 || rep.Moved != 0 {
		t.Fatalf("run: %+v, %v", rep, err)
	}
	if get(t, ddb, table, uid, oldSK) != nil || get(t, ddb, table, uid, newSK) != nil {
		t.Fatal("the orphan was kept or moved to the new key")
	}
}

// reasons builds a cancellation in the order a move's transaction lists its items: the Put of the
// new row, the Delete of the old one, the check that the reaction still exists.
func reasons(codes ...string) *types.TransactionCanceledException {
	var rs []types.CancellationReason
	for _, c := range codes {
		rs = append(rs, types.CancellationReason{Code: aws.String(c)})
	}
	return &types.TransactionCanceledException{CancellationReasons: rs}
}

func TestNothingLeftToMove(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  *types.TransactionCanceledException
		want bool
	}{
		{"old row gone", reasons("None", "ConditionalCheckFailed", "None"), true},
		{"old row gone and the new one appeared", reasons("ConditionalCheckFailed", "ConditionalCheckFailed", "None"), true},
		{"new row appeared, old row still there", reasons("ConditionalCheckFailed", "None", "None"), false},
		{"reaction taken back mid-move, old row still there", reasons("None", "None", "ConditionalCheckFailed"), false},
		{"conflicting transaction", reasons("None", "TransactionConflict", "None"), false},
		{"throttled", reasons("ThrottlingError", "None", "None"), false},
		{"no reasons given", reasons(), false},
		{"too few reasons to include the delete", reasons("ConditionalCheckFailed"), false},
		{"only None", reasons("None", "None", "None"), false},
	} {
		if got := nothingLeftToMove(tc.err); got != tc.want {
			t.Errorf("%s: nothingLeftToMove = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestACancelledMoveIsCountedAsRetryUnlessTheOldRowIsGone(t *testing.T) {
	gone := rekeyReport{Moved: 1}
	gone.recordCancelled(reasons("None", "ConditionalCheckFailed", "None"))
	if gone.Moved != 0 || gone.Retry != 0 {
		t.Errorf("old row gone: %+v, want moved 0 retry 0", gone)
	}
	for name, c := range map[string]*types.TransactionCanceledException{
		"conflict":            reasons("None", "TransactionConflict", "None"),
		"new row appeared":    reasons("ConditionalCheckFailed", "None", "None"),
		"reaction taken back": reasons("None", "None", "ConditionalCheckFailed"),
	} {
		r := rekeyReport{Moved: 1}
		r.recordCancelled(c)
		if r.Moved != 0 || r.Retry != 1 {
			t.Errorf("%s: %+v, want moved 0 retry 1", name, r)
		}
	}
}

// onTransaction returns a client whose TransactWriteItems calls run fn once, just before the
// request is sent: the moment a conflicting write can land between the migration's reads and its
// transaction.
func onTransaction(ddb *dynamodb.Client, fn func()) *dynamodb.Client {
	done := false
	return dynamodb.New(ddb.Options(), func(o *dynamodb.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("rekey-test",
				func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
					if !done && middleware.GetOperationName(ctx) == "TransactWriteItems" {
						done = true
						fn()
					}
					return next.HandleInitialize(ctx, in)
				}), middleware.Before)
		})
	})
}

// raceFixture is one old-key row, the reaction it announces, and the keys involved.
type raceFixture struct {
	uid, rxnPK, rxnSK, oldSK, newSK string
	only                            map[string]bool
	newRow                          map[string]types.AttributeValue
}

func newRace(t *testing.T, ddb *dynamodb.Client, table string) raceFixture {
	t.Helper()
	uid, _ := idgen.UUID()
	gid, _ := idgen.UUID()
	pid := gid + "#2026-10-15#00112233445566a1"
	hash := "000000000000000000000000000000aa"
	f := raceFixture{uid: uid, rxnPK: "POST#" + pid, rxnSK: "RXN#0001#bob",
		oldSK: "NOTIF#0000-00-00#" + hash, newSK: "NOTIF#0000-00-00#2026-10-15#" + hash, only: map[string]bool{uid: true}}
	f.newRow = map[string]types.AttributeValue{
		"PK": s("USER#" + uid), "SK": s(f.newSK), "Type": s("NOTIFICATION"), "Kind": s("reaction"),
		"ActorUserID": s("bob"), "GroupID": s(gid), "PostID": s(pid), "CmtPath": s("0001"),
		"Read": &types.AttributeValueMemberBOOL{Value: false},
	}
	put(t, ddb, table, map[string]types.AttributeValue{"PK": s(f.rxnPK), "SK": s(f.rxnSK), "Type": s("REACTION")})
	old := map[string]types.AttributeValue{}
	for k, v := range f.newRow {
		old[k] = v
	}
	old["SK"] = s(f.oldSK)
	put(t, ddb, table, old)
	return f
}

func (f raceFixture) run(t *testing.T, ddb *dynamodb.Client, table string, dry bool) rekeyReport {
	t.Helper()
	rep, err := rekeyReactionNotifications(context.Background(), ddb, table, rekeyOptions{dryRun: dry, onlyUsers: f.only})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// A reaction taken back after the migration read it but before its transaction: the move must not
// land, or the row would sit on the new key with no reaction row left to point at it.
func TestRekeyDoesNotMoveARowWhoseReactionIsTakenBackMidMove(t *testing.T) {
	ddb, table := localClient(t)
	f := newRace(t, ddb, table)
	racing := onTransaction(ddb, func() {
		if _, err := ddb.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{TableName: &table,
			Key: map[string]types.AttributeValue{"PK": s(f.rxnPK), "SK": s(f.rxnSK)}}); err != nil {
			t.Error(err)
		}
	})
	rep := f.run(t, racing, table, false)
	if rep.Moved != 0 || rep.Retry != 1 {
		t.Fatalf("racing run: %+v, want moved 0 retry 1", rep)
	}
	if get(t, ddb, table, f.uid, f.oldSK) == nil || get(t, ddb, table, f.uid, f.newSK) != nil {
		t.Fatal("the row was moved although its reaction was gone")
	}
	// The next run deletes it as an orphan, and then a dry run has nothing left to report.
	if rep := f.run(t, ddb, table, false); rep.Orphaned != 1 || rep.Moved != 0 {
		t.Fatalf("second run: %+v, want orphaned 1", rep)
	}
	if get(t, ddb, table, f.uid, f.oldSK) != nil || get(t, ddb, table, f.uid, f.newSK) != nil {
		t.Fatal("a notification for a taken-back reaction is still stored")
	}
	if rep := f.run(t, ddb, table, true); rep.Moved+rep.Superseded+rep.Orphaned+rep.Retry != 0 {
		t.Fatalf("final dry run: %+v, want all zero", rep)
	}
}

// The old row deleted after the migration read it (its post's TTL, or an account sweep): the move
// must not write the new row, or it would bring back a notification that was deleted.
func TestRekeyDoesNotRecreateARowDeletedMidMove(t *testing.T) {
	ddb, table := localClient(t)
	f := newRace(t, ddb, table)
	racing := onTransaction(ddb, func() {
		if _, err := ddb.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{TableName: &table,
			Key: map[string]types.AttributeValue{"PK": s("USER#" + f.uid), "SK": s(f.oldSK)}}); err != nil {
			t.Error(err)
		}
	})
	rep := f.run(t, racing, table, false)
	if rep.Moved != 0 || rep.Retry != 0 {
		t.Fatalf("racing run: %+v, want moved 0 retry 0 (nothing left to move)", rep)
	}
	if get(t, ddb, table, f.uid, f.oldSK) != nil || get(t, ddb, table, f.uid, f.newSK) != nil {
		t.Fatal("a row deleted mid-move was brought back on the new key")
	}
}

// The new row appearing after the migration read (the reaction was given again) cancels the move
// with the old row still in place. That is a retry, not a finished row: a dry run afterwards must
// show it, and the next run removes it.
func TestRekeyCountsARowThatAppearedMidMoveAsRetryThenSupersedesTheOldOne(t *testing.T) {
	ddb, table := localClient(t)
	f := newRace(t, ddb, table)
	racing := onTransaction(ddb, func() { put(t, ddb, table, f.newRow) })
	rep := f.run(t, racing, table, false)
	if rep.Moved != 0 || rep.Retry != 1 {
		t.Fatalf("racing run: %+v, want moved 0 retry 1", rep)
	}
	if get(t, ddb, table, f.uid, f.oldSK) == nil {
		t.Fatal("the old row is gone although the move was cancelled")
	}
	if dry := f.run(t, ddb, table, true); dry.Superseded != 1 {
		t.Fatalf("dry run after the race: %+v, want superseded 1 (so an operator sees it is not done)", dry)
	}
	if rep := f.run(t, ddb, table, false); rep.Superseded != 1 {
		t.Fatalf("second run: %+v, want superseded 1", rep)
	}
	if get(t, ddb, table, f.uid, f.oldSK) != nil || get(t, ddb, table, f.uid, f.newSK) == nil {
		t.Fatal("want only the new row left")
	}
	if rep := f.run(t, ddb, table, true); rep.Moved+rep.Superseded+rep.Orphaned+rep.Retry != 0 {
		t.Fatalf("final dry run: %+v, want all zero", rep)
	}
}

// A notification the user already read must not come back as new: the old row is read, the new one
// (written after the deploy, e.g. by a changed emoji, which found no row and wrote Read=false)
// is not. The new row wins, carrying the read flag.
func TestRekeySupersededRowKeepsTheReadFlagOfTheOldOne(t *testing.T) {
	for _, tc := range []struct {
		name             string
		oldRead, newRead bool
		wantRead         bool
	}{
		{"old read, new unread", true, false, true},
		{"old unread, new unread", false, false, false},
		{"old unread, new read", false, true, true},
		{"both read", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ddb, table := localClient(t)
			f := newRace(t, ddb, table)
			setRead := func(sk string, read bool) {
				if _, err := ddb.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{TableName: &table,
					Key:                       map[string]types.AttributeValue{"PK": s("USER#" + f.uid), "SK": s(sk)},
					UpdateExpression:          aws.String("SET #r = :v"),
					ExpressionAttributeNames:  map[string]string{"#r": "Read"},
					ExpressionAttributeValues: map[string]types.AttributeValue{":v": &types.AttributeValueMemberBOOL{Value: read}}}); err != nil {
					t.Fatal(err)
				}
			}
			setRead(f.oldSK, tc.oldRead)
			newRow := map[string]types.AttributeValue{}
			for k, v := range f.newRow {
				newRow[k] = v
			}
			newRow["Read"] = &types.AttributeValueMemberBOOL{Value: tc.newRead}
			put(t, ddb, table, newRow)
			if dry := f.run(t, ddb, table, true); dry.Superseded != 1 {
				t.Fatalf("dry run: %+v", dry)
			}
			if get(t, ddb, table, f.uid, f.newSK)["Read"].(*types.AttributeValueMemberBOOL).Value != tc.newRead {
				t.Fatal("a dry run changed the new row")
			}
			if rep := f.run(t, ddb, table, false); rep.Superseded != 1 || rep.Retry != 0 {
				t.Fatalf("run: %+v", rep)
			}
			if get(t, ddb, table, f.uid, f.oldSK) != nil {
				t.Fatal("the old row is still there")
			}
			got := get(t, ddb, table, f.uid, f.newSK)["Read"].(*types.AttributeValueMemberBOOL).Value
			if got != tc.wantRead {
				t.Fatalf("surviving row Read = %v, want %v", got, tc.wantRead)
			}
		})
	}
}

// The new row's reaction was taken back between the migration's read and its transaction: the new
// row is gone, so the old one stays for the next run (which deletes it as an orphan), reported as
// retry.
func TestRekeySupersedeCancelledWhenTheNewRowVanishesIsRetry(t *testing.T) {
	ddb, table := localClient(t)
	f := newRace(t, ddb, table)
	put(t, ddb, table, f.newRow)
	if _, err := ddb.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{TableName: &table,
		Key:                       map[string]types.AttributeValue{"PK": s("USER#" + f.uid), "SK": s(f.oldSK)},
		UpdateExpression:          aws.String("SET #r = :v"),
		ExpressionAttributeNames:  map[string]string{"#r": "Read"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": &types.AttributeValueMemberBOOL{Value: true}}}); err != nil {
		t.Fatal(err)
	}
	racing := onTransaction(ddb, func() {
		if _, err := ddb.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{TableName: &table,
			Key: map[string]types.AttributeValue{"PK": s("USER#" + f.uid), "SK": s(f.newSK)}}); err != nil {
			t.Error(err)
		}
	})
	rep := f.run(t, racing, table, false)
	if rep.Superseded != 0 || rep.Retry != 1 {
		t.Fatalf("racing run: %+v, want superseded 0 retry 1", rep)
	}
	if get(t, ddb, table, f.uid, f.oldSK) == nil {
		t.Fatal("the old row was deleted although the new one vanished")
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
