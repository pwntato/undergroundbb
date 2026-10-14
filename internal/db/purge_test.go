package db

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// purgeFarFuture is a clock far enough ahead that every account is old enough.
var purgeFarFuture = time.Now().Add(24 * time.Hour)

func newUserID(t *testing.T) string {
	t.Helper()
	id, err := idgen.UUID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// registerAccount registers a test account (reserved prefix, flag set) or a
// real one, and removes whatever it left behind when the test ends.
func registerAccount(t *testing.T, c *Client, test bool) RegisterInput {
	t.Helper()
	name := "real-" + randomSuffix(t) + randomSuffix(t)
	if test {
		name = models.TestUsernamePrefix + randomSuffix(t) + randomSuffix(t)
	}
	in := testRegisterInput(newUserID(t), name)
	in.TestAccount = test
	if err := c.Register(context.Background(), in); err != nil {
		t.Fatalf("Register: %v", err)
	}
	t.Cleanup(func() { removePartitions(t, c, "USER#"+in.UserID) })
	t.Cleanup(func() {
		_, _ = c.ddb.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
			TableName: aws.String(c.table),
			Key:       map[string]types.AttributeValue{"PK": s("USERNAME#" + in.UsernameLower), "SK": s("CLAIM")},
		})
	})
	return in
}

// removePartitions deletes every item in the given partitions, a cleanup that
// does not depend on the code under test.
func removePartitions(t *testing.T, c *Client, pks ...string) {
	t.Helper()
	for _, pk := range pks {
		keys, err := c.partitionKeys(context.Background(), pk)
		if err != nil {
			t.Errorf("cleanup %s: %v", pk, err)
			continue
		}
		if err := c.batchDelete(context.Background(), keys); err != nil {
			t.Errorf("cleanup %s: %v", pk, err)
		}
	}
}

func putRaw(t *testing.T, c *Client, item map[string]types.AttributeValue) {
	t.Helper()
	if _, err := c.ddb.PutItem(context.Background(), &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: item}); err != nil {
		t.Fatal(err)
	}
}

// putGroup writes a group with META plus a grant and a generation key, and the
// given members.
func putGroup(t *testing.T, c *Client, members ...string) string {
	t.Helper()
	gid := newUserID(t)
	putGroupMeta(t, c, gid)
	putRaw(t, c, map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s("GRANT#root#2026-01-01#aa"), "Type": s("Grant")})
	putRaw(t, c, map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s("GENKEY#000000"), "Type": s("GenKey")})
	for _, m := range members {
		putTestMember(t, c, gid, m, "member")
	}
	t.Cleanup(func() { removePartitions(t, c, "GROUP#"+gid) })
	return gid
}

func profileOf(t *testing.T, c *Client, uid string) models.User {
	t.Helper()
	out, err := c.ddb.GetItem(context.Background(), getItemInput(c.table, "USER#"+uid, "PROFILE"))
	if err != nil || out.Item == nil {
		t.Fatalf("PROFILE of %s must survive as a tombstone: %v", uid, err)
	}
	var u models.User
	if err := unmarshalItem(out.Item, &u); err != nil {
		t.Fatal(err)
	}
	return u
}

// requireFinishedTombstone checks a purged account is down to a tombstone that
// keeps its public key and no longer carries the purge's index keys.
func requireFinishedTombstone(t *testing.T, c *Client, in RegisterInput) {
	t.Helper()
	u := profileOf(t, c, in.UserID)
	if u.DeletedAt == "" || u.Username != "" || len(u.Salt) != 0 || len(u.WrappedPrivateKeys.Ciphertext) != 0 {
		t.Errorf("PROFILE is not a clean tombstone: %+v", u)
	}
	if string(u.SigningPublicKey) != string(in.SigningPublicKey) {
		t.Error("tombstone must keep the public signing key so grants it signed still verify")
	}
	if u.GSI1PK != "" || u.GSI1SK != "" {
		t.Errorf("tombstone still carries index keys %q %q, so every run would revisit it", u.GSI1PK, u.GSI1SK)
	}
	if !u.TestAccount {
		t.Error("tombstone lost the TestAccount flag")
	}
}

func purgeOnly(ids ...string) PurgeOptions {
	only := map[string]bool{}
	for _, id := range ids {
		only[id] = true
	}
	return PurgeOptions{Now: purgeFarFuture, onlyUsers: only}
}

func TestPurgeRemovesTestAccountsAndTheirTestOnlyGroups(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	a, b := registerAccount(t, c, true), registerAccount(t, c, true)
	gid := putGroup(t, c, a.UserID, b.UserID)

	// A's own rows: a pin, a challenge, and an invite it sent (SENT# + INVITE#).
	if err := c.PutPin(ctx, a.UserID, newUserID(t), [][]byte{make([]byte, 32)}, make([]byte, 32), make([]byte, 32), make([]byte, 64)); err != nil {
		t.Fatalf("PutPin: %v", err)
	}
	if err := c.PutChallenge(ctx, a.UserID, []byte("nonce"), time.Minute); err != nil {
		t.Fatalf("PutChallenge: %v", err)
	}
	sentID := newUserID(t)
	putRaw(t, c, map[string]types.AttributeValue{"PK": s("USER#" + a.UserID), "SK": s("SENT#" + sentID), "InviteID": s(sentID)})
	putRaw(t, c, map[string]types.AttributeValue{"PK": s("INVITE#" + sentID), "SK": s("META")})
	t.Cleanup(func() { removePartitions(t, c, "INVITE#"+sentID) })
	// An invite addressed to B and a join request B made in some group.
	toB := newUserID(t)
	putRaw(t, c, map[string]types.AttributeValue{"PK": s("INVITE#" + toB), "SK": s("META"), "GSI1PK": s("USER#" + b.UserID), "GSI1SK": s("INVITE#2026-01-01#x")})
	t.Cleanup(func() { removePartitions(t, c, "INVITE#"+toB) })

	rep, err := c.PurgeTestAccounts(ctx, purgeOnly(a.UserID, b.UserID))
	if err != nil {
		t.Fatalf("PurgeTestAccounts: %v", err)
	}
	if rep.Purged != 2 || rep.Groups != 1 || len(rep.Skipped) != 0 {
		t.Errorf("report = %+v, want 2 purged, 1 group, none skipped", rep)
	}
	for _, a := range []struct{ pk, sk string }{
		{"GROUP#" + gid, "META"}, {"GROUP#" + gid, "GRANT#root#2026-01-01#aa"}, {"GROUP#" + gid, "GENKEY#000000"},
		{"GROUP#" + gid, "MEMBER#" + a.UserID}, {"GROUP#" + gid, "MEMBER#" + b.UserID},
		{"USER#" + a.UserID, "RECOVERY"}, {"USER#" + a.UserID, "CHALLENGE"},
		{"USER#" + a.UserID, "SENT#" + sentID}, {"INVITE#" + sentID, "META"}, {"INVITE#" + toB, "META"},
		{"USERNAME#" + a.UsernameLower, "CLAIM"}, {"USERNAME#" + b.UsernameLower, "CLAIM"},
	} {
		if itemExists(t, c, a.pk, a.sk) {
			t.Errorf("%s / %s still exists", a.pk, a.sk)
		}
	}
	if ok, err := c.UsernameAvailable(ctx, a.UsernameLower); err != nil || !ok {
		t.Errorf("username should be free again: available=%v err=%v", ok, err)
	}
	// PROFILE is never deleted: grants the account signed must keep verifying,
	// and its client-chosen uuid must stay taken so nobody can re-register it.
	requireFinishedTombstone(t, c, a)
	requireFinishedTombstone(t, c, b)
	again := testRegisterInput(a.UserID, "other-"+randomSuffix(t))
	if err := c.Register(ctx, again); !errors.Is(err, ErrUserIDTaken) {
		t.Errorf("re-registering a purged uuid = %v, want ErrUserIDTaken", err)
	}
}

func TestPurgeLeavesAGroupWithRealMembersAndWaitsUntilItIsTestOnly(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	testUser, realUser, otherTest := registerAccount(t, c, true), registerAccount(t, c, false), registerAccount(t, c, true)
	mixed := putGroup(t, c, testUser.UserID, realUser.UserID)
	onlyTest := putGroup(t, c, testUser.UserID, otherTest.UserID)
	if err := c.PutChallenge(ctx, testUser.UserID, []byte("nonce"), time.Minute); err != nil {
		t.Fatal(err)
	}

	rep, err := c.PurgeTestAccounts(ctx, purgeOnly(testUser.UserID))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Purged != 0 || rep.Waiting != 1 || rep.Groups != 1 || rep.KeptGroups != 1 || len(rep.Skipped) != 0 {
		t.Fatalf("report = %+v, want 1 waiting, 1 group deleted, 1 kept", rep)
	}

	// The mixed group and the real user are untouched, including the test
	// user's membership row (removing it needs a signature the server lacks).
	for _, k := range [][2]string{
		{"GROUP#" + mixed, "META"}, {"GROUP#" + mixed, "GRANT#root#2026-01-01#aa"},
		{"GROUP#" + mixed, "MEMBER#" + testUser.UserID}, {"GROUP#" + mixed, "MEMBER#" + realUser.UserID},
		{"USER#" + realUser.UserID, "PROFILE"}, {"USERNAME#" + realUser.UsernameLower, "CLAIM"},
	} {
		if !itemExists(t, c, k[0], k[1]) {
			t.Errorf("%s / %s was deleted", k[0], k[1])
		}
	}
	// The all-test group is gone, taking the other test member's membership with it.
	for _, k := range [][2]string{{"GROUP#" + onlyTest, "META"}, {"GROUP#" + onlyTest, "MEMBER#" + otherTest.UserID}} {
		if itemExists(t, c, k[0], k[1]) {
			t.Errorf("%s / %s still exists", k[0], k[1])
		}
	}
	// The account is gone except a tombstone, which keeps its index keys so the
	// next run looks at it again.
	for _, k := range [][2]string{{"USER#" + testUser.UserID, "RECOVERY"}, {"USER#" + testUser.UserID, "CHALLENGE"}, {"USERNAME#" + testUser.UsernameLower, "CLAIM"}} {
		if itemExists(t, c, k[0], k[1]) {
			t.Errorf("%s / %s still exists", k[0], k[1])
		}
	}
	if ok, err := c.UsernameAvailable(ctx, testUser.UsernameLower); err != nil || !ok {
		t.Errorf("username should be free: available=%v err=%v", ok, err)
	}
	tomb := profileOf(t, c, testUser.UserID)
	if tomb.DeletedAt == "" || tomb.Username != "" || tomb.GSI1PK != models.TestAccountGSI1PK {
		t.Fatalf("PROFILE = %+v, want a tombstone still indexed", tomb)
	}

	// Still waiting on the next run, and nothing is rewritten.
	second, err := c.PurgeTestAccounts(ctx, purgeOnly(testUser.UserID))
	if err != nil || second.Examined != 1 || second.Waiting != 1 || second.Purged != 0 {
		t.Fatalf("second run = %+v err = %v, want it examined and still waiting", second, err)
	}
	if got := profileOf(t, c, testUser.UserID); got.DeletedAt != tomb.DeletedAt {
		t.Errorf("DeletedAt = %q, want %q left alone", got.DeletedAt, tomb.DeletedAt)
	}

	// The last real member leaves; the group is now test-only and goes with the
	// account's membership, and the account is finished.
	if _, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(c.table),
		Key:       map[string]types.AttributeValue{"PK": s("GROUP#" + mixed), "SK": s("MEMBER#" + realUser.UserID)},
	}); err != nil {
		t.Fatal(err)
	}
	third, err := c.PurgeTestAccounts(ctx, purgeOnly(testUser.UserID))
	if err != nil || third.Purged != 1 || third.Waiting != 0 || third.Groups != 1 {
		t.Fatalf("third run = %+v err = %v, want the group deleted and the account finished", third, err)
	}
	for _, k := range [][2]string{{"GROUP#" + mixed, "META"}, {"GROUP#" + mixed, "MEMBER#" + testUser.UserID}} {
		if itemExists(t, c, k[0], k[1]) {
			t.Errorf("%s / %s still exists once the group was test-only", k[0], k[1])
		}
	}
	requireFinishedTombstone(t, c, testUser)
	if last, err := c.PurgeTestAccounts(ctx, purgeOnly(testUser.UserID)); err != nil || last.Examined != 0 {
		t.Errorf("final run = %+v err = %v, want nothing left to examine", last, err)
	}
}

func TestPurgeKeepsTheTombstoneOfAnAlreadyDeletedAccountThatIsStillAMember(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	testUser, realUser := registerAccount(t, c, true), registerAccount(t, c, false)
	gid := putGroup(t, c, realUser.UserID)
	// The documented race: a membership that survived DeleteAccount.
	if err := c.DeleteAccount(ctx, testUser.UserID); err != nil {
		t.Fatal(err)
	}
	putTestMember(t, c, gid, testUser.UserID, "member")
	before := profileOf(t, c, testUser.UserID)

	rep, err := c.PurgeTestAccounts(ctx, purgeOnly(testUser.UserID))
	if err != nil || rep.Waiting != 1 {
		t.Fatalf("report = %+v err = %v, want it waiting", rep, err)
	}
	after := profileOf(t, c, testUser.UserID)
	if after.DeletedAt != before.DeletedAt || after.GSI1PK != models.TestAccountGSI1PK {
		t.Errorf("PROFILE = %+v, want DeletedAt %q left alone and still indexed", after, before.DeletedAt)
	}
	if !itemExists(t, c, "GROUP#"+gid, "MEMBER#"+testUser.UserID) {
		t.Error("the leftover membership was deleted")
	}
}

func TestPurgeDoesNotDeleteAGroupWhileAYoungTestAccountIsInIt(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	old, young := registerAccount(t, c, true), registerAccount(t, c, true)
	gid := putGroup(t, c, old.UserID, young.UserID)
	// Make one account old enough by backdating its profile and index key.
	if _, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(c.table),
		Key:              map[string]types.AttributeValue{"PK": s("USER#" + old.UserID), "SK": s("PROFILE")},
		UpdateExpression: aws.String("SET CreatedAt = :t, GSI1SK = :k"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":t": s("2020-01-01T00:00:00Z"), ":k": s("2020-01-01T00:00:00Z#" + old.UserID),
		},
	}); err != nil {
		t.Fatal(err)
	}

	// The real clock and a 2h minimum: only `old` is a candidate, but `young`,
	// whose test may still be running, shares its group.
	opts := purgeOnly(old.UserID)
	opts.Now, opts.MinAge = time.Now(), 2*time.Hour
	rep, err := c.PurgeTestAccounts(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Groups != 0 || rep.Waiting != 1 || rep.KeptGroups != 1 {
		t.Fatalf("report = %+v, want the old account waiting and the group kept", rep)
	}
	for _, k := range [][2]string{{"GROUP#" + gid, "META"}, {"GROUP#" + gid, "MEMBER#" + old.UserID}, {"GROUP#" + gid, "MEMBER#" + young.UserID}, {"USER#" + young.UserID, "PROFILE"}} {
		if !itemExists(t, c, k[0], k[1]) {
			t.Errorf("%s / %s was deleted while a young test account was using the group", k[0], k[1])
		}
	}

	// Once the young account is old enough too, the group goes.
	later := purgeOnly(old.UserID, young.UserID)
	later.Now, later.MinAge = time.Now().Add(3*time.Hour), 2*time.Hour
	rep, err = c.PurgeTestAccounts(ctx, later)
	if err != nil || rep.Purged != 2 || rep.Groups != 1 {
		t.Fatalf("later run = %+v err = %v, want both purged and the group deleted", rep, err)
	}
	if itemExists(t, c, "GROUP#"+gid, "META") {
		t.Error("group still exists once both accounts were old enough")
	}
}

func TestPurgeFinishesAfterARunStoppedMidGroup(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	a, b := registerAccount(t, c, true), registerAccount(t, c, true)
	gid := putGroup(t, c, a.UserID, b.UserID)

	// Stop after the group's other rows are gone and before A's own MEMBER# row:
	// the row the next run finds the group through must still exist.
	opts := purgeOnly(a.UserID)
	stop := errors.New("simulated crash")
	opts.beforeMemberRow = func(string) error { return stop }
	if _, err := c.PurgeTestAccounts(ctx, opts); !errors.Is(err, stop) {
		t.Fatalf("err = %v, want the simulated crash", err)
	}
	if itemExists(t, c, "GROUP#"+gid, "META") {
		t.Fatal("setup: the group's other rows should already be deleted")
	}
	if !itemExists(t, c, "GROUP#"+gid, "MEMBER#"+a.UserID) {
		t.Fatal("the account's own MEMBER# row must be deleted last")
	}
	if got := profileOf(t, c, a.UserID); got.DeletedAt != "" {
		t.Fatal("PROFILE must not be touched before the group is done")
	}

	rep, err := c.PurgeTestAccounts(ctx, purgeOnly(a.UserID))
	if err != nil || rep.Purged != 1 {
		t.Fatalf("rerun = %+v err = %v, want the account finished", rep, err)
	}
	if itemExists(t, c, "GROUP#"+gid, "MEMBER#"+a.UserID) {
		t.Error("MEMBER# row still exists after the rerun")
	}
	requireFinishedTombstone(t, c, a)
}

func TestPurgeDryRunReportMatchesARealRun(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	a, b := registerAccount(t, c, true), registerAccount(t, c, true)
	putGroup(t, c, a.UserID, b.UserID) // shared by both
	putGroup(t, c, a.UserID)
	if err := c.PutChallenge(ctx, b.UserID, []byte("n"), time.Minute); err != nil {
		t.Fatal(err)
	}

	dry := purgeOnly(a.UserID, b.UserID)
	dry.DryRun = true
	want, err := c.PurgeTestAccounts(ctx, dry)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.PurgeTestAccounts(ctx, purgeOnly(a.UserID, b.UserID))
	if err != nil {
		t.Fatal(err)
	}
	want.DryRun = false
	if want.Examined != got.Examined || want.Purged != got.Purged || want.Groups != got.Groups || want.Rows != got.Rows {
		t.Errorf("dry run reported %+v but the real run did %+v", want, got)
	}
	if got.Groups != 2 {
		t.Errorf("real run deleted %d groups, want 2 (one shared, one not)", got.Groups)
	}
}

func TestPurgeStampsTombstonesWithTheRunsClock(t *testing.T) {
	c := testClient(t)
	a := registerAccount(t, c, true)
	opts := purgeOnly(a.UserID)
	opts.Now = time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)

	if rep, err := c.PurgeTestAccounts(context.Background(), opts); err != nil || rep.Purged != 1 {
		t.Fatalf("report = %+v err = %v", rep, err)
	}
	if got, want := profileOf(t, c, a.UserID).DeletedAt, opts.Now.Format(time.RFC3339); got != want {
		t.Errorf("DeletedAt = %q, want the run's clock %q", got, want)
	}
}

func TestPurgeNeedsBothTheFlagAndThePrefix(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	index := func(uid string) map[string]types.AttributeValue {
		return map[string]types.AttributeValue{"GSI1PK": s(models.TestAccountGSI1PK), "GSI1SK": s("2026-01-01T00:00:00Z#" + uid)}
	}
	put := func(uid, username string, flag bool) {
		item := index(uid)
		item["PK"], item["SK"], item["Username"] = s("USER#"+uid), s("PROFILE"), s(username)
		item["TestAccount"] = &types.AttributeValueMemberBOOL{Value: flag}
		putRaw(t, c, item)
		t.Cleanup(func() { removePartitions(t, c, "USER#"+uid) })
	}
	flagOnly, prefixOnly := newUserID(t), newUserID(t)
	put(flagOnly, "ordinary-"+randomSuffix(t), true)                      // flag without the prefix
	put(prefixOnly, models.TestUsernamePrefix+"x"+randomSuffix(t), false) // prefix without the flag

	rep, err := c.PurgeTestAccounts(ctx, purgeOnly(flagOnly, prefixOnly))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Purged != 0 || len(rep.Skipped) != 2 {
		t.Fatalf("report = %+v, want both skipped", rep)
	}
	for _, uid := range []string{flagOnly, prefixOnly} {
		if !itemExists(t, c, "USER#"+uid, "PROFILE") {
			t.Errorf("USER#%s PROFILE was deleted", uid)
		}
	}
}

func TestPurgeRespectsMinAge(t *testing.T) {
	c := testClient(t)
	a := registerAccount(t, c, true)
	opts := purgeOnly(a.UserID)
	opts.Now = time.Now()
	opts.MinAge = time.Hour

	rep, err := c.PurgeTestAccounts(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Examined != 0 || !itemExists(t, c, "USER#"+a.UserID, "PROFILE") {
		t.Fatalf("a brand-new account was examined or deleted: %+v", rep)
	}

	opts.Now = time.Now().Add(2 * time.Hour)
	rep, err = c.PurgeTestAccounts(context.Background(), opts)
	if err != nil || rep.Purged != 1 {
		t.Fatalf("after the min age: report = %+v err = %v, want it purged", rep, err)
	}
}

func TestPurgeDryRunDeletesNothingButCounts(t *testing.T) {
	c := testClient(t)
	a := registerAccount(t, c, true)
	gid := putGroup(t, c, a.UserID)
	opts := purgeOnly(a.UserID)
	opts.DryRun = true

	rep, err := c.PurgeTestAccounts(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.DryRun || rep.Purged != 1 || rep.Groups != 1 || rep.Rows < 6 {
		t.Errorf("dry-run report = %+v, want it to count the account, group and rows", rep)
	}
	for _, k := range [][2]string{{"USER#" + a.UserID, "PROFILE"}, {"USERNAME#" + a.UsernameLower, "CLAIM"}, {"GROUP#" + gid, "META"}, {"GROUP#" + gid, "MEMBER#" + a.UserID}} {
		if !itemExists(t, c, k[0], k[1]) {
			t.Errorf("dry run deleted %s / %s", k[0], k[1])
		}
	}
}

func TestPurgeRemovesADeletedTestAccountByFlagAlone(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	a := registerAccount(t, c, true)
	if err := c.DeleteAccount(ctx, a.UserID); err != nil {
		t.Fatal(err)
	}
	tomb, err := c.GetUserByID(ctx, a.UserID)
	if err != nil || tomb.Username != "" {
		t.Fatalf("setup: expected a tombstone, got %+v %v", tomb, err)
	}

	rep, err := c.PurgeTestAccounts(ctx, purgeOnly(a.UserID))
	if err != nil || rep.Purged != 1 {
		t.Fatalf("report = %+v err = %v, want the tombstone purged", rep, err)
	}
	// Nothing to remove but the index: the tombstone is kept and left as it was.
	if got := profileOf(t, c, a.UserID); got.DeletedAt != tomb.DeletedAt || got.GSI1PK != "" {
		t.Errorf("PROFILE = %+v, want the original tombstone with its index removed", got)
	}
}

func TestPurgeCapsAccountsPerRunAndFinishesAfterAPartialRun(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	a, b := registerAccount(t, c, true), registerAccount(t, c, true)
	gid := putGroup(t, c, a.UserID)
	opts := purgeOnly(a.UserID, b.UserID)
	opts.MaxAccounts = 1

	// A run that died after the group partition was deleted but before PROFILE
	// leaves the account findable; the next run must finish it.
	removePartitions(t, c, "GROUP#"+gid)

	first, err := c.PurgeTestAccounts(ctx, opts)
	if err != nil || first.Examined != 1 {
		t.Fatalf("first run = %+v err = %v, want exactly one account examined", first, err)
	}
	second, err := c.PurgeTestAccounts(ctx, opts)
	if err != nil || second.Examined != 1 {
		t.Fatalf("second run = %+v err = %v, want the other account", second, err)
	}
	for _, u := range []RegisterInput{a, b} {
		requireFinishedTombstone(t, c, u)
	}
}

func TestRegisterIndexesOnlyTestAccounts(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	testUser, realUser := registerAccount(t, c, true), registerAccount(t, c, false)

	get := func(uid string) models.User {
		out, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+uid, "PROFILE"))
		if err != nil || out.Item == nil {
			t.Fatalf("GetItem: %v", err)
		}
		var u models.User
		if err := unmarshalItem(out.Item, &u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	tu, ru := get(testUser.UserID), get(realUser.UserID)
	if !tu.TestAccount || tu.GSI1PK != models.TestAccountGSI1PK || !strings.HasSuffix(tu.GSI1SK, "#"+testUser.UserID) {
		t.Errorf("test PROFILE = TestAccount %v GSI1PK %q GSI1SK %q", tu.TestAccount, tu.GSI1PK, tu.GSI1SK)
	}
	if ru.TestAccount || ru.GSI1PK != "" || ru.GSI1SK != "" {
		t.Errorf("real PROFILE = TestAccount %v GSI1PK %q GSI1SK %q, want none", ru.TestAccount, ru.GSI1PK, ru.GSI1SK)
	}
}

// The purge deletes partitions it knows about. A new partition kind added to
// the data layer and not taught to the purge would be left behind silently, so
// this fails until a developer decides which it is.
var purgeKnownPartitions = map[string]string{
	"USER":     "purged: PROFILE last, everything else with it",
	"USERNAME": "purged: the claim",
	"GROUP":    "purged whole when every member is a test account",
	"INVITE":   "purged: invites the test user sent or was sent",
}

func TestEveryPartitionKindIsKnownToThePurge(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	// "PK": ...Value: "X#" and PK: "X#" as written in the db package.
	re := regexp.MustCompile(`(?:"(?:PK|:pk)":\s*&types\.AttributeValueMemberS\{Value:\s*|\bPK:\s*)"([A-Z]+)#"`)
	found := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			if found[m[1]] == "" {
				found[m[1]] = f
			}
		}
	}
	for _, kind := range []string{"USER", "GROUP", "INVITE", "USERNAME"} {
		if found[kind] == "" {
			t.Fatalf("scan found no %s# partition; has the db key literal style changed?", kind)
		}
	}
	var unknown []string
	for kind, where := range found {
		if _, ok := purgeKnownPartitions[kind]; !ok {
			unknown = append(unknown, kind+"# (first used in "+where+")")
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		t.Errorf("partition kinds the purge does not know about: %s\nteach internal/db/purge.go to delete them (or to leave them on purpose) and add them to purgeKnownPartitions", strings.Join(unknown, ", "))
	}
}
