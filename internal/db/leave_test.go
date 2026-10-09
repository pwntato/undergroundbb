package db

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go/middleware"

	"github.com/pwntato/undergroundbb/internal/models"
)

func s(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

// putGroupMeta writes a bare META, enough for CompleteInvite's group-exists check.
func putGroupMeta(t *testing.T, c *Client, groupID string) {
	t.Helper()
	_, err := c.ddb.PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName: aws.String(c.table),
		Item:      map[string]types.AttributeValue{"PK": s("GROUP#" + groupID), "SK": s("META"), "Type": s("Group")},
	})
	if err != nil {
		t.Fatalf("putGroupMeta: %v", err)
	}
}

func putTestMember(t *testing.T, c *Client, groupID, userID, role string) {
	t.Helper()
	_, err := c.ddb.PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName: aws.String(c.table),
		Item: map[string]types.AttributeValue{
			"PK": s("GROUP#" + groupID), "SK": s("MEMBER#" + userID), "Type": s("Membership"),
			"GSI1PK": s("USER#" + userID), "GSI1SK": s("GROUP#" + groupID), "Role": s(role),
			// Real memberships always carry Generation (models.Membership has no omitempty).
			"Generation": &types.AttributeValueMemberN{Value: "0"},
		},
	})
	if err != nil {
		t.Fatalf("putTestMember: %v", err)
	}
}

func itemExists(t *testing.T, c *Client, pk, sk string) bool {
	t.Helper()
	out, err := c.ddb.GetItem(context.Background(), getItemInput(c.table, pk, sk))
	if err != nil {
		t.Fatal(err)
	}
	return out.Item != nil
}

// testDemotion is a demotion for a test member written by putTestMember, which
// leaves GrantSortKey unset (the fallback case). The signature is not checked
// at this layer; the handler verifies it.
func testDemotion(userID string) *LeaveDemotion {
	return &LeaveDemotion{
		GrantSortKey:     "GRANT#" + userID + "#2026-09-30#" + userID,
		GrantorGrantRef:  "GRANT#root",
		SigningPublicKey: []byte("k"),
		Signature:        []byte("sig"),
	}
}

func newLeaveGroup(t *testing.T, c *Client) string {
	t.Helper()
	g := "test-group-" + randomSuffix(t)
	putGroupMeta(t, c, g)
	return g
}

func TestLeaveGroupPlainMemberLeaves(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "admin1", "admin")
	putTestMember(t, c, g, "bob", "member")

	deleted, err := c.LeaveGroup(context.Background(), g, "bob", nil, nil, false)
	if err != nil || deleted {
		t.Fatalf("deleted=%v err=%v, want false/nil", deleted, err)
	}
	if itemExists(t, c, "GROUP#"+g, "MEMBER#bob") {
		t.Error("bob's membership still exists")
	}
	if !itemExists(t, c, "GROUP#"+g, "MEMBER#admin1") || !itemExists(t, c, "GROUP#"+g, "META") {
		t.Error("group or admin damaged by a member leaving")
	}
}

func TestLeaveGroupLastAdminBlockedWhileOthersRemain(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "admin1", "admin")
	putTestMember(t, c, g, "amb", "ambassador")

	if _, err := c.LeaveGroup(context.Background(), g, "admin1", testDemotion("admin1"), nil, false); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("err = %v, want ErrLastAdmin", err)
	}
	if !itemExists(t, c, "GROUP#"+g, "MEMBER#admin1") {
		t.Error("blocked admin's membership was deleted anyway")
	}
}

func TestLeaveGroupAdminMayLeaveWhenAnotherAdminExists(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "admin1", "admin")
	putTestMember(t, c, g, "admin2", "admin")

	if _, err := c.LeaveGroup(context.Background(), g, "admin1", testDemotion("admin1"), nil, false); err != nil {
		t.Fatalf("err = %v", err)
	}
	if itemExists(t, c, "GROUP#"+g, "MEMBER#admin1") || !itemExists(t, c, "GROUP#"+g, "MEMBER#admin2") {
		t.Error("wrong membership state after admin1 left")
	}
}

// The only member leaving deletes the group, including rows a naive
// "delete META and MEMBER" would orphan, across more than one 25-item batch.
func TestLeaveGroupOnlyMemberDeletesWholePartition(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "solo", "admin")
	for i := range 60 {
		_, err := c.ddb.PutItem(context.Background(), &dynamodb.PutItemInput{
			TableName: aws.String(c.table),
			Item:      map[string]types.AttributeValue{"PK": s("GROUP#" + g), "SK": s(fmt.Sprintf("GRANT#solo#%03d", i))},
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	deleted, err := c.LeaveGroup(context.Background(), g, "solo", nil, nil, false)
	if err != nil || !deleted {
		t.Fatalf("deleted=%v err=%v, want true/nil", deleted, err)
	}
	out, err := c.ddb.Query(context.Background(), &dynamodb.QueryInput{
		TableName:                 aws.String(c.table),
		KeyConditionExpression:    aws.String("PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": s("GROUP#" + g)},
		ConsistentRead:            aws.Bool(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 0 {
		t.Errorf("%d rows left under the deleted group's partition", len(out.Items))
	}
}

func TestLeaveGroupNotMember(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "admin1", "admin")
	if _, err := c.LeaveGroup(context.Background(), g, "stranger", nil, nil, false); !errors.Is(err, ErrNotMember) {
		t.Fatalf("err = %v, want ErrNotMember", err)
	}
	if _, err := c.LeaveGroup(context.Background(), "test-group-nonexistent-"+randomSuffix(t), "stranger", nil, nil, false); !errors.Is(err, ErrNotMember) {
		t.Fatalf("unknown group: err = %v, want ErrNotMember", err)
	}
}

// Two admins leaving at the same moment must never leave the group without
// one. Repeated because the failure is a race, not a deterministic path.
func TestLeaveGroupTwoAdminsLeavingNeverStrandsTheGroup(t *testing.T) {
	c := testClient(t)
	for round := range 25 {
		g := newLeaveGroup(t, c)
		putTestMember(t, c, g, "a1", "admin")
		putTestMember(t, c, g, "a2", "admin")
		putTestMember(t, c, g, "m", "member")

		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, id := range []string{"a1", "a2"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = c.LeaveGroup(context.Background(), g, id, testDemotion(id), nil, false)
			}()
		}
		wg.Wait()

		left := 0
		for _, id := range []string{"a1", "a2"} {
			if itemExists(t, c, "GROUP#"+g, "MEMBER#"+id) {
				left++
			}
		}
		if left == 0 {
			t.Fatalf("round %d: both admins left, group has none (errs: %v, %v)", round, errs[0], errs[1])
		}
	}
}

func TestLeaveGroupElevatedNeedsDemotionAndWritesIt(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "a1", "admin")
	putTestMember(t, c, g, "a2", "admin")
	putTestMember(t, c, g, "amb", "ambassador")

	for _, id := range []string{"a1", "amb"} {
		if _, err := c.LeaveGroup(ctx, g, id, nil, nil, false); !errors.Is(err, ErrDemotionRequired) {
			t.Fatalf("%s without demotion: err = %v, want ErrDemotionRequired", id, err)
		}
		if !itemExists(t, c, "GROUP#"+g, "MEMBER#"+id) {
			t.Fatalf("%s membership deleted without a demotion", id)
		}
	}

	for _, id := range []string{"a1", "amb"} {
		d := testDemotion(id)
		if _, err := c.LeaveGroup(ctx, g, id, d, nil, false); err != nil {
			t.Fatalf("%s leave: %v", id, err)
		}
		if itemExists(t, c, "GROUP#"+g, "MEMBER#"+id) {
			t.Errorf("%s membership still exists", id)
		}
		row, err := c.ddb.GetItem(ctx, getItemInput(c.table, "GROUP#"+g, d.GrantSortKey))
		if err != nil || row.Item == nil {
			t.Fatalf("%s demotion grant not written (err %v)", id, err)
		}
		var got models.RoleGrant
		if err := attributevalue.UnmarshalMap(row.Item, &got); err != nil {
			t.Fatal(err)
		}
		if got.GrantedRole != models.RoleMember || got.SubjectUserID != id || got.GrantorUserID != id || got.GrantorGrantRef != d.GrantorGrantRef {
			t.Errorf("%s grant = %+v", id, got)
		}
	}
}

// A member never carries a demotion; one arriving means their role changed
// after the request was built.
func TestLeaveGroupMemberWithDemotionConflicts(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "a", "admin")
	putTestMember(t, c, g, "m", "member")
	d := testDemotion("m")
	if _, err := c.LeaveGroup(context.Background(), g, "m", d, nil, false); !errors.Is(err, ErrLeaveConflict) {
		t.Fatalf("err = %v, want ErrLeaveConflict", err)
	}
	if !itemExists(t, c, "GROUP#"+g, "MEMBER#m") || itemExists(t, c, "GROUP#"+g, d.GrantSortKey) {
		t.Error("state changed on a rejected leave")
	}
}

// The demotion is signed against one grant; if the membership moved to
// another (or gained one), nothing is written.
func TestLeaveGroupStaleGrantRefWritesNothing(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "a1", "admin")
	putTestMember(t, c, g, "a2", "admin")
	_, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(c.table),
		Key:                       memberKey(g, "a1"),
		UpdateExpression:          aws.String("SET GrantSortKey = :g"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":g": s("GRANT#current")},
	})
	if err != nil {
		t.Fatal(err)
	}

	stale := testDemotion("a1") // HasStoredGrant false: signed against the fallback
	if _, err := c.LeaveGroup(ctx, g, "a1", stale, nil, false); !errors.Is(err, ErrLeaveConflict) {
		t.Fatalf("stale fallback: err = %v, want ErrLeaveConflict", err)
	}
	wrong := testDemotion("a1")
	wrong.HasStoredGrant, wrong.GrantorGrantRef = true, "GRANT#old"
	if _, err := c.LeaveGroup(ctx, g, "a1", wrong, nil, false); !errors.Is(err, ErrLeaveConflict) {
		t.Fatalf("wrong ref: err = %v, want ErrLeaveConflict", err)
	}
	if !itemExists(t, c, "GROUP#"+g, "MEMBER#a1") || itemExists(t, c, "GROUP#"+g, stale.GrantSortKey) {
		t.Error("state changed on a rejected leave")
	}

	ok := testDemotion("a1")
	ok.HasStoredGrant, ok.GrantorGrantRef = true, "GRANT#current"
	if _, err := c.LeaveGroup(ctx, g, "a1", ok, nil, false); err != nil {
		t.Fatalf("matching ref: %v", err)
	}
}

func TestLeaveGroupDemotionKeyTakenWritesNothing(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "a1", "admin")
	putTestMember(t, c, g, "a2", "admin")
	d := testDemotion("a1")
	_, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(c.table),
		Item:      map[string]types.AttributeValue{"PK": s("GROUP#" + g), "SK": s(d.GrantSortKey)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LeaveGroup(ctx, g, "a1", d, nil, false); !errors.Is(err, ErrLeaveGrantKeyTaken) {
		t.Fatalf("err = %v, want ErrLeaveGrantKeyTaken", err)
	}
	if !itemExists(t, c, "GROUP#"+g, "MEMBER#a1") {
		t.Error("membership deleted although the grant write failed")
	}
}

// The only member leaves with no grant at all, whatever their role.
func TestLeaveGroupSoleAdminNeedsNoDemotion(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "solo", "admin")
	deleted, err := c.LeaveGroup(context.Background(), g, "solo", nil, nil, false)
	if err != nil || !deleted {
		t.Fatalf("deleted=%v err=%v", deleted, err)
	}
}

// putTombstone writes a deleted account's PROFILE, leaving any membership in
// place: the state account deletion's documented race leaves behind (#77).
func putTombstone(t *testing.T, c *Client, userID string) {
	t.Helper()
	_, err := c.ddb.PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName: aws.String(c.table),
		Item: map[string]types.AttributeValue{
			"PK": s("USER#" + userID), "SK": s("PROFILE"), "DeletedAt": s("2026-10-05T00:00:00Z"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Test ids are short and shared across tests and runs ("admin2"), and a
	// tombstone left behind would make every later test see that user as deleted.
	t.Cleanup(func() {
		_, _ = c.ddb.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
			TableName: aws.String(c.table),
			Key:       map[string]types.AttributeValue{"PK": s("USER#" + userID), "SK": s("PROFILE")},
		})
	})
}

// A deleted admin is not another admin: nobody can sign in as them, so if the
// leaver is the only live admin the group would be left with no one to govern.
func TestLeaveGroupDeletedCoAdminDoesNotCountAsAnotherAdmin(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	ghost := "ghost-" + randomSuffix(t)
	putTestMember(t, c, g, "admin1", "admin")
	putTestMember(t, c, g, ghost, "admin")
	putTestMember(t, c, g, "bob", "member")
	putTombstone(t, c, ghost)

	_, err := c.LeaveGroup(context.Background(), g, "admin1", testDemotion("admin1"), nil, false)
	if !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("err = %v, want ErrLastAdmin", err)
	}
	if !itemExists(t, c, "GROUP#"+g, "MEMBER#admin1") {
		t.Error("the leaver was removed although no live admin remained")
	}
}

// With a live co-admin alongside the deleted one, leaving is fine, and the
// transaction's admin check must be against the live one.
func TestLeaveGroupLiveCoAdminAmongDeletedOnesIsEnough(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "admin1", "admin")
	// Sorts before the live one, so a check that just took the first admin
	// would pick the tombstone.
	ghost := "aaa-ghost-" + randomSuffix(t)
	putTestMember(t, c, g, ghost, "admin")
	putTestMember(t, c, g, "zed", "admin")
	putTombstone(t, c, ghost)

	if _, err := c.LeaveGroup(context.Background(), g, "admin1", testDemotion("admin1"), nil, false); err != nil {
		t.Fatalf("err = %v", err)
	}
	if itemExists(t, c, "GROUP#"+g, "MEMBER#admin1") {
		t.Error("admin1 did not leave")
	}
}

// The successor's account can be deleted between the roster read and the
// transaction. The transaction's own PROFILE check is what then refuses the
// leave, so the group is not stranded; a retry sees the tombstone and answers
// last_admin. The tombstone is written from inside the client, right before
// the TransactWriteItems call goes out.
func TestLeaveGroupSuccessorDeletedBetweenReadAndTransactionIsRefused(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	successor := "successor-" + randomSuffix(t)
	putTestMember(t, c, g, "admin1", "admin")
	putTestMember(t, c, g, successor, "admin")

	racing := *c
	fired := false
	racing.ddb = dynamodb.New(c.ddb.Options(), func(o *dynamodb.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("tombstone-before-txn",
				func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
					if middleware.GetOperationName(ctx) == "TransactWriteItems" && !fired {
						fired = true
						putTombstone(t, c, successor)
					}
					return next.HandleInitialize(ctx, in)
				}), middleware.Before)
		})
	})

	_, err := racing.LeaveGroup(context.Background(), g, "admin1", testDemotion("admin1"), nil, false)
	if !fired {
		t.Fatal("the tombstone was never written, so this tested nothing")
	}
	if !errors.Is(err, ErrLeaveConflict) {
		t.Fatalf("err = %v, want ErrLeaveConflict", err)
	}
	if !itemExists(t, c, "GROUP#"+g, "MEMBER#admin1") {
		t.Fatal("admin1 left although the only other admin was deleted")
	}
	// The retry now sees the tombstone up front.
	if _, err := c.LeaveGroup(context.Background(), g, "admin1", testDemotion("admin1"), nil, false); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("retry err = %v, want ErrLastAdmin", err)
	}
}

// --- Leaving a Rotating group starts a key rotation (#178) ---

func testLeaveRotation(gen int64, holders ...string) *LeaveRotation {
	rot := &LeaveRotation{
		CurrentGeneration: gen,
		Link:              models.WrappedBlob{Nonce: []byte("n"), Ciphertext: []byte("c")},
		StartSignature:    []byte("start-sig"),
	}
	for _, h := range holders {
		rot.Holders = append(rot.Holders, LeaveHolder{UserID: h, WrappedKey: models.WrappedKey{EphemeralPub: []byte("e"), Nonce: []byte("n"), Ciphertext: []byte("c")}})
	}
	return rot
}

func memberGeneration(t *testing.T, c *Client, groupID, userID string) string {
	t.Helper()
	out, err := c.ddb.GetItem(context.Background(), getItemInput(c.table, "GROUP#"+groupID, "MEMBER#"+userID))
	if err != nil || out.Item == nil {
		t.Fatalf("get member %s: %v", userID, err)
	}
	return out.Item["Generation"].(*types.AttributeValueMemberN).Value
}

func TestLeaveGroupRotationRules(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "admin1", "admin")
	putTestMember(t, c, g, "admin2", "admin")
	putTestMember(t, c, g, "bob", "member")
	ctx := context.Background()

	// A Rotating group needs the rotation; an Open one must not carry one.
	if _, err := c.LeaveGroup(ctx, g, "bob", nil, nil, true); !errors.Is(err, ErrRotationRequired) {
		t.Fatalf("no rotation in a Rotating group: %v", err)
	}
	if _, err := c.LeaveGroup(ctx, g, "bob", nil, testLeaveRotation(0, "admin1"), false); !errors.Is(err, ErrRotationNotApplicable) {
		t.Fatalf("rotation in an Open group: %v", err)
	}
	// Holder sets: none, repeated, the leaver, too many.
	many := make([]string, 0, MaxLeaveHolders+1)
	for i := 0; i <= MaxLeaveHolders; i++ {
		many = append(many, fmt.Sprintf("h%d", i))
	}
	for name, rot := range map[string]*LeaveRotation{
		"none":     testLeaveRotation(0),
		"repeated": testLeaveRotation(0, "admin1", "admin1"),
		"leaver":   testLeaveRotation(0, "admin1", "bob"),
		"too many": testLeaveRotation(0, many...),
	} {
		if _, err := c.LeaveGroup(ctx, g, "bob", nil, rot, true); !errors.Is(err, ErrLeaveHolders) {
			t.Fatalf("%s holders: %v", name, err)
		}
	}
	// The leaver must still be at the generation the key was minted from: a
	// stale view (their entry moved on) is a conflict, not a rotation from the
	// wrong generation.
	// (The holder is at 5 so only the leaver's own condition can fail.)
	if _, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(c.table),
		Key:                       memberKey(g, "admin1"),
		UpdateExpression:          aws.String("SET Generation = :g"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":g": &types.AttributeValueMemberN{Value: "5"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.LeaveGroup(ctx, g, "bob", nil, testLeaveRotation(5, "admin1"), true); !errors.Is(err, ErrLeaveConflict) {
		t.Fatalf("leaver at another generation: %v", err)
	}
	if _, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(c.table),
		Key:                       memberKey(g, "admin1"),
		UpdateExpression:          aws.String("SET Generation = :g"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":g": &types.AttributeValueMemberN{Value: "0"}},
	}); err != nil {
		t.Fatal(err)
	}
	if !itemExists(t, c, "GROUP#"+g, "MEMBER#bob") || itemExists(t, c, "GROUP#"+g, RotationSortKey) {
		t.Fatal("a refused leave changed something")
	}
	if memberGeneration(t, c, g, "admin1") != "0" {
		t.Fatal("a refused leave moved a holder")
	}

	// A good leave commits all of it, and a second leave while the rotation
	// runs is refused.
	if _, err := c.LeaveGroup(ctx, g, "bob", nil, testLeaveRotation(0, "admin1", "admin2"), true); err != nil {
		t.Fatal(err)
	}
	if itemExists(t, c, "GROUP#"+g, "MEMBER#bob") || !itemExists(t, c, "GROUP#"+g, RotationSortKey) || !itemExists(t, c, "GROUP#"+g, GenKeySortKey(0)) {
		t.Fatal("leave did not commit membership, marker and link together")
	}
	if memberGeneration(t, c, g, "admin1") != "1" || memberGeneration(t, c, g, "admin2") != "1" {
		t.Fatal("holders did not move to the new generation")
	}
	putTestMember(t, c, g, "dan", "member")
	if _, err := c.LeaveGroup(ctx, g, "dan", nil, testLeaveRotation(0, "admin1"), true); !errors.Is(err, ErrRotationInProgress) {
		t.Fatalf("second rotation: %v", err)
	}
}

// An admin leaving is checked against a live successor; when that successor is
// also a key holder the transaction would touch their row twice, which DynamoDB
// refuses. The holder's own condition (admin, at the generation) covers it.
func TestLeaveGroupSuccessorWhoIsAlsoAHolder(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "admin1", "admin")
	putTestMember(t, c, g, "admin2", "admin")
	putTestMember(t, c, g, "bob", "member")
	// Every other admin is the holder, so the successor is among them.
	if _, err := c.LeaveGroup(context.Background(), g, "admin1", testDemotion("admin1"), testLeaveRotation(0, "admin2"), true); err != nil {
		t.Fatalf("leave: %v", err)
	}
	if memberGeneration(t, c, g, "admin2") != "1" {
		t.Fatal("holder did not move")
	}
}

func TestLeaveGroupHolderWhoIsNotAnAdminIsAConflict(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "admin1", "admin")
	putTestMember(t, c, g, "bob", "member")
	putTestMember(t, c, g, "cat", "member")
	if _, err := c.LeaveGroup(context.Background(), g, "bob", nil, testLeaveRotation(0, "admin1", "cat"), true); !errors.Is(err, ErrLeaveHolderChanged) {
		t.Fatalf("non-admin holder: %v", err)
	}
	if !itemExists(t, c, "GROUP#"+g, "MEMBER#bob") || memberGeneration(t, c, g, "admin1") != "0" {
		t.Fatal("a refused leave changed something")
	}
}
