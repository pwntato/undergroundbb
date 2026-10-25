package db

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

func setMemberGeneration(t *testing.T, c *Client, groupID, userID string, gen int64) {
	t.Helper()
	if _, err := c.ddb.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:                 aws.String(c.table),
		Key:                       memberKey(groupID, userID),
		UpdateExpression:          aws.String("SET Generation = :g"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":g": &types.AttributeValueMemberN{Value: strconv.FormatInt(gen, 10)}},
	}); err != nil {
		t.Fatal(err)
	}
}

func approveInput(g, approver, member string, gen int64, kep uint64) ApproveRewrapInput {
	return ApproveRewrapInput{
		GroupID: g, ApproverUserID: approver, MemberUserID: member, Generation: gen, KeyEpoch: kep,
		Wrapped: models.WrappedKey{EphemeralPub: []byte("e"), Nonce: []byte("n"), Ciphertext: []byte("A-" + member)},
	}
}

// approveFixture: a1 is an admin at generation 1 (rotation 0 to 1 in progress),
// a2 rotated (KeyEpoch 1) and is dormant behind at generation 0.
func approveFixture(t *testing.T, c *Client) string {
	t.Helper()
	g := startedRotation(t, c)
	putProfileAtEpoch(t, c, "a2", 1, false)
	return g
}

func TestApproveRewrapWritesWrapGenerationAndEpoch(t *testing.T) {
	c := testClient(t)
	g := approveFixture(t, c)
	if err := c.ApproveRewrap(context.Background(), approveInput(g, "a1", "a2", 1, 1)); err != nil {
		t.Fatal(err)
	}
	m := readMember(t, c, g, "a2")
	if m.Generation != 1 || m.WrapEpoch != 1 || string(m.WrappedGroupKey.Ciphertext) != "A-a2" {
		t.Fatalf("a2 = gen %d, WrapEpoch %d, key %q; want 1, 1, A-a2", m.Generation, m.WrapEpoch, m.WrappedGroupKey.Ciphertext)
	}
}

func TestApproveRewrapIsRefusedWhileTheOldKeysHoldTheCurrentKey(t *testing.T) {
	c := testClient(t)
	g := approveFixture(t, c)
	// a2's entry is at the generation the approver holds: the keys they
	// rotated away from still read it, so only a re-key helps.
	setMemberGeneration(t, c, g, "a2", 1)
	err := c.ApproveRewrap(context.Background(), approveInput(g, "a1", "a2", 1, 1))
	if !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("member at the current generation: %v, want ErrRekeyRequired", err)
	}
	if m := readMember(t, c, g, "a2"); m.WrapEpoch != 0 || string(m.WrappedGroupKey.Ciphertext) == "A-a2" {
		t.Fatalf("a refused approval wrote the member: %+v", m)
	}
	// Past the generation the approver holds: the member moved on, not a re-key.
	setMemberGeneration(t, c, g, "a2", 2)
	if err := c.ApproveRewrap(context.Background(), approveInput(g, "a1", "a2", 1, 1)); !errors.Is(err, ErrRewrapMemberChanged) {
		t.Fatalf("member past the generation: %v, want ErrRewrapMemberChanged", err)
	}
}

func TestApproveRewrapWithoutAMarkerStillNeedsAMemberBehind(t *testing.T) {
	c := testClient(t)
	g := approveFixture(t, c)
	if _, err := c.ddb.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{TableName: aws.String(c.table), Key: rotationKey(g)}); err != nil {
		t.Fatal(err)
	}
	// A catch-up after completion: a2 is strictly behind, so a plain wrap is right.
	if err := c.ApproveRewrap(context.Background(), approveInput(g, "a1", "a2", 1, 1)); err != nil {
		t.Fatal(err)
	}
	// m2 is at the current generation and dormant: a re-key, not a wrap.
	putTestMember(t, c, g, "m2", "member")
	setMemberGeneration(t, c, g, "m2", 1)
	putProfileAtEpoch(t, c, "m2", 1, false)
	if err := c.ApproveRewrap(context.Background(), approveInput(g, "a1", "m2", 1, 1)); !errors.Is(err, ErrRekeyRequired) {
		t.Fatalf("no marker, member at the generation: %v, want ErrRekeyRequired", err)
	}
}

func TestApproveRewrapInAnOpenGroupReplacesTheOldKeyCopy(t *testing.T) {
	c := testClient(t)
	g := approveFixture(t, c)
	setMemberGeneration(t, c, g, "a2", 1)
	in := approveInput(g, "a1", "a2", 1, 1)
	in.Open = true
	if err := c.ApproveRewrap(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if m := readMember(t, c, g, "a2"); m.Generation != 1 || m.WrapEpoch != 1 || string(m.WrappedGroupKey.Ciphertext) != "A-a2" {
		t.Fatalf("a2 = %+v", m)
	}
	// Open does not widen anything else: a member past the generation is refused.
	setMemberGeneration(t, c, g, "a2", 2)
	setWrapEpoch(t, c, g, "a2", 0)
	if err := c.ApproveRewrap(context.Background(), in); !errors.Is(err, ErrRewrapMemberChanged) {
		t.Fatalf("open, member past the generation: %v, want ErrRewrapMemberChanged", err)
	}
}

func TestApproveRewrapChecksTheMemberTheEpochAndTheApprover(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := approveFixture(t, c)

	// The member rotated again since the approver read their keys.
	putProfileAtEpoch(t, c, "a2", 2, false)
	if err := c.ApproveRewrap(ctx, approveInput(g, "a1", "a2", 1, 1)); !errors.Is(err, ErrWrapEpochStale) {
		t.Fatalf("stale epoch: %v, want ErrWrapEpochStale", err)
	}
	putProfileAtEpoch(t, c, "a2", 1, false)

	// A member whose entry already matches their key has nothing to approve.
	setWrapEpoch(t, c, g, "a2", 1)
	if err := c.ApproveRewrap(ctx, approveInput(g, "a1", "a2", 1, 1)); !errors.Is(err, ErrMemberNotDormant) {
		t.Fatalf("not dormant: %v, want ErrMemberNotDormant", err)
	}
	setWrapEpoch(t, c, g, "a2", 0)

	// An account that never rotated has nothing to approve.
	putTestMember(t, c, g, "m4", "member")
	if err := c.ApproveRewrap(ctx, approveInput(g, "a1", "m4", 1, 0)); !errors.Is(err, ErrMemberNotDormant) {
		t.Fatalf("epoch 0: %v, want ErrMemberNotDormant", err)
	}

	// The marker names another generation.
	if err := c.ApproveRewrap(ctx, approveInput(g, "a1", "a2", 2, 1)); !errors.Is(err, ErrRotationNotActive) {
		t.Fatalf("wrong generation: %v, want ErrRotationNotActive", err)
	}
	// A plain member cannot approve, and an approver behind the generation
	// does not hold the key.
	putTestMember(t, c, g, "m3", "member")
	setMemberGeneration(t, c, g, "m3", 1)
	if err := c.ApproveRewrap(ctx, approveInput(g, "m3", "a2", 1, 1)); !errors.Is(err, ErrRewrapCallerBehind) {
		t.Fatalf("member as approver: %v, want ErrRewrapCallerBehind", err)
	}
	putProfileAtEpoch(t, c, "bob", 1, false)
	if err := c.ApproveRewrap(ctx, approveInput(g, "a2", "a1", 1, 0)); !errors.Is(err, ErrRewrapCallerBehind) {
		t.Fatalf("approver behind: %v, want ErrRewrapCallerBehind", err)
	}
	// A member who left (or deleted their account) is gone, not stale.
	putProfileAtEpoch(t, c, "gone", 1, true)
	putTestMember(t, c, g, "gone", "member")
	if err := c.ApproveRewrap(ctx, approveInput(g, "a1", "gone", 1, 1)); !errors.Is(err, ErrRewrapMemberChanged) {
		t.Fatalf("deleted account: %v, want ErrRewrapMemberChanged", err)
	}
	if err := c.ApproveRewrap(ctx, approveInput(g, "a1", "nobody", 1, 0)); !errors.Is(err, ErrRewrapMemberChanged) {
		t.Fatalf("not a member: %v, want ErrRewrapMemberChanged", err)
	}

	// An ambassador at the generation may approve.
	putTestMember(t, c, g, "amb", "ambassador")
	setMemberGeneration(t, c, g, "amb", 1)
	if err := c.ApproveRewrap(ctx, approveInput(g, "amb", "a2", 1, 1)); err != nil {
		t.Fatalf("ambassador: %v", err)
	}
}
