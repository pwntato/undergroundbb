package db

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// settledGroup: admins a1, a2 and member m2, all at generation 0 with no
// rotation marker (leaver bob is gone and the leave rotation was finished).
func settledGroup(t *testing.T, c *Client) string {
	t.Helper()
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "a1", "admin")
	putTestMember(t, c, g, "a2", "admin")
	putTestMember(t, c, g, "m2", "member")
	putMode(t, c, g, "rotating")
	return g
}

// putMode gives the fixture's META the mode a real group always has.
func putMode(t *testing.T, c *Client, g, mode string) {
	t.Helper()
	if _, err := c.ddb.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:                 aws.String(c.table),
		Key:                       map[string]types.AttributeValue{"PK": s("GROUP#" + g), "SK": s("META")},
		UpdateExpression:          aws.String("SET RevocationMode = :m"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":m": s(mode)},
	}); err != nil {
		t.Fatal(err)
	}
}

func modeInMeta(t *testing.T, c *Client, g string) string {
	t.Helper()
	got, err := c.GetGroup(context.Background(), g)
	if err != nil || got == nil {
		t.Fatalf("group: %v %v", got, err)
	}
	return got.RevocationMode
}

func TestConvertGroupToOpen(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := settledGroup(t, c)
	if err := c.ConvertGroupToOpen(ctx, g, "m2", 0); !errors.Is(err, ErrNotGroupAdmin) {
		t.Fatalf("a member: %v, want ErrNotGroupAdmin", err)
	}
	// The caller's generation is part of the check: an admin whose entry is
	// not at the generation the handler read is refused rather than converting
	// on a stale view.
	if err := c.convertTx(ctx, g, "a1", 3); !errors.Is(err, ErrNotGroupAdmin) {
		t.Fatalf("a stale generation: %v, want ErrNotGroupAdmin", err)
	}
	if m := modeInMeta(t, c, g); m != "rotating" {
		t.Fatalf("mode = %q after refusals", m)
	}

	if err := c.ConvertGroupToOpen(ctx, g, "a1", 0); err != nil {
		t.Fatalf("convert: %v", err)
	}
	if m := modeInMeta(t, c, g); m != "open" {
		t.Fatalf("mode = %q, want open", m)
	}
	if err := c.ConvertGroupToOpen(ctx, g, "a1", 0); !errors.Is(err, ErrGroupAlreadyOpen) {
		t.Fatalf("again: %v, want ErrGroupAlreadyOpen", err)
	}
}

func TestConvertGroupToOpenWaitsForMembersButNotForDormantOnes(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := settledGroup(t, c)
	// a1 is at generation 1; m2 and a2 are still at 0, so a rotation is owed.
	setMemberGeneration(t, c, g, "a1", 1)
	putProfileAtEpoch(t, c, "m2", 0, false)
	putProfileAtEpoch(t, c, "a2", 0, false)
	if err := c.ConvertGroupToOpen(ctx, g, "a1", 1); !errors.Is(err, ErrMembersBehind) {
		t.Fatalf("members behind: %v, want ErrMembersBehind", err)
	}
	if m := modeInMeta(t, c, g); m != "rotating" {
		t.Fatalf("mode = %q after a refusal", m)
	}
	// Both rotated their keys: they are dormant (entry wrapped to a replaced
	// key), which an ordinary rotation never fixes, so they do not hold it up.
	putProfileAtEpoch(t, c, "m2", 1, false)
	putProfileAtEpoch(t, c, "a2", 1, false)
	if err := c.ConvertGroupToOpen(ctx, g, "a1", 1); err != nil {
		t.Fatalf("dormant members: %v", err)
	}
}

func TestConvertGroupToOpenRefusesARunningRotation(t *testing.T) {
	c := testClient(t)
	g := startedRotation(t, c)
	if err := c.ConvertGroupToOpen(context.Background(), g, "a1", 1); !errors.Is(err, ErrRotationInProgress) {
		t.Fatalf("mid-rotation: %v, want ErrRotationInProgress", err)
	}
}

// The handler and ConvertGroupToOpen read the marker first, so only the
// transaction holds the line against a rotation that starts after that read.
func TestConvertTransactionRefusesAMarkerAndAnOpenGroup(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := startedRotation(t, c)
	putMode(t, c, g, "rotating")
	if err := c.convertTx(ctx, g, "a1", 1); !errors.Is(err, ErrRotationInProgress) {
		t.Fatalf("with a marker: %v, want ErrRotationInProgress", err)
	}
	if m := modeInMeta(t, c, g); m != "rotating" {
		t.Fatalf("mode = %q after a refusal", m)
	}
	h := settledGroup(t, c)
	if err := c.convertTx(ctx, h, "a1", 0); err != nil {
		t.Fatal(err)
	}
	if err := c.convertTx(ctx, h, "a1", 0); !errors.Is(err, ErrGroupAlreadyOpen) {
		t.Fatalf("already open: %v, want ErrGroupAlreadyOpen", err)
	}
}
