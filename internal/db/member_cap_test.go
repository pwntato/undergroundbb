package db

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func deleteItemInput(table, pk, sk string) *dynamodb.DeleteItemInput {
	return &dynamodb.DeleteItemInput{
		TableName: aws.String(table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: pk},
			"SK": &types.AttributeValueMemberS{Value: sk},
		},
	}
}

// capFixture is a group with one admin and n accepted-but-uncompleted invites,
// each to its own invitee.
type capFixture struct {
	groupID, inviterID string
	invites            []capInvite
}

type capInvite struct{ inviteID, inviteeID string }

func newCapFixture(t *testing.T, c *Client, invites int) capFixture {
	t.Helper()
	ctx := context.Background()
	f := capFixture{
		groupID:   "test-group-" + randomSuffix(t),
		inviterID: "test-inviter-" + randomSuffix(t),
	}
	putGroupMeta(t, c, f.groupID)
	putTestMember(t, c, f.groupID, f.inviterID, "admin")
	for i := 0; i < invites; i++ {
		inv := capInvite{inviteID: "test-invite-" + randomSuffix(t), inviteeID: "test-invitee-" + randomSuffix(t)}
		if err := c.CreateInvite(ctx, testCreateInviteInput(t, inv.inviteID, f.groupID, f.inviterID, time.Now().Add(7*24*time.Hour))); err != nil {
			t.Fatalf("CreateInvite: %v", err)
		}
		if err := c.AcceptInvite(ctx, testAcceptInviteInput(inv.inviteID, inv.inviteeID)); err != nil {
			t.Fatalf("AcceptInvite: %v", err)
		}
		f.invites = append(f.invites, inv)
	}
	return f
}

func (f capFixture) complete(c *Client, i, maxMembers int) error {
	in := testCompleteInviteInput(f.invites[i].inviteID, f.groupID, f.inviterID, f.invites[i].inviteeID)
	in.MaxMembers = maxMembers
	return c.CompleteInvite(context.Background(), in)
}

func mustCount(t *testing.T, c *Client, groupID string) int {
	t.Helper()
	n, err := c.CountMembers(context.Background(), groupID)
	if err != nil {
		t.Fatalf("CountMembers: %v", err)
	}
	return n
}

func TestCompleteInviteStopsAtTheCap(t *testing.T) {
	c := testClient(t)
	f := newCapFixture(t, c, 3)

	// The inviter is member 1; a cap of 3 leaves room for exactly two more.
	for i := 0; i < 2; i++ {
		if err := f.complete(c, i, 3); err != nil {
			t.Fatalf("join %d under the cap: %v", i, err)
		}
	}
	if err := f.complete(c, 2, 3); !errors.Is(err, ErrGroupFull) {
		t.Fatalf("join at the cap = %v, want ErrGroupFull", err)
	}
	if n := mustCount(t, c, f.groupID); n != 3 {
		t.Errorf("members = %d, want 3", n)
	}
}

func TestCompleteInviteCapFollowsDepartures(t *testing.T) {
	c := testClient(t)
	f := newCapFixture(t, c, 2)
	if err := f.complete(c, 0, 2); err != nil {
		t.Fatalf("first join: %v", err)
	}
	if err := f.complete(c, 1, 2); !errors.Is(err, ErrGroupFull) {
		t.Fatalf("join into a full group = %v, want ErrGroupFull", err)
	}

	// A member leaving or being removed deletes their MEMBER# row, which frees the slot.
	if _, err := c.ddb.DeleteItem(context.Background(), deleteItemInput(c.table, "GROUP#"+f.groupID, "MEMBER#"+f.invites[0].inviteeID)); err != nil {
		t.Fatalf("delete member: %v", err)
	}
	if err := f.complete(c, 1, 2); err != nil {
		t.Fatalf("join after a departure: %v", err)
	}
}

func TestCompleteInviteCapIsTunable(t *testing.T) {
	c := testClient(t)
	f := newCapFixture(t, c, 3)
	if err := f.complete(c, 0, 2); err != nil {
		t.Fatalf("join: %v", err)
	}
	if err := f.complete(c, 1, 2); !errors.Is(err, ErrGroupFull) {
		t.Fatalf("at cap 2 = %v, want ErrGroupFull", err)
	}
	// The same group, the same state, a larger cap: the next join goes through.
	if err := f.complete(c, 1, 3); err != nil {
		t.Fatalf("after raising the cap to 3: %v", err)
	}
}

func TestCompleteInviteWithoutACapIgnoresTheCount(t *testing.T) {
	c := testClient(t)
	f := newCapFixture(t, c, 3)
	for i := range f.invites {
		if err := f.complete(c, i, 0); err != nil {
			t.Fatalf("uncapped join %d: %v", i, err)
		}
	}
	if seq, err := c.joinSeq(context.Background(), f.groupID); err != nil || seq != 0 {
		t.Errorf("joinSeq = %d, %v after uncapped joins, want 0 (an Open group is never serialized)", seq, err)
	}
}

func TestCompleteInviteBumpsJoinSeqOnCappedJoins(t *testing.T) {
	c := testClient(t)
	f := newCapFixture(t, c, 3)
	for i := 0; i < 3; i++ {
		if err := f.complete(c, i, 10); err != nil {
			t.Fatalf("join %d: %v", i, err)
		}
		if seq, err := c.joinSeq(context.Background(), f.groupID); err != nil || seq != int64(i+1) {
			t.Fatalf("joinSeq after join %d = %d, %v, want %d", i, seq, err, i+1)
		}
	}
}

func TestCompleteInviteFullGroupStillReportsAlreadyMember(t *testing.T) {
	c := testClient(t)
	f := newCapFixture(t, c, 1)
	// The invitee is already a member some other way, and the group is full.
	putTestMember(t, c, f.groupID, f.invites[0].inviteeID, "member")
	if err := f.complete(c, 0, 2); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("full group, existing member = %v, want ErrAlreadyMember", err)
	}
}

func TestCompleteInviteCappedGroupGone(t *testing.T) {
	c := testClient(t)
	f := newCapFixture(t, c, 1)
	if _, err := c.ddb.DeleteItem(context.Background(), deleteItemInput(c.table, "GROUP#"+f.groupID, "META")); err != nil {
		t.Fatalf("delete META: %v", err)
	}
	if err := f.complete(c, 0, 5); !errors.Is(err, ErrGroupGone) {
		t.Fatalf("capped join into a deleted group = %v, want ErrGroupGone", err)
	}
}

// Many joins at once into a group with room for fewer of them. Without the
// JoinSeq guard each would count the same number of members, find room, and all
// succeed. Run several rounds: the failure is a race, not a deterministic one.
func TestCompleteInviteCapHoldsUnderConcurrentJoins(t *testing.T) {
	const (
		rounds     = 8
		contenders = 6
		cap_       = 4 // the inviter plus room for 3
	)
	c := testClient(t)
	for round := 0; round < rounds; round++ {
		f := newCapFixture(t, c, contenders)

		var wg sync.WaitGroup
		errs := make([]error, contenders)
		start := make(chan struct{})
		for i := 0; i < contenders; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				errs[i] = f.complete(c, i, cap_)
			}(i)
		}
		close(start)
		wg.Wait()

		ok, full := 0, 0
		for i, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrGroupFull):
				full++
			default:
				t.Fatalf("round %d contender %d: unexpected error %v", round, i, err)
			}
		}
		if n := mustCount(t, c, f.groupID); n > cap_ {
			t.Fatalf("round %d: group has %d members, cap is %d (ok=%d full=%d)", round, n, cap_, ok, full)
		}
		if ok != cap_-1 || full != contenders-(cap_-1) {
			t.Fatalf("round %d: ok=%d full=%d, want ok=%d full=%d", round, ok, full, cap_-1, contenders-(cap_-1))
		}
	}
}
