package db

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
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

	deleted, err := c.LeaveGroup(context.Background(), g, "bob")
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

	if _, err := c.LeaveGroup(context.Background(), g, "admin1"); !errors.Is(err, ErrLastAdmin) {
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

	if _, err := c.LeaveGroup(context.Background(), g, "admin1"); err != nil {
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

	deleted, err := c.LeaveGroup(context.Background(), g, "solo")
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
	if _, err := c.LeaveGroup(context.Background(), g, "stranger"); !errors.Is(err, ErrNotMember) {
		t.Fatalf("err = %v, want ErrNotMember", err)
	}
	if _, err := c.LeaveGroup(context.Background(), "test-group-nonexistent-"+randomSuffix(t), "stranger"); !errors.Is(err, ErrNotMember) {
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
				_, errs[i] = c.LeaveGroup(context.Background(), g, id)
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
