package db

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Re-admitting a member (#178) replaces their ADMISSION# row with the caller's
// fresh signed one; every refusal must leave the old row exactly as it was.

func readmitInput(g string) ReadmitMemberInput {
	return ReadmitMemberInput{
		GroupID: g, SubjectUserID: "bob",
		SubjectEd25519: []byte("ed-bob"), SubjectX25519: []byte("x-bob"),
		CallerUserID: "a1", CallerGeneration: 0, CallerGrantRef: "GRANT#a1#2026-01-01#1",
		InviteID: "readmit-1", Day: "2026-10-09", Signature: []byte("sig-new"),
	}
}

func readmitGroup(t *testing.T, c *Client) string {
	t.Helper()
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "a1", "admin")
	putTestMember(t, c, g, "bob", "member")
	putTestAdmission(t, c, g, "bob") // the stale record being replaced
	setGrantRef(t, c, g, "a1", "GRANT#a1#2026-01-01#1")
	return g
}

func setGrantRef(t *testing.T, c *Client, g, user, ref string) {
	t.Helper()
	if _, err := c.ddb.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:                 aws.String(c.table),
		Key:                       memberKey(g, user),
		UpdateExpression:          aws.String("SET GrantSortKey = :r"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":r": s(ref)},
	}); err != nil {
		t.Fatal(err)
	}
}

func admissionSignature(t *testing.T, c *Client, g, user string) string {
	t.Helper()
	out, err := c.ddb.GetItem(context.Background(), getItemInput(c.table, "GROUP#"+g, "ADMISSION#"+user))
	if err != nil || out.Item == nil {
		t.Fatalf("admission row: %v", err)
	}
	if v, ok := out.Item["Signature"].(*types.AttributeValueMemberB); ok {
		return string(v.Value)
	}
	return ""
}

func TestReadmitMemberReplacesTheAdmission(t *testing.T) {
	c := testClient(t)
	g := readmitGroup(t, c)
	in := readmitInput(g)
	in.CallerHasStoredGrant = true
	if err := c.ReadmitMember(context.Background(), in); err != nil {
		t.Fatalf("ReadmitMember: %v", err)
	}
	if got := admissionSignature(t, c, g, "bob"); got != "sig-new" {
		t.Fatalf("admission signature = %q, want the new one", got)
	}
	// A running rotation does not block it: a rotation paused on an unadmitted
	// member is exactly when this is needed.
	if _, err := c.ddb.PutItem(context.Background(), &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: map[string]types.AttributeValue{
		"PK": s("GROUP#" + g), "SK": s(RotationSortKey), "StartedBy": s("a1"),
	}}); err != nil {
		t.Fatal(err)
	}
	in.Signature = []byte("sig-newer")
	if err := c.ReadmitMember(context.Background(), in); err != nil {
		t.Fatalf("ReadmitMember during a rotation: %v", err)
	}
	if got := admissionSignature(t, c, g, "bob"); got != "sig-newer" {
		t.Fatalf("admission signature = %q, want sig-newer", got)
	}
}

func TestReadmitMemberRefusalsChangeNothing(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		prepare func(t *testing.T, c *Client, g string, in *ReadmitMemberInput)
		want    error
	}{
		"caller demoted to member": {func(t *testing.T, c *Client, g string, in *ReadmitMemberInput) {
			putTestMember(t, c, g, "a1", "member")
			setGrantRef(t, c, g, "a1", in.CallerGrantRef)
			in.CallerHasStoredGrant = true
		}, ErrReadmitCallerChanged},
		"caller on another generation": {func(t *testing.T, c *Client, g string, in *ReadmitMemberInput) {
			in.CallerGeneration = 1
			in.CallerHasStoredGrant = true
		}, ErrReadmitCallerChanged},
		"caller's grant changed": {func(t *testing.T, c *Client, g string, in *ReadmitMemberInput) {
			setGrantRef(t, c, g, "a1", "GRANT#a1#2026-02-02#2")
			in.CallerHasStoredGrant = true
		}, ErrReadmitCallerChanged},
		"creator signed the root grant but now holds a stored one": {func(t *testing.T, c *Client, g string, in *ReadmitMemberInput) {
			in.CallerHasStoredGrant = false
		}, ErrReadmitCallerChanged},
		"member left": {func(t *testing.T, c *Client, g string, in *ReadmitMemberInput) {
			in.CallerHasStoredGrant = true
			if _, err := c.LeaveGroup(ctx, g, "bob", nil, nil, false); err != nil {
				t.Fatal(err)
			}
			putTestAdmission(t, c, g, "bob")
		}, ErrNotMember},
		"account deleted": {func(t *testing.T, c *Client, g string, in *ReadmitMemberInput) {
			in.CallerHasStoredGrant = true
			if _, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: map[string]types.AttributeValue{
				"PK": s("USER#bob"), "SK": s("PROFILE"), "DeletedAt": s("2026-10-09T00:00:00Z"),
			}}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(c.table), Key: map[string]types.AttributeValue{"PK": s("USER#bob"), "SK": s("PROFILE")}})
			})
		}, ErrSubjectDeleted},
		"group gone": {func(t *testing.T, c *Client, g string, in *ReadmitMemberInput) {
			in.CallerHasStoredGrant = true
			if _, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(c.table), Key: map[string]types.AttributeValue{"PK": s("GROUP#" + g), "SK": s("META")}}); err != nil {
				t.Fatal(err)
			}
		}, ErrGroupGone},
	} {
		t.Run(name, func(t *testing.T) {
			c := testClient(t)
			g := readmitGroup(t, c)
			in := readmitInput(g)
			tc.prepare(t, c, g, &in)
			err := c.ReadmitMember(ctx, in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if got := admissionSignature(t, c, g, "bob"); got == "sig-new" {
				t.Fatal("a refused re-admission replaced the admission")
			}
		})
	}
}
