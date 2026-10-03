package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

func registerTestUser(t *testing.T, c *Client) RegisterInput {
	t.Helper()
	in := testRegisterInput("test-acct-"+randomSuffix(t), "acct-"+randomSuffix(t))
	in.SigningPublicKey = []byte("0123456789abcdef0123456789abcdef")
	if err := c.Register(context.Background(), in); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return in
}

func TestDeleteAccountTombstonesProfileAndRemovesLoginRows(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	in := registerTestUser(t, c)
	uid := in.UserID

	if err := c.PutPin(ctx, uid, "other-"+randomSuffix(t), [][]byte{make([]byte, 32)}, make([]byte, 32), make([]byte, 32), make([]byte, 64)); err != nil {
		t.Fatalf("PutPin: %v", err)
	}
	if err := c.PutChallenge(ctx, uid, []byte("nonce"), time.Minute); err != nil {
		t.Fatalf("PutChallenge: %v", err)
	}

	if err := c.DeleteAccount(ctx, uid); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	user, err := c.GetUserByID(ctx, uid)
	if err != nil {
		t.Fatalf("PROFILE must survive as a tombstone: %v", err)
	}
	if user.DeletedAt == "" {
		t.Error("DeletedAt not set")
	}
	if user.Username != "" {
		t.Errorf("Username = %q, want cleared", user.Username)
	}
	if len(user.Salt) != 0 || len(user.WrappedPrivateKeys.Ciphertext) != 0 {
		t.Error("credential material still on the tombstone")
	}
	if string(user.SigningPublicKey) != string(in.SigningPublicKey) {
		t.Error("public signing key must be kept so old signatures still verify")
	}

	if itemExists(t, c, "USERNAME#"+in.UsernameLower, "CLAIM") {
		t.Error("USERNAME claim still exists")
	}
	if _, err := c.LookupUserByUsername(ctx, in.UsernameLower); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("login lookup of a deleted account = %v, want ErrUserNotFound", err)
	}
	for _, sk := range []string{"RECOVERY", "CHALLENGE"} {
		if itemExists(t, c, "USER#"+uid, sk) {
			t.Errorf("%s still exists", sk)
		}
	}
	pins, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
		TableName:                 aws.String(c.table),
		KeyConditionExpression:    aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": s("USER#" + uid), ":sk": s("PIN#")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pins.Items) != 0 {
		t.Errorf("%d pins remain", len(pins.Items))
	}

	// The username is free again and the uuid is not reusable.
	again := testRegisterInput("test-acct-"+randomSuffix(t), in.Username)
	if err := c.Register(ctx, again); err != nil {
		t.Errorf("re-registering the freed username: %v", err)
	}
	reuse := testRegisterInput(uid, "acct-"+randomSuffix(t))
	if err := c.Register(ctx, reuse); !errors.Is(err, ErrUserIDTaken) {
		t.Errorf("re-registering the deleted uuid = %v, want ErrUserIDTaken", err)
	}
}

func TestDeleteAccountRefusesWhileMember(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	in := registerTestUser(t, c)
	gid := "test-group-" + randomSuffix(t)
	putGroupMeta(t, c, gid)
	putTestMember(t, c, gid, in.UserID, models.RoleMember)

	if err := c.DeleteAccount(ctx, in.UserID); !errors.Is(err, ErrStillMember) {
		t.Fatalf("DeleteAccount = %v, want ErrStillMember", err)
	}
	user, err := c.GetUserByID(ctx, in.UserID)
	if err != nil || user.DeletedAt != "" {
		t.Fatalf("a refused deletion must change nothing (err=%v, DeletedAt=%q)", err, user.DeletedAt)
	}
	if !itemExists(t, c, "USERNAME#"+in.UsernameLower, "CLAIM") || !itemExists(t, c, "USER#"+in.UserID, "RECOVERY") {
		t.Error("a refused deletion removed login rows")
	}

	if _, err := c.LeaveGroup(ctx, gid, in.UserID, nil); err != nil {
		t.Fatalf("LeaveGroup: %v", err)
	}
	// Only member, so the group was deleted; now deletion succeeds.
	if err := c.DeleteAccount(ctx, in.UserID); err != nil {
		t.Fatalf("DeleteAccount after leaving: %v", err)
	}
}

func TestDeleteAccountRemovesInvitesAndIsRepeatable(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	in := registerTestUser(t, c)
	gid := "test-group-" + randomSuffix(t)
	other := "test-other-" + randomSuffix(t)
	putGroupMeta(t, c, gid)
	putTestMember(t, c, gid, other, models.RoleAdmin)

	// An invite this user sent (they are not a member any more, so it is
	// written directly) and one addressed to them.
	sent := "test-invite-" + randomSuffix(t)
	recv := "test-invite-" + randomSuffix(t)
	for _, it := range []map[string]types.AttributeValue{
		{"PK": s("USER#" + in.UserID), "SK": s("SENT#" + sent), "InviteID": s(sent), "GroupID": s(gid)},
		{"PK": s("INVITE#" + sent), "SK": s("META")},
		{"PK": s("INVITE#" + recv), "SK": s("META"), "GSI1PK": s("USER#" + in.UserID), "GSI1SK": s("INVITE#2026-10-03#x")},
	} {
		if _, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: it}); err != nil {
			t.Fatal(err)
		}
	}

	if err := c.DeleteAccount(ctx, in.UserID); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	for _, k := range [][2]string{{"USER#" + in.UserID, "SENT#" + sent}, {"INVITE#" + sent, "META"}, {"INVITE#" + recv, "META"}} {
		if itemExists(t, c, k[0], k[1]) {
			t.Errorf("%s/%s still exists", k[0], k[1])
		}
	}
	if !itemExists(t, c, "GROUP#"+gid, "MEMBER#"+other) {
		t.Error("another member's row was touched")
	}
	// A second call finishes any leftover cleanup and does not fail.
	if err := c.DeleteAccount(ctx, in.UserID); err != nil {
		t.Errorf("repeat DeleteAccount: %v", err)
	}
}

func TestCompleteInviteRefusesDeletedInvitee(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	invitee := registerTestUser(t, c)
	if err := c.DeleteAccount(ctx, invitee.UserID); err != nil {
		t.Fatal(err)
	}
	inviteID := "test-invite-" + randomSuffix(t)
	gid := "test-group-" + randomSuffix(t)
	inviter := "test-inviter-" + randomSuffix(t)
	putGroupMeta(t, c, gid)
	putTestMember(t, c, gid, inviter, models.RoleAdmin)
	if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, gid, inviter, time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, invitee.UserID)); err != nil {
		t.Fatal(err)
	}
	err := c.CompleteInvite(ctx, testCompleteInviteInput(inviteID, gid, inviter, invitee.UserID))
	if !errors.Is(err, ErrInviteeDeleted) {
		t.Fatalf("CompleteInvite = %v, want ErrInviteeDeleted", err)
	}
	if itemExists(t, c, "GROUP#"+gid, "MEMBER#"+invitee.UserID) {
		t.Error("a membership was written for a deleted account")
	}
}

// A session cookie issued before deletion stays valid for its TTL, so a
// password change from it must not put credentials back on the tombstone.
func TestRewrapCredentialsCannotReviveDeletedAccount(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	in := registerTestUser(t, c)
	if err := c.DeleteAccount(ctx, in.UserID); err != nil {
		t.Fatal(err)
	}
	if err := c.RewrapCredentials(ctx, testRewrapInput(in.UserID, 1)); err == nil {
		t.Fatal("RewrapCredentials succeeded on a deleted account")
	}
	user, err := c.GetUserByID(ctx, in.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(user.WrappedPrivateKeys.Ciphertext) != 0 || len(user.Salt) != 0 {
		t.Error("credential material was written back onto the tombstone")
	}
	if itemExists(t, c, "USER#"+in.UserID, "RECOVERY") {
		t.Error("RECOVERY was recreated")
	}
}

func TestCreateGroupRefusesDeletedCreator(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	in := registerTestUser(t, c)
	if err := c.DeleteAccount(ctx, in.UserID); err != nil {
		t.Fatal(err)
	}
	gid := "test-group-" + randomSuffix(t)
	_, err := c.CreateGroup(ctx, testCreateGroupInput(t, gid, in.UserID))
	if !errors.Is(err, ErrCreatorDeleted) {
		t.Fatalf("CreateGroup = %v, want ErrCreatorDeleted", err)
	}
	if itemExists(t, c, "GROUP#"+gid, "META") || itemExists(t, c, "GROUP#"+gid, "MEMBER#"+in.UserID) {
		t.Error("rows were written for a deleted creator")
	}
}
