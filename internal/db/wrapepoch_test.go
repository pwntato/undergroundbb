package db

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// Every writer of a MEMBER# wrap records the recipient's KeyEpoch as WrapEpoch
// and checks it against PROFILE in the same transaction (#62), so a wrap to a
// key that was just replaced is refused, and a member whose WrapEpoch is behind
// their KeyEpoch (dormant) is not wrapped to by an ordinary rotation.

// putProfileAtEpoch writes a stand-in PROFILE with the given KeyEpoch (absent
// for 0, as a real account that never rotated has it) and optional tombstone.
func putProfileAtEpoch(t *testing.T, c *Client, userID string, epoch uint64, deleted bool) {
	t.Helper()
	item := map[string]types.AttributeValue{"PK": s("USER#" + userID), "SK": s("PROFILE"), "Type": s("User")}
	if epoch > 0 {
		item["KeyEpoch"] = &types.AttributeValueMemberN{Value: strconv.FormatUint(epoch, 10)}
	}
	if deleted {
		item["DeletedAt"] = s("2026-01-01T00:00:00Z")
	}
	if _, err := c.ddb.PutItem(context.Background(), &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: item}); err != nil {
		t.Fatal(err)
	}
	// Several fixtures here use fixed user ids ("a1", "a2"), so a profile left
	// behind would change the outcome of every later test that uses them.
	t.Cleanup(func() {
		_, _ = c.ddb.DeleteItem(context.Background(), &dynamodb.DeleteItemInput{TableName: aws.String(c.table), Key: profileKey(userID)})
	})
}

func setWrapEpoch(t *testing.T, c *Client, groupID, userID string, epoch uint64) {
	t.Helper()
	if _, err := c.ddb.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:                 aws.String(c.table),
		Key:                       memberKey(groupID, userID),
		UpdateExpression:          aws.String("SET WrapEpoch = :e"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":e": &types.AttributeValueMemberN{Value: strconv.FormatUint(epoch, 10)}},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateGroupRecordsAndChecksTheCreatorsEpoch(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	creator := "creator-" + randomSuffix(t)
	putProfileAtEpoch(t, c, creator, 2, false)

	stale := testCreateGroupInput(t, "g-"+randomSuffix(t), creator)
	stale.CreatorKeyEpoch = 1
	if _, err := c.CreateGroup(ctx, stale); !errors.Is(err, ErrWrapEpochStale) {
		t.Fatalf("a wrap to a replaced key: %v, want ErrWrapEpochStale", err)
	}
	if itemExists(t, c, "GROUP#"+stale.GroupID, "META") || itemExists(t, c, "GROUP#"+stale.GroupID, "MEMBER#"+creator) {
		t.Fatal("a refused creation wrote rows")
	}

	ok := testCreateGroupInput(t, "g-"+randomSuffix(t), creator)
	ok.CreatorKeyEpoch = 2
	if _, err := c.CreateGroup(ctx, ok); err != nil {
		t.Fatal(err)
	}
	if m := readMember(t, c, ok.GroupID, creator); m.WrapEpoch != 2 {
		t.Errorf("creator WrapEpoch = %d, want 2", m.WrapEpoch)
	}

	gone := "gone-" + randomSuffix(t)
	putProfileAtEpoch(t, c, gone, 0, true)
	in := testCreateGroupInput(t, "g-"+randomSuffix(t), gone)
	if _, err := c.CreateGroup(ctx, in); !errors.Is(err, ErrCreatorDeleted) {
		t.Fatalf("a deleted creator: %v, want ErrCreatorDeleted", err)
	}
}

func TestCompleteInviteRecordsAndChecksTheInviteesEpoch(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	setup := func(t *testing.T, epoch uint64, deleted bool) (CompleteInviteInput, string) {
		inviteID := "inv-" + randomSuffix(t)
		groupID := "g-" + randomSuffix(t)
		inviter := "inviter-" + randomSuffix(t)
		invitee := "invitee-" + randomSuffix(t)
		putGroupMeta(t, c, groupID)
		putTestMember(t, c, groupID, inviter, "admin")
		putProfileAtEpoch(t, c, invitee, epoch, deleted)
		if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, groupID, inviter, time.Now().Add(7*24*time.Hour))); err != nil {
			t.Fatal(err)
		}
		if err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, invitee)); err != nil {
			t.Fatal(err)
		}
		return testCompleteInviteInput(inviteID, groupID, inviter, invitee), invitee
	}

	in, invitee := setup(t, 3, false)
	in.InviteeKeyEpoch = 2
	if err := c.CompleteInvite(ctx, in); !errors.Is(err, ErrWrapEpochStale) {
		t.Fatalf("a wrap to a replaced key: %v, want ErrWrapEpochStale", err)
	}
	if itemExists(t, c, "GROUP#"+in.GroupID, "MEMBER#"+invitee) {
		t.Fatal("a refused completion wrote a membership")
	}
	in.InviteeKeyEpoch = 3
	if err := c.CompleteInvite(ctx, in); err != nil {
		t.Fatal(err)
	}
	if m := readMember(t, c, in.GroupID, invitee); m.WrapEpoch != 3 {
		t.Errorf("invitee WrapEpoch = %d, want 3", m.WrapEpoch)
	}

	in, _ = setup(t, 0, true)
	if err := c.CompleteInvite(ctx, in); !errors.Is(err, ErrInviteeDeleted) {
		t.Fatalf("a deleted invitee: %v, want ErrInviteeDeleted", err)
	}
}

func TestTakeOverRecordsAndChecksTheCallersEpoch(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g, _, _ := leftRotatingGroup(t, c)
	putProfileAtEpoch(t, c, "a1", 2, false)

	stale := takeOverInput(g, "a1")
	stale.CallerKeyEpoch = 1
	if err := c.TakeOverLeaveRotation(ctx, stale); !errors.Is(err, ErrWrapEpochStale) {
		t.Fatalf("stale epoch: %v, want ErrWrapEpochStale", err)
	}
	if rot, _ := c.GetRotation(ctx, g); rot == nil || rot.StartedBy != "bob" || readMember(t, c, g, "a1").Generation != 0 {
		t.Fatal("a refused takeover changed something")
	}

	ok := takeOverInput(g, "a1")
	ok.CallerKeyEpoch = 2
	if err := c.TakeOverLeaveRotation(ctx, ok); err != nil {
		t.Fatal(err)
	}
	if m := readMember(t, c, g, "a1"); m.Generation != 1 || m.WrapEpoch != 2 {
		t.Errorf("caller = gen %d, WrapEpoch %d, want 1 and 2", m.Generation, m.WrapEpoch)
	}
}

func TestRemoveStartRecordsAndChecksTheRemoversEpoch(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "a1", "admin")
	putTestMember(t, c, g, "bob", "member")
	putProfileAtEpoch(t, c, "a1", 2, false)
	input := func(epoch uint64) RemoveMemberInput {
		return RemoveMemberInput{
			GroupID: g, SubjectUserID: "bob", SubjectRole: models.RoleMember, RemoverUserID: "a1",
			Rotation: &RemoveRotation{
				CurrentGeneration: 0,
				Link:              models.WrappedBlob{Nonce: []byte("N"), Ciphertext: []byte("C")},
				RemoverKeyEpoch:   epoch,
				RemoverWrappedKey: models.WrappedKey{EphemeralPub: []byte("E"), Nonce: []byte("N"), Ciphertext: []byte("NEW")},
				StartSignature:    []byte("sig"),
			},
		}
	}
	if err := c.RemoveMember(ctx, input(1)); !errors.Is(err, ErrWrapEpochStale) {
		t.Fatalf("stale epoch: %v, want ErrWrapEpochStale", err)
	}
	if !itemExists(t, c, "GROUP#"+g, "MEMBER#bob") {
		t.Fatal("a refused removal deleted the member")
	}
	if rot, _ := c.GetRotation(ctx, g); rot != nil {
		t.Fatal("a refused removal started a rotation")
	}
	if err := c.RemoveMember(ctx, input(2)); err != nil {
		t.Fatal(err)
	}
	if m := readMember(t, c, g, "a1"); m.Generation != 1 || m.WrapEpoch != 2 {
		t.Errorf("remover = gen %d, WrapEpoch %d, want 1 and 2", m.Generation, m.WrapEpoch)
	}
}

// startedRotation: admin a1 holds generation 1 (rotation 0 to 1 in progress),
// members a2 and m2 are behind at 0.
func startedRotation(t *testing.T, c *Client) string {
	t.Helper()
	g, _, _ := leftRotatingGroup(t, c)
	if err := c.TakeOverLeaveRotation(context.Background(), takeOverInput(g, "a1")); err != nil {
		t.Fatal(err)
	}
	return g
}

func wrapFor(user string, epoch uint64) MemberRewrap {
	return MemberRewrap{UserID: user, WrapEpoch: epoch, Wrapped: models.WrappedKey{EphemeralPub: []byte("e"), Nonce: []byte("n"), Ciphertext: []byte("W-" + user)}}
}

func TestRewrapNeverWrapsToADormantMember(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := startedRotation(t, c)
	// a2 rotated (KeyEpoch 1) and no admin has approved the change: their entry
	// is still wrapped to the key they replaced (WrapEpoch absent, 0).
	putProfileAtEpoch(t, c, "a2", 1, false)
	call := func(wraps ...MemberRewrap) error {
		return c.RewrapMembers(ctx, RewrapMembersInput{GroupID: g, CallerUserID: "a1", Generation: 1, Wraps: wraps})
	}

	// Wrapped to the key they hold now: dormant, refused.
	if err := call(wrapFor("a2", 1)); !errors.Is(err, ErrRewrapMemberDormant) {
		t.Fatalf("dormant member: %v, want ErrRewrapMemberDormant", err)
	}
	// Wrapped to the key they replaced: the wrap is stale, refused.
	if err := call(wrapFor("a2", 0)); !errors.Is(err, ErrWrapEpochStale) {
		t.Fatalf("stale epoch: %v, want ErrWrapEpochStale", err)
	}
	// A batch with one dormant member writes nothing for anyone in it.
	putProfileAtEpoch(t, c, "bob", 0, false)
	putTestMember(t, c, g, "m2", "member")
	if err := call(wrapFor("m2", 0), wrapFor("a2", 1)); !errors.Is(err, ErrRewrapMemberDormant) {
		t.Fatalf("mixed batch: %v, want ErrRewrapMemberDormant", err)
	}
	if m := readMember(t, c, g, "m2"); m.Generation != 0 {
		t.Fatal("a refused batch wrote the member that was fine")
	}
	if m := readMember(t, c, g, "a2"); m.Generation != 0 || m.WrapEpoch != 0 {
		t.Fatalf("a refused wrap changed the dormant member: %+v", m)
	}

	// An explicit approval (here: the member's entry brought current by other
	// means) makes them an ordinary recipient, and the epoch is stored.
	setWrapEpoch(t, c, g, "a2", 1)
	if err := call(wrapFor("a2", 1)); err != nil {
		t.Fatal(err)
	}
	if m := readMember(t, c, g, "a2"); m.Generation != 1 || m.WrapEpoch != 1 {
		t.Errorf("a2 = gen %d, WrapEpoch %d, want 1 and 1", m.Generation, m.WrapEpoch)
	}
}

func TestRewrapToARecipientWhoNeverRotated(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := startedRotation(t, c)
	// No PROFILE at all behaves as epoch 0, like an account that never rotated.
	if err := c.RewrapMembers(ctx, RewrapMembersInput{GroupID: g, CallerUserID: "a1", Generation: 1, Wraps: []MemberRewrap{wrapFor("a2", 0)}}); err != nil {
		t.Fatal(err)
	}
	if m := readMember(t, c, g, "a2"); m.Generation != 1 || m.WrapEpoch != 0 {
		t.Errorf("a2 = gen %d, WrapEpoch %d, want 1 and 0", m.Generation, m.WrapEpoch)
	}
}

func TestCompleteRotationIgnoresADormantMemberButNotAnOrdinaryOne(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := startedRotation(t, c)
	// a2 is behind at generation 0 and an ordinary member: completion waits.
	if err := c.CompleteRotation(ctx, g, "a1", 1); !errors.Is(err, ErrMembersBehind) {
		t.Fatalf("ordinary member behind: %v, want ErrMembersBehind", err)
	}
	// Once a2 has rotated and not been approved they are dormant: the rotation
	// does not wait for them, and does not wrap to them.
	putProfileAtEpoch(t, c, "a2", 1, false)
	if err := c.CompleteRotation(ctx, g, "a1", 1); err != nil {
		t.Fatalf("dormant member behind: %v, want completion", err)
	}
	if m := readMember(t, c, g, "a2"); m.Generation != 0 {
		t.Fatal("completing moved the dormant member")
	}
	// A rotated member whose entry was brought current (WrapEpoch == KeyEpoch)
	// and is still behind is an ordinary straggler again.
	g2 := startedRotation(t, c)
	putProfileAtEpoch(t, c, "a2", 1, false)
	setWrapEpoch(t, c, g2, "a2", 1)
	if err := c.CompleteRotation(ctx, g2, "a1", 1); !errors.Is(err, ErrMembersBehind) {
		t.Fatalf("approved member behind: %v, want ErrMembersBehind", err)
	}
}
