package db

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// A leave must never replace the key an admin already holds with bytes the
// leaver chose (#178 review): the new key lands beside the entry as pending,
// is adopted only on the admin's say-so, and an admin can replace a rotation
// whose key no one could verify.

// setOwnKey gives a test member a recognizable current wrapped key, so a test
// can see whether a leave or an adoption changed it.
func setOwnKey(t *testing.T, c *Client, groupID, userID string, marker byte) models.WrappedKey {
	t.Helper()
	k := models.WrappedKey{EphemeralPub: []byte{marker, 'e'}, Nonce: []byte{marker, 'n'}, Ciphertext: []byte{marker, 'c'}}
	av, err := attributevalue.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ddb.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:                 aws.String(c.table),
		Key:                       memberKey(groupID, userID),
		UpdateExpression:          aws.String("SET WrappedGroupKey = :k"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":k": av},
	}); err != nil {
		t.Fatal(err)
	}
	return k
}

func readMember(t *testing.T, c *Client, groupID, userID string) *models.Membership {
	t.Helper()
	m, err := c.GetMembership(context.Background(), groupID, userID)
	if err != nil || m == nil {
		t.Fatalf("get member %s: %v", userID, err)
	}
	return m
}

// leftRotatingGroup: admins a1 and a2 (both holders, each with their own key
// at generation 0) and a leaver who has just left, starting the rotation.
func leftRotatingGroup(t *testing.T, c *Client) (g string, own1, own2 models.WrappedKey) {
	t.Helper()
	g = newLeaveGroup(t, c)
	putTestMember(t, c, g, "a1", "admin")
	putTestMember(t, c, g, "a2", "admin")
	putTestMember(t, c, g, "bob", "member")
	own1 = setOwnKey(t, c, g, "a1", 1)
	own2 = setOwnKey(t, c, g, "a2", 2)
	if _, err := c.LeaveGroup(context.Background(), g, "bob", nil, testLeaveRotation(0, "a1", "a2"), true); err != nil {
		t.Fatal(err)
	}
	return g, own1, own2
}

func TestLeaveLeavesTheHoldersOwnKeyAlone(t *testing.T) {
	c := testClient(t)
	g, own1, own2 := leftRotatingGroup(t, c)
	for id, want := range map[string]models.WrappedKey{"a1": own1, "a2": own2} {
		m := readMember(t, c, g, id)
		if m.Generation != 0 || !bytes.Equal(m.WrappedGroupKey.Ciphertext, want.Ciphertext) {
			t.Fatalf("%s: the leave overwrote their own entry: gen %d key %v", id, m.Generation, m.WrappedGroupKey)
		}
		if m.PendingWrappedKey == nil {
			t.Fatalf("%s: no pending key", id)
		}
	}
}

func TestAdoptPendingKeyMovesTheHolderAndCounts(t *testing.T) {
	c := testClient(t)
	g, _, _ := leftRotatingGroup(t, c)
	ctx := context.Background()
	pending := readMember(t, c, g, "a1").PendingWrappedKey

	if err := c.AdoptPendingKey(ctx, g, "a1", 1); err != nil {
		t.Fatal(err)
	}
	m := readMember(t, c, g, "a1")
	if m.Generation != 1 || m.PendingWrappedKey != nil || !bytes.Equal(m.WrappedGroupKey.Ciphertext, pending.Ciphertext) {
		t.Fatalf("after adopt: gen %d, pending %v, key %v", m.Generation, m.PendingWrappedKey, m.WrappedGroupKey)
	}
	rot, _ := c.GetRotation(ctx, g)
	if rot.Adopted != 1 {
		t.Fatalf("Adopted = %d, want 1", rot.Adopted)
	}
	// The other holder is untouched until they adopt.
	if m2 := readMember(t, c, g, "a2"); m2.Generation != 0 || m2.PendingWrappedKey == nil {
		t.Fatal("adopting moved another holder")
	}
	if err := c.AdoptPendingKey(ctx, g, "a2", 1); err != nil {
		t.Fatal(err)
	}
	if rot, _ = c.GetRotation(ctx, g); rot.Adopted != 2 {
		t.Fatalf("Adopted = %d, want 2", rot.Adopted)
	}
}

func TestAdoptPendingKeyRefusals(t *testing.T) {
	c := testClient(t)
	g, _, _ := leftRotatingGroup(t, c)
	ctx := context.Background()
	putTestMember(t, c, g, "a3", "admin") // an admin nobody named: no pending key
	putTestMember(t, c, g, "m1", "member")

	adopted := func() int64 { r, _ := c.GetRotation(ctx, g); return r.Adopted }
	for name, tc := range map[string]struct {
		user string
		gen  int64
		want error
	}{
		"not a holder":         {"a3", 1, ErrNoPendingKey},
		"not an admin":         {"m1", 1, ErrNoPendingKey},
		"not a member":         {"ghost", 1, ErrNoPendingKey},
		"wrong generation":     {"a1", 2, ErrRotationNotActive},
		"generation not ahead": {"a1", 0, ErrRotationNotActive},
	} {
		if err := c.AdoptPendingKey(ctx, g, tc.user, tc.gen); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	// A refused adoption counts for nothing: the count and the move are one commit.
	if adopted() != 0 {
		t.Fatalf("a refused adoption bumped the count to %d", adopted())
	}
	if readMember(t, c, g, "a1").Generation != 0 {
		t.Fatal("a refused adoption moved a holder")
	}
	// A demoted holder cannot adopt.
	if _, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table), Key: memberKey(g, "a1"),
		UpdateExpression:          aws.String("SET #r = :m"),
		ExpressionAttributeNames:  map[string]string{"#r": "Role"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":m": &types.AttributeValueMemberS{Value: "member"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.AdoptPendingKey(ctx, g, "a1", 1); !errors.Is(err, ErrNoPendingKey) {
		t.Fatalf("demoted holder: %v", err)
	}
	// No rotation at all.
	g2 := newLeaveGroup(t, c)
	putTestMember(t, c, g2, "a1", "admin")
	if err := c.AdoptPendingKey(ctx, g2, "a1", 1); !errors.Is(err, ErrRotationNotActive) {
		t.Fatalf("no marker: %v", err)
	}
}

// A removal's marker has a remover that is not the removed member; it never
// carries pending keys, and adopting against it is refused outright.
func TestAdoptPendingKeyRefusesARemovalsRotation(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "a1", "admin")
	putTestMember(t, c, g, "a2", "admin")
	ctx := context.Background()
	// An admin's own rotation (StartedBy a2, removing bob), plus a stray pending
	// key on a1 (a hostile server's doing).
	if _, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: map[string]types.AttributeValue{
		"PK": s("GROUP#" + g), "SK": s(RotationSortKey), "Generation": genAttr(1),
		"StartedBy": s("a2"), "RemovedUserID": s("bob"),
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table), Key: memberKey(g, "a1"),
		UpdateExpression: aws.String("SET PendingWrappedKey = :p"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": &types.AttributeValueMemberM{Value: map[string]types.AttributeValue{
			"EphemeralPub": &types.AttributeValueMemberB{Value: []byte("e")},
		}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.AdoptPendingKey(ctx, g, "a1", 1); !errors.Is(err, ErrRotationNotActive) {
		t.Fatalf("adopt against a removal's marker: %v", err)
	}
	if readMember(t, c, g, "a1").Generation != 0 {
		t.Fatal("moved onto an admin's rotation by a stray pending key")
	}
}

func restartInput(g, caller string) RestartLeaveRotationInput {
	return RestartLeaveRotationInput{
		GroupID:           g,
		CallerUserID:      caller,
		LeaverUserID:      "bob",
		CurrentGeneration: 0,
		Link:              models.WrappedBlob{Nonce: []byte("N"), Ciphertext: []byte("C")},
		CallerWrappedKey:  models.WrappedKey{EphemeralPub: []byte("E"), Nonce: []byte("N"), Ciphertext: []byte("NEW")},
		StartSignature:    []byte("admin-start-sig"),
	}
}

func TestRestartLeaveRotationReplacesAUnverifiableRotation(t *testing.T) {
	c := testClient(t)
	g, _, _ := leftRotatingGroup(t, c)
	ctx := context.Background()

	if err := c.RestartLeaveRotation(ctx, restartInput(g, "a1")); err != nil {
		t.Fatal(err)
	}
	rot, _ := c.GetRotation(ctx, g)
	if rot.Generation != 1 || rot.StartedBy != "a1" || rot.RemovedUserID != "bob" || !bytes.Equal(rot.StartSignature, []byte("admin-start-sig")) || rot.Adopted != 0 {
		t.Fatalf("marker = %+v", rot)
	}
	links, _, err := c.ListGenerationKeys(ctx, g, 0, 0, 10)
	if err != nil || len(links) != 1 || links[0].RemoverUserID != "a1" || links[0].RemovedUserID != "bob" ||
		!bytes.Equal(links[0].Wrapped.Ciphertext, []byte("C")) || !bytes.Equal(links[0].StartSignature, []byte("admin-start-sig")) {
		t.Fatalf("link = %+v, %v", links, err)
	}
	a1 := readMember(t, c, g, "a1")
	if a1.Generation != 1 || a1.PendingWrappedKey != nil || !bytes.Equal(a1.WrappedGroupKey.Ciphertext, []byte("NEW")) {
		t.Fatalf("caller = gen %d pending %v key %v", a1.Generation, a1.PendingWrappedKey, a1.WrappedGroupKey)
	}
	// The other holder still has the leaver's stale key waiting, but it can no
	// longer be adopted: the marker is the admin's now.
	if err := c.AdoptPendingKey(ctx, g, "a2", 1); !errors.Is(err, ErrRotationNotActive) {
		t.Fatalf("adopting the replaced rotation's key: %v", err)
	}
	// ...and the ordinary re-wrap moves them and clears it, so the rotation
	// finishes with nothing stale left behind.
	if err := c.RewrapMembers(ctx, RewrapMembersInput{GroupID: g, CallerUserID: "a1", Generation: 1, Wraps: []MemberRewrap{
		{UserID: "a2", Wrapped: models.WrappedKey{EphemeralPub: []byte("e"), Nonce: []byte("n"), Ciphertext: []byte("W2")}},
	}}); err != nil {
		t.Fatal(err)
	}
	a2 := readMember(t, c, g, "a2")
	if a2.Generation != 1 || a2.PendingWrappedKey != nil || !bytes.Equal(a2.WrappedGroupKey.Ciphertext, []byte("W2")) {
		t.Fatalf("a2 after re-wrap: gen %d pending %v key %v", a2.Generation, a2.PendingWrappedKey, a2.WrappedGroupKey)
	}
	if err := c.CompleteRotation(ctx, g, "a1", 1); err != nil {
		t.Fatal(err)
	}
}

func TestRestartLeaveRotationRefusals(t *testing.T) {
	ctx := context.Background()
	unchanged := func(t *testing.T, c *Client, g string) {
		t.Helper()
		rot, _ := c.GetRotation(ctx, g)
		if rot == nil || rot.StartedBy != "bob" || readMember(t, c, g, "a1").Generation != 0 {
			t.Fatalf("a refused restart changed something: %+v", rot)
		}
	}

	t.Run("after an admin adopted", func(t *testing.T) {
		c := testClient(t)
		g, _, _ := leftRotatingGroup(t, c)
		if err := c.AdoptPendingKey(ctx, g, "a2", 1); err != nil {
			t.Fatal(err)
		}
		if err := c.RestartLeaveRotation(ctx, restartInput(g, "a1")); !errors.Is(err, ErrRotationAdopted) {
			t.Fatalf("%v", err)
		}
		unchanged(t, c, g)
	})
	t.Run("no rotation", func(t *testing.T) {
		c := testClient(t)
		g := newLeaveGroup(t, c)
		putTestMember(t, c, g, "a1", "admin")
		if err := c.RestartLeaveRotation(ctx, restartInput(g, "a1")); !errors.Is(err, ErrRotationNotActive) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("an admin's rotation is not replaceable", func(t *testing.T) {
		c := testClient(t)
		g := newLeaveGroup(t, c)
		putTestMember(t, c, g, "a1", "admin")
		if _, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: map[string]types.AttributeValue{
			"PK": s("GROUP#" + g), "SK": s(RotationSortKey), "Generation": genAttr(1), "StartedBy": s("a2"), "RemovedUserID": s("bob"),
		}}); err != nil {
			t.Fatal(err)
		}
		if err := c.RestartLeaveRotation(ctx, restartInput(g, "a1")); !errors.Is(err, ErrRotationNotActive) {
			t.Fatalf("%v", err)
		}
		if rot, _ := c.GetRotation(ctx, g); rot.StartedBy != "a2" {
			t.Fatal("replaced another admin's rotation")
		}
	})
	t.Run("a different leaver", func(t *testing.T) {
		c := testClient(t)
		g, _, _ := leftRotatingGroup(t, c)
		in := restartInput(g, "a1")
		in.LeaverUserID = "someone-else"
		if err := c.RestartLeaveRotation(ctx, in); !errors.Is(err, ErrRotationNotActive) {
			t.Fatalf("%v", err)
		}
		unchanged(t, c, g)
	})
	t.Run("caller not at the generation, or not an admin", func(t *testing.T) {
		c := testClient(t)
		g, _, _ := leftRotatingGroup(t, c)
		putTestMember(t, c, g, "m1", "member")
		if err := c.RestartLeaveRotation(ctx, restartInput(g, "m1")); !errors.Is(err, ErrRewrapCallerBehind) {
			t.Fatalf("member: %v", err)
		}
		in := restartInput(g, "a1")
		in.CurrentGeneration = 3
		if err := c.RestartLeaveRotation(ctx, in); !errors.Is(err, ErrRotationNotActive) {
			t.Fatalf("wrong generation: %v", err)
		}
		unchanged(t, c, g)
		// The link is still the leaver's.
		if links, _, _ := c.ListGenerationKeys(ctx, g, 0, 0, 10); len(links) != 1 || links[0].RemoverUserID != "bob" {
			t.Fatalf("a refused restart touched the link: %+v", links)
		}
	})
}
