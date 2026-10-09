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

// A leave must never hand the leaver the next key (#178 review, round 2): the
// leave writes only the marker, and an admin at the leaver's generation takes
// it over and mints the key.

// setOwnKey gives a test member a recognizable current wrapped key, so a test
// can see whether a leave or a takeover changed it.
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

// leftRotatingGroup: admins a1 and a2 (each with their own key at generation
// 0) and a leaver who has just left, starting the rotation.
func leftRotatingGroup(t *testing.T, c *Client) (g string, own1, own2 models.WrappedKey) {
	t.Helper()
	g = newLeaveGroup(t, c)
	putTestMember(t, c, g, "a1", "admin")
	putTestMember(t, c, g, "a2", "admin")
	putTestMember(t, c, g, "bob", "member")
	own1 = setOwnKey(t, c, g, "a1", 1)
	own2 = setOwnKey(t, c, g, "a2", 2)
	if _, err := c.LeaveGroup(context.Background(), g, "bob", nil, testLeaveRotation(0), true); err != nil {
		t.Fatal(err)
	}
	return g, own1, own2
}

func TestLeaveWritesOnlyTheMarker(t *testing.T) {
	c := testClient(t)
	g, own1, own2 := leftRotatingGroup(t, c)
	ctx := context.Background()

	rot, err := c.GetRotation(ctx, g)
	if err != nil || rot == nil {
		t.Fatalf("marker: %v %v", rot, err)
	}
	if rot.Generation != 1 || rot.StartedBy != "bob" || rot.RemovedUserID != "bob" || !bytes.Equal(rot.StartSignature, []byte("start-sig")) {
		t.Fatalf("marker = %+v", rot)
	}
	// No key material from the leaver is stored anywhere: no chain link, and no
	// admin's entry is touched.
	if itemExists(t, c, "GROUP#"+g, GenKeySortKey(0)) {
		t.Fatal("the leave wrote a chain link; only an admin may mint one")
	}
	for id, want := range map[string]models.WrappedKey{"a1": own1, "a2": own2} {
		m := readMember(t, c, g, id)
		if m.Generation != 0 || !bytes.Equal(m.WrappedGroupKey.Ciphertext, want.Ciphertext) {
			t.Fatalf("%s: the leave touched their entry: gen %d key %v", id, m.Generation, m.WrappedGroupKey)
		}
	}
}

func takeOverInput(g, caller string) TakeOverLeaveRotationInput {
	return TakeOverLeaveRotationInput{
		GroupID:           g,
		CallerUserID:      caller,
		LeaverUserID:      "bob",
		CurrentGeneration: 0,
		Link:              models.WrappedBlob{Nonce: []byte("N"), Ciphertext: []byte("C")},
		CallerWrappedKey:  models.WrappedKey{EphemeralPub: []byte("E"), Nonce: []byte("N"), Ciphertext: []byte("NEW")},
		StartSignature:    []byte("admin-start-sig"),
	}
}

func TestTakeOverLeaveRotationMintsTheAdminsKey(t *testing.T) {
	c := testClient(t)
	g, _, _ := leftRotatingGroup(t, c)
	ctx := context.Background()

	if err := c.TakeOverLeaveRotation(ctx, takeOverInput(g, "a1")); err != nil {
		t.Fatal(err)
	}
	rot, _ := c.GetRotation(ctx, g)
	if rot.Generation != 1 || rot.StartedBy != "a1" || rot.RemovedUserID != "bob" || !bytes.Equal(rot.StartSignature, []byte("admin-start-sig")) {
		t.Fatalf("marker = %+v", rot)
	}
	links, _, err := c.ListGenerationKeys(ctx, g, 0, 0, 10)
	if err != nil || len(links) != 1 || links[0].RemoverUserID != "a1" || links[0].RemovedUserID != "bob" ||
		!bytes.Equal(links[0].Wrapped.Ciphertext, []byte("C")) || !bytes.Equal(links[0].StartSignature, []byte("admin-start-sig")) {
		t.Fatalf("link = %+v, %v", links, err)
	}
	a1 := readMember(t, c, g, "a1")
	if a1.Generation != 1 || !bytes.Equal(a1.WrappedGroupKey.Ciphertext, []byte("NEW")) {
		t.Fatalf("caller = gen %d key %v", a1.Generation, a1.WrappedGroupKey)
	}
	if a2 := readMember(t, c, g, "a2"); a2.Generation != 0 {
		t.Fatal("the takeover moved another admin")
	}
	// A second admin racing for the same marker loses: it is the first admin's
	// now. They are re-wrapped like any member, and the rotation finishes.
	if err := c.TakeOverLeaveRotation(ctx, takeOverInput(g, "a2")); !errors.Is(err, ErrRotationNotActive) {
		t.Fatalf("second takeover: %v", err)
	}
	if err := c.RewrapMembers(ctx, RewrapMembersInput{GroupID: g, CallerUserID: "a1", Generation: 1, Wraps: []MemberRewrap{
		{UserID: "a2", Wrapped: models.WrappedKey{EphemeralPub: []byte("e"), Nonce: []byte("n"), Ciphertext: []byte("W2")}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := c.CompleteRotation(ctx, g, "a1", 1); err != nil {
		t.Fatal(err)
	}
}

func TestTakeOverLeaveRotationRefusals(t *testing.T) {
	ctx := context.Background()
	unchanged := func(t *testing.T, c *Client, g, startedBy string) {
		t.Helper()
		rot, _ := c.GetRotation(ctx, g)
		if rot == nil || rot.StartedBy != startedBy || readMember(t, c, g, "a1").Generation != 0 {
			t.Fatalf("a refused takeover changed something: %+v", rot)
		}
	}

	t.Run("no rotation", func(t *testing.T) {
		c := testClient(t)
		g := newLeaveGroup(t, c)
		putTestMember(t, c, g, "a1", "admin")
		if err := c.TakeOverLeaveRotation(ctx, takeOverInput(g, "a1")); !errors.Is(err, ErrRotationNotActive) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("an admin's rotation is not takeable", func(t *testing.T) {
		c := testClient(t)
		g := newLeaveGroup(t, c)
		putTestMember(t, c, g, "a1", "admin")
		// No link exists, so only the MARKER's own condition (an admin started
		// it) can refuse this.
		if _, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: map[string]types.AttributeValue{
			"PK": s("GROUP#" + g), "SK": s(RotationSortKey), "Generation": genAttr(1), "StartedBy": s("a2"), "RemovedUserID": s("bob"),
		}}); err != nil {
			t.Fatal(err)
		}
		if err := c.TakeOverLeaveRotation(ctx, takeOverInput(g, "a1")); !errors.Is(err, ErrRotationNotActive) {
			t.Fatalf("%v", err)
		}
		unchanged(t, c, g, "a2")
		if itemExists(t, c, "GROUP#"+g, GenKeySortKey(0)) {
			t.Fatal("a refused takeover wrote a link")
		}
	})
	t.Run("a chain link already exists", func(t *testing.T) {
		c := testClient(t)
		g, _, _ := leftRotatingGroup(t, c)
		// The leaver's marker is intact, so only the link's own condition (a
		// generation is minted once) can refuse.
		if _, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: map[string]types.AttributeValue{
			"PK": s("GROUP#" + g), "SK": s(GenKeySortKey(0)), "RemoverUserID": s("x"), "RemovedUserID": s("x"),
		}}); err != nil {
			t.Fatal(err)
		}
		if err := c.TakeOverLeaveRotation(ctx, takeOverInput(g, "a1")); !errors.Is(err, ErrRotationNotActive) {
			t.Fatalf("%v", err)
		}
		unchanged(t, c, g, "bob")
	})
	t.Run("a different leaver", func(t *testing.T) {
		c := testClient(t)
		g, _, _ := leftRotatingGroup(t, c)
		in := takeOverInput(g, "a1")
		in.LeaverUserID = "someone-else"
		if err := c.TakeOverLeaveRotation(ctx, in); !errors.Is(err, ErrRotationNotActive) {
			t.Fatalf("%v", err)
		}
		unchanged(t, c, g, "bob")
	})
	t.Run("a marker whose starter is not the removed member", func(t *testing.T) {
		c := testClient(t)
		g := newLeaveGroup(t, c)
		putTestMember(t, c, g, "a1", "admin")
		// bob "started" it but it names carl as removed: not a leave. Only the
		// marker's RemovedUserID condition can refuse this (bob is the leaver
		// the caller names, and the generation matches).
		if _, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: map[string]types.AttributeValue{
			"PK": s("GROUP#" + g), "SK": s(RotationSortKey), "Generation": genAttr(1), "StartedBy": s("bob"), "RemovedUserID": s("carl"),
		}}); err != nil {
			t.Fatal(err)
		}
		if err := c.TakeOverLeaveRotation(ctx, takeOverInput(g, "a1")); !errors.Is(err, ErrRotationNotActive) {
			t.Fatalf("%v", err)
		}
		unchanged(t, c, g, "bob")
	})
	t.Run("caller's entry is at another generation than the one they minted from", func(t *testing.T) {
		c := testClient(t)
		g, _, _ := leftRotatingGroup(t, c)
		// a1 is already ahead (generation 1), so only the CALLER's own
		// generation condition can refuse: the marker is at 1 and the link is free.
		if _, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName: aws.String(c.table), Key: memberKey(g, "a1"),
			UpdateExpression:          aws.String("SET Generation = :g"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":g": genAttr(1)},
		}); err != nil {
			t.Fatal(err)
		}
		if err := c.TakeOverLeaveRotation(ctx, takeOverInput(g, "a1")); !errors.Is(err, ErrRewrapCallerBehind) {
			t.Fatalf("%v", err)
		}
		if rot, _ := c.GetRotation(ctx, g); rot.StartedBy != "bob" {
			t.Fatal("a refused takeover replaced the marker")
		}
		if itemExists(t, c, "GROUP#"+g, GenKeySortKey(0)) {
			t.Fatal("a refused takeover wrote a link")
		}
	})
	t.Run("caller not an admin, or not at the generation", func(t *testing.T) {
		c := testClient(t)
		g, _, _ := leftRotatingGroup(t, c)
		putTestMember(t, c, g, "m1", "member")
		if err := c.TakeOverLeaveRotation(ctx, takeOverInput(g, "m1")); !errors.Is(err, ErrRewrapCallerBehind) {
			t.Fatalf("member: %v", err)
		}
		in := takeOverInput(g, "a1")
		in.CurrentGeneration = 3
		if err := c.TakeOverLeaveRotation(ctx, in); !errors.Is(err, ErrRotationNotActive) {
			t.Fatalf("wrong generation: %v", err)
		}
		unchanged(t, c, g, "bob")
		if itemExists(t, c, "GROUP#"+g, GenKeySortKey(0)) {
			t.Fatal("a refused takeover wrote a link")
		}
	})
}
