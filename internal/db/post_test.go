package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

const testPostKey = "POST#2026-10-28#00112233445566ff"

func postInput(g, author string) CreatePostInput {
	return CreatePostInput{
		GroupID: g, SortKey: testPostKey, AuthorUserID: author, Generation: 0,
		Nonce: []byte("nonce-nonce1"), Ciphertext: []byte("ciphertext"), Signature: []byte("signature"),
		ExpirationDays: 30, Now: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
	}
}

func readPost(t *testing.T, c *Client, g string) *models.Post {
	t.Helper()
	return readPostAt(t, c, g, testPostKey)
}

func readPostAt(t *testing.T, c *Client, g, sk string) *models.Post {
	t.Helper()
	out, err := c.ddb.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(c.table), ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{"PK": s("GROUP#" + g), "SK": s(sk)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Item == nil {
		return nil
	}
	var p models.Post
	if err := attributevalue.UnmarshalMap(out.Item, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

func TestCreatePostWritesTheItemAndTheTTL(t *testing.T) {
	c := testClient(t)
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "a1", "member")
	if err := c.CreatePost(context.Background(), postInput(g, "a1")); err != nil {
		t.Fatal(err)
	}
	p := readPost(t, c, g)
	if p == nil || p.AuthorUserID != "a1" || string(p.Ciphertext) != "ciphertext" {
		t.Fatalf("stored = %+v", p)
	}
	// 30 days from 2026-10-28 is 2026-11-27, rounded to the end of its UTC day.
	if want := time.Date(2026, 11, 27, 23, 59, 59, 0, time.UTC).Unix(); p.TTL != want {
		t.Errorf("TTL = %d, want %d", p.TTL, want)
	}

	// A group that never expires stores no TTL.
	in := postInput(g, "a1")
	in.SortKey, in.ExpirationDays = "POST#2026-10-28#aabbccddeeff0011", 0
	if err := c.CreatePost(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if p := readPostAt(t, c, g, in.SortKey); p.TTL != 0 {
		t.Errorf("never-expiring post has TTL %d", p.TTL)
	}
}

func TestCreatePostRetryMustMatchEveryField(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "a1", "member")
	putTestMember(t, c, g, "a2", "member")
	if err := c.CreatePost(ctx, postInput(g, "a1")); err != nil {
		t.Fatal(err)
	}
	if err := c.CreatePost(ctx, postInput(g, "a1")); err != nil {
		t.Fatalf("identical retry: %v", err)
	}
	for name, mutate := range map[string]func(*CreatePostInput){
		"author":     func(in *CreatePostInput) { in.AuthorUserID = "a2" },
		"generation": func(in *CreatePostInput) { in.Generation = 1 },
		"nonce":      func(in *CreatePostInput) { in.Nonce = []byte("other-nonce1") },
		"ciphertext": func(in *CreatePostInput) { in.Ciphertext = []byte("other-cipher") },
		"signature":  func(in *CreatePostInput) { in.Signature = []byte("other-sig") },
	} {
		in := postInput(g, "a1")
		mutate(&in)
		setMemberGeneration(t, c, g, "a1", 1)
		setMemberGeneration(t, c, g, "a2", 1)
		if err := c.CreatePost(ctx, in); !errors.Is(err, ErrPostExists) {
			t.Errorf("a retry differing in %s: %v, want ErrPostExists", name, err)
		}
	}
}

func TestCreatePostChecksTheAuthorsMembershipInTheSameTransaction(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "a1", "member")

	// Not a member.
	if err := c.CreatePost(ctx, postInput(g, "stranger")); !errors.Is(err, ErrPostMemberChanged) {
		t.Errorf("non-member: %v", err)
	}
	// A member whose entry is behind the post's generation.
	in := postInput(g, "a1")
	in.Generation = 1
	if err := c.CreatePost(ctx, in); !errors.Is(err, ErrPostMemberChanged) {
		t.Errorf("behind: %v", err)
	}
	// A member ahead of it can derive the older key through the chain.
	setMemberGeneration(t, c, g, "a1", 2)
	if err := c.CreatePost(ctx, in); err != nil {
		t.Errorf("ahead: %v", err)
	}
	// Dormant: the profile moved to epoch 1 and the entry is still wrapped to 0.
	putProfileAtEpoch(t, c, "a1", 1, false)
	in = postInput(g, "a1")
	in.SortKey, in.AuthorKeyEpoch = "POST#2026-10-28#1111111111111111", 1
	if err := c.CreatePost(ctx, in); !errors.Is(err, ErrPostMemberChanged) {
		t.Errorf("dormant: %v", err)
	}
	// Approved at epoch 1: fine. Then the handler's epoch is stale.
	setWrapEpoch(t, c, g, "a1", 1)
	if err := c.CreatePost(ctx, in); err != nil {
		t.Errorf("approved: %v", err)
	}
	in.SortKey, in.AuthorKeyEpoch = "POST#2026-10-28#2222222222222222", 0
	if err := c.CreatePost(ctx, in); !errors.Is(err, ErrPostMemberChanged) {
		t.Errorf("stale epoch against the entry: %v", err)
	}
	// A deleted account.
	putProfileAtEpoch(t, c, "a1", 1, true)
	in.SortKey, in.AuthorKeyEpoch = "POST#2026-10-28#3333333333333333", 1
	if err := c.CreatePost(ctx, in); !errors.Is(err, ErrWrapEpochStale) {
		t.Errorf("deleted profile: %v", err)
	}
	// A profile whose epoch moved after the handler read it.
	putProfileAtEpoch(t, c, "a1", 2, false)
	if err := c.CreatePost(ctx, in); !errors.Is(err, ErrWrapEpochStale) {
		t.Errorf("profile epoch moved: %v", err)
	}
}

func TestCreatePostPinsTheRotationMarkerInTheSameTransaction(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := startedRotation(t, c) // rotation 0 -> 1 running; a1 is at generation 1, a2 behind at 0
	marker, err := c.GetRotation(ctx, g)
	if err != nil || marker == nil {
		t.Fatalf("marker = %v, %v", marker, err)
	}
	in := postInput(g, "a1")
	in.Generation, in.MarkerPresent, in.MarkerGeneration = 0, true, marker.Generation

	// The rotation completes between the handler's read and the write: the
	// marker is gone, and the post sealed for the old generation must not land.
	if _, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(c.table), Key: rotationKey(g)}); err != nil {
		t.Fatal(err)
	}
	if err := c.CreatePost(ctx, in); !errors.Is(err, ErrPostMarkerChanged) {
		t.Fatalf("after the rotation completed: %v, want ErrPostMarkerChanged", err)
	}
	if readPost(t, c, g) != nil {
		t.Error("a post landed on the old generation after the rotation completed")
	}

	// The marker as the handler read it (gone) is what the write now sees.
	in.MarkerPresent, in.MarkerGeneration = false, 0
	if err := c.CreatePost(ctx, in); err != nil {
		t.Fatalf("with the marker absent as read: %v", err)
	}

	// A rotation that starts in the window is refused too: the settled
	// generation the handler used may be about to change.
	in.SortKey = "POST#2026-10-28#4444444444444444"
	putRotationMarker(t, c, g, 2)
	if err := c.CreatePost(ctx, in); !errors.Is(err, ErrPostMarkerChanged) {
		t.Fatalf("a rotation started in the window: %v, want ErrPostMarkerChanged", err)
	}
	// And one whose marker moved to another generation.
	in.MarkerPresent, in.MarkerGeneration = true, 1
	if err := c.CreatePost(ctx, in); !errors.Is(err, ErrPostMarkerChanged) {
		t.Fatalf("marker moved to another generation: %v, want ErrPostMarkerChanged", err)
	}
	in.MarkerGeneration = 2
	if err := c.CreatePost(ctx, in); err != nil {
		t.Fatalf("marker as read: %v", err)
	}
}

func TestPostAlreadyStoredIsTrueOnlyForTheSameBytes(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "a1", "member")
	in := postInput(g, "a1")
	if same, err := c.PostAlreadyStored(ctx, in); err != nil || same {
		t.Fatalf("before any write: %v, %v", same, err)
	}
	if err := c.CreatePost(ctx, in); err != nil {
		t.Fatal(err)
	}
	if same, err := c.PostAlreadyStored(ctx, in); err != nil || !same {
		t.Fatalf("same bytes: %v, %v", same, err)
	}
	other := in
	other.Ciphertext = []byte("other-cipher")
	if same, err := c.PostAlreadyStored(ctx, other); err != nil || same {
		t.Fatalf("other bytes: %v, %v", same, err)
	}
}

func putRotationMarker(t *testing.T, c *Client, g string, gen int64) {
	t.Helper()
	item := rotationKey(g)
	item["Type"] = s("Rotation")
	item["Generation"] = genAttr(gen)
	if _, err := c.ddb.PutItem(context.Background(), &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: item}); err != nil {
		t.Fatal(err)
	}
}
