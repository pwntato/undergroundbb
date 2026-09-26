package db

import (
	"context"
	"errors"
	"testing"

	"github.com/pwntato/undergroundbb/internal/models"
)

func testCreateGroupInput(t *testing.T, groupID, creatorUserID string) CreateGroupInput {
	t.Helper()
	suffix := randomSuffix(t)
	daySuffix := "2026-09-25#" + suffix
	return CreateGroupInput{
		GroupID: groupID,

		CreatorUserID:           creatorUserID,
		CreatorSigningPublicKey: make([]byte, 32),
		TrustAnchorSignature:    []byte("trust-anchor-signature"),

		Visibility: models.VisibilityPrivate,
		NameCiphertext: &models.WrappedBlob{
			Nonce:      make([]byte, 12),
			Ciphertext: []byte("name-ciphertext"),
		},
		DescriptionCiphertext: &models.WrappedBlob{
			Nonce:      make([]byte, 12),
			Ciphertext: []byte("description-ciphertext"),
		},

		RevocationMode: models.RevocationRotating,
		ExpirationDays: 30,

		GenerationKeyWrapped: models.WrappedKey{
			EphemeralPub: make([]byte, 32),
			Nonce:        make([]byte, 12),
			Ciphertext:   []byte("wrapped-generation-key"),
		},

		RootGrantSortKey:   "GRANT#" + creatorUserID + "#" + daySuffix,
		RootGrantSignature: []byte("root-grant-signature"),
	}
}

func TestCreateGroupWritesAllThreeItems(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	groupID := "test-group-" + randomSuffix(t)
	creatorUserID := "test-creator-" + randomSuffix(t)
	in := testCreateGroupInput(t, groupID, creatorUserID)

	if err := c.CreateGroup(ctx, in); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	metaOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "GROUP#"+groupID, "META"))
	if err != nil {
		t.Fatalf("GetItem META: %v", err)
	}
	if metaOut.Item == nil {
		t.Fatal("META item was not written")
	}
	var group models.Group
	if err := unmarshalItem(metaOut.Item, &group); err != nil {
		t.Fatalf("unmarshal META: %v", err)
	}
	if group.CreatorUserID != creatorUserID {
		t.Errorf("META CreatorUserID = %q, want %q", group.CreatorUserID, creatorUserID)
	}
	if group.Visibility != models.VisibilityPrivate {
		t.Errorf("META Visibility = %q, want %q", group.Visibility, models.VisibilityPrivate)
	}
	if group.RevocationMode != models.RevocationRotating {
		t.Errorf("META RevocationMode = %q, want %q", group.RevocationMode, models.RevocationRotating)
	}
	if group.GSI1PK != "" || group.GSI1SK != "" {
		t.Errorf("private group META has GSI1PK=%q GSI1SK=%q, want both empty -- see DESIGN.md, private groups write no directory entry", group.GSI1PK, group.GSI1SK)
	}
	if len(group.GenerationKeyWrapped.EphemeralPub) != 32 {
		t.Errorf("META GenerationKeyWrapped.EphemeralPub len = %d, want 32 -- an ECIES wrap without its ephemeral public key can never be unwrapped again", len(group.GenerationKeyWrapped.EphemeralPub))
	}

	memberOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "GROUP#"+groupID, "MEMBER#"+creatorUserID))
	if err != nil {
		t.Fatalf("GetItem MEMBER#: %v", err)
	}
	if memberOut.Item == nil {
		t.Fatal("MEMBER# item was not written")
	}
	var membership models.Membership
	if err := unmarshalItem(memberOut.Item, &membership); err != nil {
		t.Fatalf("unmarshal MEMBER#: %v", err)
	}
	if membership.Role != models.RoleAdmin {
		t.Errorf("creator's Role = %q, want %q", membership.Role, models.RoleAdmin)
	}
	if membership.Generation != 0 {
		t.Errorf("creator's Generation = %d, want 0", membership.Generation)
	}
	if membership.GSI1PK != "USER#"+creatorUserID {
		t.Errorf("MEMBER# GSI1PK = %q, want %q (see DESIGN.md's 'list my groups' access pattern)", membership.GSI1PK, "USER#"+creatorUserID)
	}
	if membership.GSI1SK != "GROUP#"+groupID {
		t.Errorf("MEMBER# GSI1SK = %q, want %q", membership.GSI1SK, "GROUP#"+groupID)
	}
	if len(membership.WrappedGroupKey.EphemeralPub) != 32 {
		t.Errorf("MEMBER# WrappedGroupKey.EphemeralPub len = %d, want 32", len(membership.WrappedGroupKey.EphemeralPub))
	}

	grantOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "GROUP#"+groupID, in.RootGrantSortKey))
	if err != nil {
		t.Fatalf("GetItem GRANT#: %v", err)
	}
	if grantOut.Item == nil {
		t.Fatal("GRANT# item was not written")
	}
	var grant models.RoleGrant
	if err := unmarshalItem(grantOut.Item, &grant); err != nil {
		t.Fatalf("unmarshal GRANT#: %v", err)
	}
	if grant.SubjectUserID != creatorUserID {
		t.Errorf("root grant SubjectUserID = %q, want %q", grant.SubjectUserID, creatorUserID)
	}
	if grant.GrantorUserID != creatorUserID {
		t.Errorf("root grant GrantorUserID = %q, want %q (root grant must be self-signed)", grant.GrantorUserID, creatorUserID)
	}
	if grant.GrantedRole != models.RoleAdmin {
		t.Errorf("root grant GrantedRole = %q, want %q", grant.GrantedRole, models.RoleAdmin)
	}
}

// TestCreateGroupPublicWritesDirectoryEntry covers the sparse-GSI1 behavior
// DESIGN.md's "Visibility" section describes: only a public group's META
// item participates in the PUBLIC#<shard> directory index.
func TestCreateGroupPublicWritesDirectoryEntry(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	groupID := "test-group-" + randomSuffix(t)
	creatorUserID := "test-creator-" + randomSuffix(t)
	in := testCreateGroupInput(t, groupID, creatorUserID)
	in.Visibility = models.VisibilityPublic
	in.NameCiphertext = nil
	in.DescriptionCiphertext = nil
	in.NamePlaintext = "Book Club"
	in.DescriptionPlaintext = "We read books"

	if err := c.CreateGroup(ctx, in); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	metaOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "GROUP#"+groupID, "META"))
	if err != nil {
		t.Fatalf("GetItem META: %v", err)
	}
	var group models.Group
	if err := unmarshalItem(metaOut.Item, &group); err != nil {
		t.Fatalf("unmarshal META: %v", err)
	}
	if group.GSI1PK != "PUBLIC#0" {
		t.Errorf("public group META GSI1PK = %q, want %q", group.GSI1PK, "PUBLIC#0")
	}
	wantGSI1SK := "NAME#Book Club#" + groupID
	if group.GSI1SK != wantGSI1SK {
		t.Errorf("public group META GSI1SK = %q, want %q", group.GSI1SK, wantGSI1SK)
	}
	if group.NamePlaintext != "Book Club" {
		t.Errorf("META NamePlaintext = %q, want %q", group.NamePlaintext, "Book Club")
	}
}

// TestCreateGroupIDCollisionFails covers ErrGroupIDTaken: a second
// CreateGroup call reusing the same GroupID must not silently overwrite the
// first group's META item.
func TestCreateGroupIDCollisionFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	groupID := "test-group-" + randomSuffix(t)
	first := testCreateGroupInput(t, groupID, "test-creator-"+randomSuffix(t))
	if err := c.CreateGroup(ctx, first); err != nil {
		t.Fatalf("CreateGroup (first): %v", err)
	}

	second := testCreateGroupInput(t, groupID, "test-creator-"+randomSuffix(t))
	err := c.CreateGroup(ctx, second)
	if !errors.Is(err, ErrGroupIDTaken) {
		t.Fatalf("CreateGroup (colliding id): err = %v, want ErrGroupIDTaken", err)
	}

	// The first group's own MEMBER#/GRANT# items must be untouched -- a
	// failed transaction must not have partially applied the second
	// creator's membership or grant under the first group's still-existing
	// META.
	memberOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "GROUP#"+groupID, "MEMBER#"+first.CreatorUserID))
	if err != nil {
		t.Fatalf("GetItem MEMBER#: %v", err)
	}
	if memberOut.Item == nil {
		t.Fatal("original creator's MEMBER# item was lost after a failed colliding CreateGroup")
	}
	collidingMemberOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "GROUP#"+groupID, "MEMBER#"+second.CreatorUserID))
	if err != nil {
		t.Fatalf("GetItem MEMBER# (colliding): %v", err)
	}
	if collidingMemberOut.Item != nil {
		t.Fatal("colliding CreateGroup's MEMBER# item was written despite the transaction failing")
	}
}
