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

	gotRootGrantSortKey, err := c.CreateGroup(ctx, in)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if gotRootGrantSortKey != in.RootGrantSortKey {
		t.Errorf("CreateGroup returned RootGrantSortKey = %q, want %q", gotRootGrantSortKey, in.RootGrantSortKey)
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
	if group.RootGrantSortKey != in.RootGrantSortKey {
		t.Errorf("META RootGrantSortKey = %q, want %q", group.RootGrantSortKey, in.RootGrantSortKey)
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
	// PR #142 review: META does not carry a wrapped group key -- only the
	// creator's own MEMBER# item does (checked below). Verified by reading
	// the raw item map rather than the models.Group struct, since a struct
	// with no such field would trivially "pass" a struct-level check even
	// if a stray attribute were still being written.
	if _, ok := metaOut.Item["GenerationKeyWrapped"]; ok {
		t.Error("META has a GenerationKeyWrapped attribute, want none -- the creator's wrapped key belongs on their own MEMBER# item only")
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

	if _, err := c.CreateGroup(ctx, in); err != nil {
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
	if _, err := c.CreateGroup(ctx, first); err != nil {
		t.Fatalf("CreateGroup (first): %v", err)
	}

	second := testCreateGroupInput(t, groupID, "test-creator-"+randomSuffix(t))
	_, err := c.CreateGroup(ctx, second)
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

// TestCreateGroupRetrySucceeds covers isOwnGroupCreation: a lost-response
// retry must return success rather than ErrGroupIDTaken -- see CreateGroup's
// own doc comment on why this is checked on every META conflict.
//
// The retry here does NOT resend byte-for-byte identical input -- PR #142
// round 2 review caught that the real client never does either.
// TrustAnchorSignature is deterministic (covers only creator+key+gid, no
// grant-specific data) so it matches across attempts, but RootGrantSortKey
// and RootGrantSignature are freshly re-signed every time
// (CreateGroupScreen -> runCreateGroup -> signGroupCreation ->
// generateGrantSortKey), so a round-1-style test that resends the exact
// same CreateGroupInput would never have caught the bug: the response must
// echo the FIRST attempt's RootGrantSortKey, the address something was
// actually written under, not the retry's own.
func TestCreateGroupRetrySucceeds(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	groupID := "test-group-" + randomSuffix(t)
	first := testCreateGroupInput(t, groupID, "test-creator-"+randomSuffix(t))
	gotFirst, err := c.CreateGroup(ctx, first)
	if err != nil {
		t.Fatalf("CreateGroup (first): %v", err)
	}
	if gotFirst != first.RootGrantSortKey {
		t.Fatalf("CreateGroup (first) returned %q, want %q", gotFirst, first.RootGrantSortKey)
	}

	// Resend as the real client does on a resume: same GroupID,
	// CreatorUserID, CreatorSigningPublicKey and TrustAnchorSignature (all
	// deterministic over the cached form/groupId/keys), but a FRESH
	// RootGrantSortKey/RootGrantSignature -- signGroupCreation is called
	// again on every retry attempt.
	retry := first
	retry.RootGrantSortKey = "GRANT#" + first.CreatorUserID + "#2026-09-26#" + randomSuffix(t)
	retry.RootGrantSignature = []byte("a-freshly-re-signed-root-grant-signature")

	gotRetry, err := c.CreateGroup(ctx, retry)
	if err != nil {
		t.Fatalf("CreateGroup (retry): err = %v, want nil (identical-creator resend should succeed)", err)
	}
	if gotRetry != first.RootGrantSortKey {
		t.Errorf("CreateGroup (retry) returned %q, want %q (the FIRST attempt's stored key, not the retry's own fresh one %q)", gotRetry, first.RootGrantSortKey, retry.RootGrantSortKey)
	}

	// The retry's own freshly-signed GRANT# row must never have been
	// written -- isOwnGroupCreation short-circuits before CreateGroup's
	// transaction runs at all on a retry.
	retryGrantOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "GROUP#"+groupID, retry.RootGrantSortKey))
	if err != nil {
		t.Fatalf("GetItem retry's GRANT#: %v", err)
	}
	if retryGrantOut.Item != nil {
		t.Error("a GRANT# row exists at the retry's own freshly-signed sort key -- it should never have been written")
	}
}

// TestCreateGroupRetryWithDivergedSignatureFails covers isOwnGroupCreation's
// second check: the same GroupID and CreatorUserID, but a
// TrustAnchorSignature that does not match what was actually stored, must
// fail loudly rather than silently report success for material that was
// never written -- see that function's own doc comment.
func TestCreateGroupRetryWithDivergedSignatureFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	groupID := "test-group-" + randomSuffix(t)
	creatorUserID := "test-creator-" + randomSuffix(t)
	first := testCreateGroupInput(t, groupID, creatorUserID)
	if _, err := c.CreateGroup(ctx, first); err != nil {
		t.Fatalf("CreateGroup (first): %v", err)
	}

	diverged := testCreateGroupInput(t, groupID, creatorUserID)
	diverged.TrustAnchorSignature = []byte("a-different-trust-anchor-signature")
	_, err := c.CreateGroup(ctx, diverged)
	if !errors.Is(err, ErrGroupIDTaken) {
		t.Fatalf("CreateGroup (diverged signature): err = %v, want ErrGroupIDTaken", err)
	}
}
