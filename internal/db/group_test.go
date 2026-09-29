package db

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

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

// TestListGroupsEmpty pins the "brand-new user" case: no memberships is a
// normal state, not an error, and ListGroups must return empty (non-nil)
// slices rather than fail.
func TestListGroupsEmpty(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	memberships, groups, err := c.ListGroups(ctx, "test-user-"+randomSuffix(t))
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(memberships) != 0 {
		t.Errorf("len(memberships) = %d, want 0", len(memberships))
	}
	if len(groups) != 0 {
		t.Errorf("len(groups) = %d, want 0", len(groups))
	}
}

// TestListGroupsReturnsCreatorsOwnGroups covers the ordinary multi-group
// case: a user who created several groups (one private, one public) sees
// all of them back, each membership correctly joined to its own META --
// role, generation and the private group's wrapped key/ciphertext round-trip
// intact, and the public group's plaintext fields intact.
func TestListGroupsReturnsCreatorsOwnGroups(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	creatorUserID := "test-creator-" + randomSuffix(t)

	privateGroupID := "test-group-" + randomSuffix(t)
	privateIn := testCreateGroupInput(t, privateGroupID, creatorUserID)
	if _, err := c.CreateGroup(ctx, privateIn); err != nil {
		t.Fatalf("CreateGroup (private): %v", err)
	}

	publicGroupID := "test-group-" + randomSuffix(t)
	publicIn := testCreateGroupInput(t, publicGroupID, creatorUserID)
	publicIn.Visibility = models.VisibilityPublic
	publicIn.NameCiphertext = nil
	publicIn.DescriptionCiphertext = nil
	publicIn.NamePlaintext = "Book Club"
	publicIn.DescriptionPlaintext = "We read books"
	if _, err := c.CreateGroup(ctx, publicIn); err != nil {
		t.Fatalf("CreateGroup (public): %v", err)
	}

	memberships, groups, err := c.ListGroups(ctx, creatorUserID)
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(memberships) != 2 {
		t.Fatalf("len(memberships) = %d, want 2", len(memberships))
	}
	if len(groups) != len(memberships) {
		t.Fatalf("len(groups) = %d, want %d (same length as memberships)", len(groups), len(memberships))
	}

	byGroupID := make(map[string]int, len(groups))
	for i := range groups {
		byGroupID[groupIDFromMembership(memberships[i])] = i
	}

	privIdx, ok := byGroupID[privateGroupID]
	if !ok {
		t.Fatalf("private group %q missing from ListGroups result", privateGroupID)
	}
	privMember, privGroup := memberships[privIdx], groups[privIdx]
	if privMember.Role != models.RoleAdmin {
		t.Errorf("private membership Role = %q, want %q", privMember.Role, models.RoleAdmin)
	}
	if privMember.Generation != 0 {
		t.Errorf("private membership Generation = %d, want 0", privMember.Generation)
	}
	if privGroup.Visibility != models.VisibilityPrivate {
		t.Errorf("private group Visibility = %q, want %q", privGroup.Visibility, models.VisibilityPrivate)
	}
	if privGroup.NameCiphertext == nil || string(privGroup.NameCiphertext.Ciphertext) != "name-ciphertext" {
		t.Errorf("private group NameCiphertext = %+v, want ciphertext %q", privGroup.NameCiphertext, "name-ciphertext")
	}
	if string(privMember.WrappedGroupKey.Ciphertext) != "wrapped-generation-key" {
		t.Errorf("private membership WrappedGroupKey.Ciphertext = %q, want %q",
			privMember.WrappedGroupKey.Ciphertext, "wrapped-generation-key")
	}

	pubIdx, ok := byGroupID[publicGroupID]
	if !ok {
		t.Fatalf("public group %q missing from ListGroups result", publicGroupID)
	}
	pubGroup := groups[pubIdx]
	if pubGroup.Visibility != models.VisibilityPublic {
		t.Errorf("public group Visibility = %q, want %q", pubGroup.Visibility, models.VisibilityPublic)
	}
	if pubGroup.NamePlaintext != "Book Club" {
		t.Errorf("public group NamePlaintext = %q, want %q", pubGroup.NamePlaintext, "Book Club")
	}
}

// TestListGroupsIgnoresOtherUsersGroups covers the GSI1 partition boundary:
// a group created by someone else must never show up in this user's list,
// even though both groups' Membership items live in the same table.
func TestListGroupsIgnoresOtherUsersGroups(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	ownGroupID := "test-group-" + randomSuffix(t)
	ownUserID := "test-creator-" + randomSuffix(t)
	if _, err := c.CreateGroup(ctx, testCreateGroupInput(t, ownGroupID, ownUserID)); err != nil {
		t.Fatalf("CreateGroup (own): %v", err)
	}

	otherGroupID := "test-group-" + randomSuffix(t)
	otherUserID := "test-creator-" + randomSuffix(t)
	if _, err := c.CreateGroup(ctx, testCreateGroupInput(t, otherGroupID, otherUserID)); err != nil {
		t.Fatalf("CreateGroup (other): %v", err)
	}

	memberships, groups, err := c.ListGroups(ctx, ownUserID)
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(memberships) != 1 {
		t.Fatalf("len(memberships) = %d, want 1", len(memberships))
	}
	if groupIDFromMembership(memberships[0]) != ownGroupID {
		t.Errorf("returned group id = %q, want %q", groupIDFromMembership(memberships[0]), ownGroupID)
	}
	if groups[0].CreatorUserID != ownUserID {
		t.Errorf("returned group CreatorUserID = %q, want %q", groups[0].CreatorUserID, ownUserID)
	}
}

// TestListGroupsExcludesNonMembershipRows pins PR #144 review's blocking
// finding: GSI1PK "USER#<uuid>" is not membership-exclusive. Per
// docs/DESIGN.md's data-model table, a Join request row
// (PK "GROUP#<gid>", SK "REQ#<uuid>", GSI1PK "USER#<requester>") shares
// this same partition. Before queryMembershipsByUser filtered on
// GSI1SK begins_with "GROUP#", that row's PK still recovered a real gid
// (groupIDFromMembership doesn't care about SK), so a pending REQUESTER --
// not a member at all -- got the group back from ListGroups with
// Role == "". Neither invites nor join requests are modeled yet (#38-40),
// so this row is built directly here rather than through a real db.Client
// method, matching the reviewer's own repro shape.
func TestListGroupsExcludesNonMembershipRows(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	groupID := "test-group-" + randomSuffix(t)
	creatorUserID := "test-creator-" + randomSuffix(t)
	in := testCreateGroupInput(t, groupID, creatorUserID)
	in.Visibility = models.VisibilityPublic
	in.NameCiphertext = nil
	in.DescriptionCiphertext = nil
	in.NamePlaintext = "Public Group"
	if _, err := c.CreateGroup(ctx, in); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	requesterUserID := "test-requester-" + randomSuffix(t)
	_, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(c.table),
		Item: map[string]types.AttributeValue{
			"PK":     &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			"SK":     &types.AttributeValueMemberS{Value: "REQ#" + requesterUserID},
			"Type":   &types.AttributeValueMemberS{Value: "JoinRequest"},
			"GSI1PK": &types.AttributeValueMemberS{Value: "USER#" + requesterUserID},
			"GSI1SK": &types.AttributeValueMemberS{Value: "REQ#2026-09-27#deadbeef"},
		},
	})
	if err != nil {
		t.Fatalf("PutItem (join request row): %v", err)
	}

	memberships, groups, err := c.ListGroups(ctx, requesterUserID)
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(memberships) != 0 || len(groups) != 0 {
		t.Fatalf("ListGroups(requester) = %d memberships, %d groups; want 0, 0 -- a pending join request must not appear as a membership (got %+v / %+v)",
			len(memberships), len(groups), memberships, groups)
	}
}

func setMemberRole(t *testing.T, c *Client, groupID, userID, role string) {
	t.Helper()
	_, err := c.ddb.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + userID},
		},
		UpdateExpression:          aws.String("SET #r = :r"),
		ExpressionAttributeNames:  map[string]string{"#r": "Role"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":r": &types.AttributeValueMemberS{Value: role}},
	})
	if err != nil {
		t.Fatalf("set role: %v", err)
	}
}

// A demotion between the handler's role read and the write must be caught by
// the in-transaction check, and must leave META untouched.
func TestUpdateGroupSettingsRejectsNonAdmin(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid, uid := "test-group-"+randomSuffix(t), "test-admin-"+randomSuffix(t)
	if _, err := c.CreateGroup(ctx, testCreateGroupInput(t, gid, uid)); err != nil {
		t.Fatal(err)
	}
	setMemberRole(t, c, gid, uid, models.RoleMember)

	err := c.UpdateGroupSettings(ctx, UpdateGroupSettingsInput{
		GroupID: gid, AdminUserID: uid, Visibility: models.VisibilityPrivate,
		NameCiphertext:        &models.WrappedBlob{Nonce: make([]byte, 12), Ciphertext: []byte("n2")},
		DescriptionCiphertext: &models.WrappedBlob{Nonce: make([]byte, 12), Ciphertext: []byte("d2")},
		ExpirationDays:        5,
	})
	if !errors.Is(err, ErrNotGroupAdmin) {
		t.Fatalf("err = %v, want ErrNotGroupAdmin", err)
	}
	g, err := c.GetGroup(ctx, gid)
	if err != nil || g == nil {
		t.Fatalf("GetGroup: %v %v", g, err)
	}
	if g.ExpirationDays != 30 || g.Version != 0 {
		t.Errorf("META changed by a rejected update: %+v", g)
	}

	// A caller with no membership row at all is rejected the same way.
	err = c.UpdateGroupSettings(ctx, UpdateGroupSettingsInput{
		GroupID: gid, AdminUserID: "stranger-" + randomSuffix(t), Visibility: models.VisibilityPrivate,
		NameCiphertext:        &models.WrappedBlob{Nonce: make([]byte, 12), Ciphertext: []byte("n2")},
		DescriptionCiphertext: &models.WrappedBlob{Nonce: make([]byte, 12), Ciphertext: []byte("d2")},
		ExpirationDays:        5,
	})
	if !errors.Is(err, ErrNotGroupAdmin) {
		t.Fatalf("stranger err = %v, want ErrNotGroupAdmin", err)
	}
}

func TestUpdateGroupSettingsVersionConflict(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid, uid := "test-group-"+randomSuffix(t), "test-admin-"+randomSuffix(t)
	if _, err := c.CreateGroup(ctx, testCreateGroupInput(t, gid, uid)); err != nil {
		t.Fatal(err)
	}
	in := UpdateGroupSettingsInput{
		GroupID: gid, AdminUserID: uid, Visibility: models.VisibilityPrivate,
		NameCiphertext:        &models.WrappedBlob{Nonce: make([]byte, 12), Ciphertext: []byte("n2")},
		DescriptionCiphertext: &models.WrappedBlob{Nonce: make([]byte, 12), Ciphertext: []byte("d2")},
		ExpirationDays:        5,
	}
	if err := c.UpdateGroupSettings(ctx, in); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := c.UpdateGroupSettings(ctx, in); !errors.Is(err, ErrGroupVersionConflict) {
		t.Fatalf("stale version err = %v, want ErrGroupVersionConflict", err)
	}
	in.ExpectedVersion = 1
	if err := c.UpdateGroupSettings(ctx, in); err != nil {
		t.Fatalf("current version: %v", err)
	}
	// Editing a group that does not exist must not create one.
	in.GroupID = "test-group-missing-" + randomSuffix(t)
	if err := c.UpdateGroupSettings(ctx, in); err == nil {
		t.Fatal("update of a nonexistent group succeeded")
	}
}

func TestUpdateGroupSettingsPublicRewritesDirectoryEntry(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid, uid := "test-group-"+randomSuffix(t), "test-admin-"+randomSuffix(t)
	create := testCreateGroupInput(t, gid, uid)
	create.Visibility = models.VisibilityPublic
	create.NameCiphertext, create.DescriptionCiphertext = nil, nil
	create.NamePlaintext, create.DescriptionPlaintext = "Old", "Old description"
	if _, err := c.CreateGroup(ctx, create); err != nil {
		t.Fatal(err)
	}

	err := c.UpdateGroupSettings(ctx, UpdateGroupSettingsInput{
		GroupID: gid, AdminUserID: uid, Visibility: models.VisibilityPublic,
		NamePlaintext: "New", ExpirationDays: 7,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	g, err := c.GetGroup(ctx, gid)
	if err != nil || g == nil {
		t.Fatalf("GetGroup: %v %v", g, err)
	}
	if g.NamePlaintext != "New" || g.DescriptionPlaintext != "" || g.ExpirationDays != 7 || g.Version != 1 {
		t.Errorf("unexpected META: %+v", g)
	}
	if g.GSI1PK != "PUBLIC#0" || g.GSI1SK != "NAME#New#"+gid {
		t.Errorf("directory entry = %q / %q", g.GSI1PK, g.GSI1SK)
	}
}

func newTestGroupWithMember(t *testing.T, c *Client) (gid, admin, member, root string) {
	t.Helper()
	ctx := context.Background()
	gid, admin, member = "test-group-"+randomSuffix(t), "test-admin-"+randomSuffix(t), "test-member-"+randomSuffix(t)
	in := testCreateGroupInput(t, gid, admin)
	if _, err := c.CreateGroup(ctx, in); err != nil {
		t.Fatal(err)
	}
	m := models.Membership{
		Record: models.Record{PK: "GROUP#" + gid, SK: "MEMBER#" + member, Type: "Membership", GSI1PK: "USER#" + member, GSI1SK: "GROUP#" + gid},
		Role:   models.RoleMember,
	}
	item, err := attributevalue.MarshalMap(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: item}); err != nil {
		t.Fatal(err)
	}
	return gid, admin, member, in.RootGrantSortKey
}

func roleChange(gid, admin, member, root, role, grantKey string) ChangeMemberRoleInput {
	return ChangeMemberRoleInput{
		GroupID: gid, SubjectUserID: member, OldRole: models.RoleMember, NewRole: role,
		GrantorUserID: admin, GrantorSigningPublicKey: make([]byte, 32),
		GrantorGrantRef: root, GrantorHasStoredGrant: true,
		GrantSortKey: grantKey, Signature: []byte("sig"),
	}
}

func TestChangeMemberRoleRaces(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid, admin, member, root := newTestGroupWithMember(t, c)
	key := func() string { return "GRANT#" + member + "#2026-09-28#" + randomSuffix(t) + randomSuffix(t) }

	// Grantor demoted after the handler's read: rejected, nothing written.
	setMemberRole(t, c, gid, admin, models.RoleMember)
	k1 := key()
	if err := c.ChangeMemberRole(ctx, roleChange(gid, admin, member, root, models.RoleAmbassador, k1)); !errors.Is(err, ErrGrantorChanged) {
		t.Fatalf("demoted grantor: %v, want ErrGrantorChanged", err)
	}
	if out, _ := c.ddb.GetItem(ctx, getItemInput(c.table, "GROUP#"+gid, k1)); out.Item != nil {
		t.Error("grant row written by a rejected change")
	}
	setMemberRole(t, c, gid, admin, models.RoleAdmin)

	// Grantor's recorded grant is not the one that was signed against.
	stale := roleChange(gid, admin, member, "GRANT#"+admin+"#2026-01-01#0000000000000000", models.RoleAmbassador, key())
	if err := c.ChangeMemberRole(ctx, stale); !errors.Is(err, ErrGrantorChanged) {
		t.Fatalf("stale ref: %v, want ErrGrantorChanged", err)
	}

	// Subject's role is no longer what the caller saw.
	setMemberRole(t, c, gid, member, models.RoleAmbassador)
	if err := c.ChangeMemberRole(ctx, roleChange(gid, admin, member, root, models.RoleAdmin, key())); !errors.Is(err, ErrSubjectRoleChanged) {
		t.Fatalf("subject changed: %v, want ErrSubjectRoleChanged", err)
	}
	setMemberRole(t, c, gid, member, models.RoleMember)

	// Success, then a reused grant address.
	k2 := key()
	if err := c.ChangeMemberRole(ctx, roleChange(gid, admin, member, root, models.RoleAmbassador, k2)); err != nil {
		t.Fatalf("good change: %v", err)
	}
	setMemberRole(t, c, gid, member, models.RoleMember)
	if err := c.ChangeMemberRole(ctx, roleChange(gid, admin, member, root, models.RoleAdmin, k2)); !errors.Is(err, ErrGrantKeyTaken) {
		t.Fatalf("reused key: %v, want ErrGrantKeyTaken", err)
	}
	// The failed attempt must not have left the subject's role changed.
	metaOut, _ := c.ddb.GetItem(ctx, getItemInput(c.table, "GROUP#"+gid, "MEMBER#"+member))
	var m models.Membership
	if err := unmarshalItem(metaOut.Item, &m); err != nil {
		t.Fatal(err)
	}
	if m.Role != models.RoleMember {
		t.Errorf("role = %q after rejected change, want member", m.Role)
	}
}

func TestIsTransactionConflict(t *testing.T) {
	code := func(c string) types.CancellationReason { return types.CancellationReason{Code: aws.String(c)} }
	conflict := &types.TransactionCanceledException{CancellationReasons: []types.CancellationReason{code("None"), code("TransactionConflict"), code("None")}}
	condFail := &types.TransactionCanceledException{CancellationReasons: []types.CancellationReason{code("ConditionalCheckFailed"), code("None")}}
	if !isTransactionConflict(conflict) {
		t.Error("TransactionConflict cancellation not recognized")
	}
	if isTransactionConflict(condFail) || isTransactionConflict(errors.New("other")) || isTransactionConflict(nil) {
		t.Error("non-conflict error recognized as TransactionConflict")
	}
}
