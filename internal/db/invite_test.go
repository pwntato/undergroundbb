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

func testCreateInviteInput(t *testing.T, inviteID, groupID, inviterUserID string, expiresAt time.Time) CreateInviteInput {
	t.Helper()
	return CreateInviteInput{
		InviteID:                inviteID,
		GroupID:                 groupID,
		InviterUserID:           inviterUserID,
		InviterSigningPublicKey: make([]byte, 32),
		CreationSignature:       []byte("creation-signature"),
		// Both fields must agree, matching how the real handler builds
		// them from the same request field -- see CreateInviteInput's own
		// doc comment for why ExpiresAt is the verbatim string (never
		// reformatted from ExpiresAtParsed) that CreationSignature covers.
		ExpiresAt:       expiresAt.UTC().Format(time.RFC3339),
		ExpiresAtParsed: expiresAt,
	}
}

func TestCreateInviteWritesBothItems(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviteID := "test-invite-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	inviterUserID := "test-inviter-" + randomSuffix(t)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	in := testCreateInviteInput(t, inviteID, groupID, inviterUserID, expiresAt)

	if err := c.CreateInvite(ctx, in); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	metaOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "INVITE#"+inviteID, "META"))
	if err != nil {
		t.Fatalf("GetItem META: %v", err)
	}
	if metaOut.Item == nil {
		t.Fatal("INVITE# META item was not written")
	}
	var invite models.Invite
	if err := unmarshalItem(metaOut.Item, &invite); err != nil {
		t.Fatalf("unmarshal INVITE# META: %v", err)
	}
	if invite.GroupID != groupID {
		t.Errorf("invite.GroupID = %q, want %q", invite.GroupID, groupID)
	}
	if invite.InviterUserID != inviterUserID {
		t.Errorf("invite.InviterUserID = %q, want %q", invite.InviterUserID, inviterUserID)
	}
	if invite.GSI1PK != "" || invite.GSI1SK != "" {
		t.Errorf("newly created invite has GSI1PK=%q GSI1SK=%q, want both empty until acceptance", invite.GSI1PK, invite.GSI1SK)
	}
	if invite.InvitedUserID != "" {
		t.Errorf("newly created invite has InvitedUserID=%q, want empty", invite.InvitedUserID)
	}
	// The stored TTL is rounded up to the end of its UTC day (RoundUpToEndOfUTCDay),
	// so it should differ from the unrounded expiresAt.Unix() but land on
	// the same UTC calendar day, at 23:59:59.
	wantTTL := RoundUpToEndOfUTCDay(expiresAt).Unix()
	if invite.TTL != wantTTL {
		t.Errorf("invite.TTL = %d, want %d (RoundUpToEndOfUTCDay(expiresAt))", invite.TTL, wantTTL)
	}

	sentOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+inviterUserID, "SENT#"+inviteID))
	if err != nil {
		t.Fatalf("GetItem SENT#: %v", err)
	}
	if sentOut.Item == nil {
		t.Fatal("SENT# item was not written")
	}
	var sent models.SentInvite
	if err := unmarshalItem(sentOut.Item, &sent); err != nil {
		t.Fatalf("unmarshal SENT#: %v", err)
	}
	if sent.InviteID != inviteID {
		t.Errorf("sent.InviteID = %q, want %q", sent.InviteID, inviteID)
	}
	if sent.GroupID != groupID {
		t.Errorf("sent.GroupID = %q, want %q", sent.GroupID, groupID)
	}
	if sent.GSI1PK != "" || sent.GSI1SK != "" {
		t.Errorf("SENT# item has GSI1PK=%q GSI1SK=%q, want both empty (DESIGN.md: blank GSI1PK/GSI1SK)", sent.GSI1PK, sent.GSI1SK)
	}
}

func TestCreateInviteIDCollisionFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviteID := "test-invite-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	inviterUserID := "test-inviter-" + randomSuffix(t)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	in := testCreateInviteInput(t, inviteID, groupID, inviterUserID, expiresAt)

	if err := c.CreateInvite(ctx, in); err != nil {
		t.Fatalf("first CreateInvite: %v", err)
	}

	// A different inviter attempting to reuse the same InviteID is a
	// genuine collision, not a resend this package treats specially (see
	// CreateInvite's own doc comment: unlike CreateGroup, no
	// isOwnGroupCreation-style retry check exists for invites).
	other := testCreateInviteInput(t, inviteID, groupID, "different-inviter-"+randomSuffix(t), expiresAt)
	err := c.CreateInvite(ctx, other)
	if !errors.Is(err, ErrInviteIDTaken) {
		t.Fatalf("second CreateInvite with colliding id: err = %v, want ErrInviteIDTaken", err)
	}
}

func TestGetInviteMissingReturnsNil(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	invite, err := c.GetInvite(ctx, "nonexistent-invite-"+randomSuffix(t))
	if err != nil {
		t.Fatalf("GetInvite: %v", err)
	}
	if invite != nil {
		t.Fatalf("GetInvite for a nonexistent id = %+v, want nil", invite)
	}
}

func testAcceptInviteInput(inviteID, invitedUserID string) AcceptInviteInput {
	return AcceptInviteInput{
		InviteID:                inviteID,
		InvitedUserID:           invitedUserID,
		InvitedEd25519PublicKey: make([]byte, 32),
		InvitedX25519PublicKey:  make([]byte, 32),
		AcceptanceSignature:     []byte("acceptance-signature"),
		InviteMAC:               []byte("invite-mac-32-bytes-of-filler!!"),
	}
}

func TestAcceptInviteSetsInviteeOnBothRows(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviteID := "test-invite-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	inviterUserID := "test-inviter-" + randomSuffix(t)
	invitedUserID := "test-invitee-" + randomSuffix(t)
	// Deliberately shorter than completionDeadlineDuration (7 days) so the
	// original signed-expiry TTL and the post-acceptance completion
	// deadline round to genuinely different UTC days -- using the same
	// duration for both would make this assertion pass even if acceptance
	// never actually replaced the TTL.
	expiresAt := time.Now().Add(1 * time.Hour)

	if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, groupID, inviterUserID, expiresAt)); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	acceptIn := testAcceptInviteInput(inviteID, invitedUserID)
	if err := c.AcceptInvite(ctx, acceptIn); err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}

	invite, err := c.GetInvite(ctx, inviteID)
	if err != nil {
		t.Fatalf("GetInvite: %v", err)
	}
	if invite == nil {
		t.Fatal("invite vanished after acceptance")
	}
	if invite.InvitedUserID != invitedUserID {
		t.Errorf("invite.InvitedUserID = %q, want %q", invite.InvitedUserID, invitedUserID)
	}
	if invite.GSI1PK != "USER#"+invitedUserID {
		t.Errorf("invite.GSI1PK = %q, want %q (added at acceptance)", invite.GSI1PK, "USER#"+invitedUserID)
	}
	wantPrefix := "INVITE#"
	if len(invite.GSI1SK) <= len(wantPrefix) || invite.GSI1SK[:len(wantPrefix)] != wantPrefix {
		t.Errorf("invite.GSI1SK = %q, want it to start with %q", invite.GSI1SK, wantPrefix)
	}

	// The TTL must have been REPLACED with a completion deadline, not merely
	// left as the original signed expiry -- see AcceptInvite's own doc
	// comment and #38/#39's "acceptance swaps the signed expiry for a
	// completion deadline" requirement.
	originalTTL := RoundUpToEndOfUTCDay(expiresAt).Unix()
	if invite.TTL == originalTTL {
		t.Error("invite.TTL unchanged after acceptance, want a new completion deadline")
	}
	wantDeadline := RoundUpToEndOfUTCDay(time.Now().Add(completionDeadlineDuration)).Unix()
	// Allow a small window since "now" ticks between the deadline computed
	// inside AcceptInvite and this assertion -- both round to the same UTC
	// day's 23:59:59 unless the test runs across a day boundary, which
	// RoundUpToEndOfUTCDay's own rounding absorbs entirely in practice.
	if invite.TTL != wantDeadline {
		t.Errorf("invite.TTL = %d, want %d (completion deadline, rounded)", invite.TTL, wantDeadline)
	}

	sentOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+inviterUserID, "SENT#"+inviteID))
	if err != nil {
		t.Fatalf("GetItem SENT#: %v", err)
	}
	if sentOut.Item == nil {
		t.Fatal("SENT# item vanished after acceptance")
	}
	var sent models.SentInvite
	if err := unmarshalItem(sentOut.Item, &sent); err != nil {
		t.Fatalf("unmarshal SENT#: %v", err)
	}
	if sent.InvitedUserID != invitedUserID {
		t.Errorf("sent.InvitedUserID = %q, want %q -- SENT# row must be updated in the same transaction", sent.InvitedUserID, invitedUserID)
	}
	if sent.TTL != wantDeadline {
		t.Errorf("sent.TTL = %d, want %d (both rows share the same completion deadline)", sent.TTL, wantDeadline)
	}
}

func TestAcceptInviteNotFound(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	err := c.AcceptInvite(ctx, testAcceptInviteInput("nonexistent-invite-"+randomSuffix(t), "test-invitee-"+randomSuffix(t)))
	if !errors.Is(err, ErrInviteNotFound) {
		t.Fatalf("AcceptInvite on nonexistent invite: err = %v, want ErrInviteNotFound", err)
	}
}

// TestAcceptInviteSecondAcceptorFails pins the single-use guarantee issue
// #39's blocking review comment requires: a second holder of the same link
// (a forwarded message, a screenshot) accepting after the intended invitee
// must get an explicit error, not silently rename who the invite points at.
func TestAcceptInviteSecondAcceptorFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviteID := "test-invite-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	inviterUserID := "test-inviter-" + randomSuffix(t)
	firstInvitee := "test-invitee-first-" + randomSuffix(t)
	secondInvitee := "test-invitee-second-" + randomSuffix(t)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, groupID, inviterUserID, expiresAt)); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, firstInvitee)); err != nil {
		t.Fatalf("first AcceptInvite: %v", err)
	}

	err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, secondInvitee))
	if !errors.Is(err, ErrInviteAlreadyAccepted) {
		t.Fatalf("second AcceptInvite: err = %v, want ErrInviteAlreadyAccepted", err)
	}

	// Verify by mutation what the bug would have looked like: the invite
	// must still name the FIRST invitee, not the second.
	invite, err := c.GetInvite(ctx, inviteID)
	if err != nil {
		t.Fatalf("GetInvite: %v", err)
	}
	if invite.InvitedUserID != firstInvitee {
		t.Errorf("invite.InvitedUserID = %q after a rejected second acceptance, want it to remain %q", invite.InvitedUserID, firstInvitee)
	}
}

func TestPendingInviteCompletionsOnlyReturnsAccepted(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviterUserID := "test-inviter-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	unacceptedID := "test-invite-unaccepted-" + randomSuffix(t)
	acceptedID := "test-invite-accepted-" + randomSuffix(t)
	invitedUserID := "test-invitee-" + randomSuffix(t)

	if err := c.CreateInvite(ctx, testCreateInviteInput(t, unacceptedID, groupID, inviterUserID, expiresAt)); err != nil {
		t.Fatalf("CreateInvite (unaccepted): %v", err)
	}
	if err := c.CreateInvite(ctx, testCreateInviteInput(t, acceptedID, groupID, inviterUserID, expiresAt)); err != nil {
		t.Fatalf("CreateInvite (accepted): %v", err)
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(acceptedID, invitedUserID)); err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}

	pending, err := c.PendingInviteCompletions(ctx, inviterUserID)
	if err != nil {
		t.Fatalf("PendingInviteCompletions: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("PendingInviteCompletions returned %d rows, want 1 (only the accepted invite)", len(pending))
	}
	if pending[0].InviteID != acceptedID {
		t.Errorf("pending[0].InviteID = %q, want %q", pending[0].InviteID, acceptedID)
	}
	if pending[0].InvitedUserID != invitedUserID {
		t.Errorf("pending[0].InvitedUserID = %q, want %q", pending[0].InvitedUserID, invitedUserID)
	}
}

func testCompleteInviteInput(inviteID, groupID, inviterUserID, invitedUserID string) CompleteInviteInput {
	return CompleteInviteInput{
		InviteID:      inviteID,
		GroupID:       groupID,
		InviterUserID: inviterUserID,
		InvitedUserID: invitedUserID,
		Generation:    0,
		WrappedGroupKey: models.WrappedKey{
			EphemeralPub: make([]byte, 32),
			Nonce:        make([]byte, 12),
			Ciphertext:   []byte("wrapped-group-key"),
		},
		Role: models.RoleMember,
	}
}

func TestCompleteInviteWritesMembershipAndDeletesBothRows(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviteID := "test-invite-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	inviterUserID := "test-inviter-" + randomSuffix(t)
	invitedUserID := "test-invitee-" + randomSuffix(t)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, groupID, inviterUserID, expiresAt)); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, invitedUserID)); err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}

	completeIn := testCompleteInviteInput(inviteID, groupID, inviterUserID, invitedUserID)
	if err := c.CompleteInvite(ctx, completeIn); err != nil {
		t.Fatalf("CompleteInvite: %v", err)
	}

	memberOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "GROUP#"+groupID, "MEMBER#"+invitedUserID))
	if err != nil {
		t.Fatalf("GetItem MEMBER#: %v", err)
	}
	if memberOut.Item == nil {
		t.Fatal("MEMBER# item was not written by CompleteInvite")
	}
	var membership models.Membership
	if err := unmarshalItem(memberOut.Item, &membership); err != nil {
		t.Fatalf("unmarshal MEMBER#: %v", err)
	}
	if membership.Role != models.RoleMember {
		t.Errorf("membership.Role = %q, want %q", membership.Role, models.RoleMember)
	}
	if membership.GSI1PK != "USER#"+invitedUserID || membership.GSI1SK != "GROUP#"+groupID {
		t.Errorf("membership GSI1PK/GSI1SK = %q/%q, want %q/%q", membership.GSI1PK, membership.GSI1SK, "USER#"+invitedUserID, "GROUP#"+groupID)
	}

	inviteOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "INVITE#"+inviteID, "META"))
	if err != nil {
		t.Fatalf("GetItem INVITE# META: %v", err)
	}
	if inviteOut.Item != nil {
		t.Error("INVITE# META row still exists after completion, want it deleted")
	}

	sentOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+inviterUserID, "SENT#"+inviteID))
	if err != nil {
		t.Fatalf("GetItem SENT#: %v", err)
	}
	if sentOut.Item != nil {
		t.Error("SENT# row still exists after completion, want it deleted")
	}

	pending, err := c.PendingInviteCompletions(ctx, inviterUserID)
	if err != nil {
		t.Fatalf("PendingInviteCompletions: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("PendingInviteCompletions after completion returned %d rows, want 0", len(pending))
	}
}

func TestCompleteInviteAlreadyCompletedFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviteID := "test-invite-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	inviterUserID := "test-inviter-" + randomSuffix(t)
	invitedUserID := "test-invitee-" + randomSuffix(t)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, groupID, inviterUserID, expiresAt)); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, invitedUserID)); err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}

	completeIn := testCompleteInviteInput(inviteID, groupID, inviterUserID, invitedUserID)
	if err := c.CompleteInvite(ctx, completeIn); err != nil {
		t.Fatalf("first CompleteInvite: %v", err)
	}

	// A second completion attempt (two tabs/devices racing on the same
	// pending invite) must fail loudly, not double-write.
	err := c.CompleteInvite(ctx, completeIn)
	if !errors.Is(err, ErrInviteAlreadyCompleted) && !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("second CompleteInvite: err = %v, want ErrInviteAlreadyCompleted or ErrAlreadyMember", err)
	}
}

func TestCompleteInviteAlreadyMemberFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviteID := "test-invite-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	inviterUserID := "test-inviter-" + randomSuffix(t)
	invitedUserID := "test-invitee-" + randomSuffix(t)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, groupID, inviterUserID, expiresAt)); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, invitedUserID)); err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}

	// Simulate the invitee already being a member some other way (e.g. a
	// second, unrelated invite to the same group already completed) by
	// creating the group with them as an unrelated member first.
	preexisting := models.Membership{
		Record: models.Record{
			PK:     "GROUP#" + groupID,
			SK:     "MEMBER#" + invitedUserID,
			Type:   "Membership",
			GSI1PK: "USER#" + invitedUserID,
			GSI1SK: "GROUP#" + groupID,
		},
		Role:       models.RoleMember,
		Generation: 0,
	}
	item, err := attributevalue.MarshalMap(preexisting)
	if err != nil {
		t.Fatalf("marshal preexisting membership: %v", err)
	}
	if _, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(c.table),
		Item:      item,
	}); err != nil {
		t.Fatalf("PutItem preexisting membership: %v", err)
	}

	completeIn := testCompleteInviteInput(inviteID, groupID, inviterUserID, invitedUserID)
	err = c.CompleteInvite(ctx, completeIn)
	if !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("CompleteInvite with a pre-existing membership: err = %v, want ErrAlreadyMember", err)
	}
}

// TestCleanupAlreadyMemberInviteDeletesBothRows pins non-blocking review
// finding #4 (round 1): the follow-up cleanup CompleteInvite's own caller
// runs after ErrAlreadyMember must actually delete both invite rows, so a
// pending invite that can never be completed does not linger until the
// 7-day deadline TTL eventually sweeps it.
func TestCleanupAlreadyMemberInviteDeletesBothRows(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviteID := "test-invite-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	inviterUserID := "test-inviter-" + randomSuffix(t)
	invitedUserID := "test-invitee-" + randomSuffix(t)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, groupID, inviterUserID, expiresAt)); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, invitedUserID)); err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}

	if err := c.CleanupAlreadyMemberInvite(ctx, inviteID, inviterUserID); err != nil {
		t.Fatalf("CleanupAlreadyMemberInvite: %v", err)
	}

	metaOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "INVITE#"+inviteID, "META"))
	if err != nil {
		t.Fatalf("GetItem META: %v", err)
	}
	if metaOut.Item != nil {
		t.Error("INVITE# META item still exists after CleanupAlreadyMemberInvite, want deleted")
	}
	sentOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+inviterUserID, "SENT#"+inviteID))
	if err != nil {
		t.Fatalf("GetItem SENT#: %v", err)
	}
	if sentOut.Item != nil {
		t.Error("SENT# item still exists after CleanupAlreadyMemberInvite, want deleted")
	}

	// A second cleanup attempt on the same, now-gone invite must succeed
	// as a no-op -- PR #146 round-2 review's own fix: CleanupAlreadyMemberInvite's
	// deletes are deliberately unconditional now, so a racing second
	// cleanup (or completion) attempt finding both rows already gone is
	// simply nothing left to do, not an error.
	if err := c.CleanupAlreadyMemberInvite(ctx, inviteID, inviterUserID); err != nil {
		t.Fatalf("second CleanupAlreadyMemberInvite: err = %v, want nil (no-op)", err)
	}
}

// TestCleanupAlreadyMemberInviteHalfGoneStillDeletesBothRows is the exact
// regression PR #146 round-2 review caught: with a ConditionExpression on
// EACH delete, if one row was already gone but the other still existed,
// TransactWriteItems canceled the WHOLE transaction on the failed
// condition -- including the delete that would have succeeded -- leaving
// the still-existing row as a genuine zombie no caller ever retried.
// Simulated here by deleting the SENT# row directly before ever calling
// CleanupAlreadyMemberInvite, so only the INVITE# row is left for it to
// find.
func TestCleanupAlreadyMemberInviteHalfGoneStillDeletesBothRows(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviteID := "test-invite-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	inviterUserID := "test-inviter-" + randomSuffix(t)
	invitedUserID := "test-invitee-" + randomSuffix(t)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, groupID, inviterUserID, expiresAt)); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, invitedUserID)); err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}

	// SENT# is already gone BEFORE cleanup ever runs -- only INVITE# is
	// left for CleanupAlreadyMemberInvite to find.
	if _, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + inviterUserID},
			"SK": &types.AttributeValueMemberS{Value: "SENT#" + inviteID},
		},
	}); err != nil {
		t.Fatalf("DeleteItem SENT#: %v", err)
	}

	if err := c.CleanupAlreadyMemberInvite(ctx, inviteID, inviterUserID); err != nil {
		t.Fatalf("CleanupAlreadyMemberInvite: %v", err)
	}

	// The bug this test pins: with per-item conditions, this INVITE# row
	// would have SURVIVED (the transaction canceled on SENT#'s failed
	// condition), even though cleanup reported no error.
	metaOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "INVITE#"+inviteID, "META"))
	if err != nil {
		t.Fatalf("GetItem META: %v", err)
	}
	if metaOut.Item != nil {
		t.Error("INVITE# META item still exists after CleanupAlreadyMemberInvite with SENT# already gone, want deleted (half-zombie regression)")
	}
}

// TestRevokeInviteDeletesBothRows pins docs/DESIGN.md's revocation remedy
// at the db layer: before acceptance, RevokeInvite deletes both rows.
func TestRevokeInviteDeletesBothRows(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviteID := "test-invite-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	inviterUserID := "test-inviter-" + randomSuffix(t)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, groupID, inviterUserID, expiresAt)); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	if err := c.RevokeInvite(ctx, inviteID, inviterUserID); err != nil {
		t.Fatalf("RevokeInvite: %v", err)
	}

	invite, err := c.GetInvite(ctx, inviteID)
	if err != nil {
		t.Fatalf("GetInvite: %v", err)
	}
	if invite != nil {
		t.Error("GetInvite after RevokeInvite returned a row, want nil")
	}
	sentOut, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+inviterUserID, "SENT#"+inviteID))
	if err != nil {
		t.Fatalf("GetItem SENT#: %v", err)
	}
	if sentOut.Item != nil {
		t.Error("SENT# item still exists after RevokeInvite, want deleted")
	}
}

// TestRevokeInviteAfterAcceptanceFails pins that revocation is
// pre-acceptance only -- RevokeInvite's own ConditionExpression includes
// attribute_not_exists(InvitedUserID), so an accepted invite's rows must
// be left untouched.
func TestRevokeInviteAfterAcceptanceFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviteID := "test-invite-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	inviterUserID := "test-inviter-" + randomSuffix(t)
	invitedUserID := "test-invitee-" + randomSuffix(t)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, groupID, inviterUserID, expiresAt)); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, invitedUserID)); err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}

	err := c.RevokeInvite(ctx, inviteID, inviterUserID)
	if !errors.Is(err, ErrInviteAlreadyAcceptedForRevoke) {
		t.Fatalf("RevokeInvite after acceptance: err = %v, want ErrInviteAlreadyAcceptedForRevoke", err)
	}

	// Both rows must be untouched.
	invite, err := c.GetInvite(ctx, inviteID)
	if err != nil {
		t.Fatalf("GetInvite: %v", err)
	}
	if invite == nil {
		t.Fatal("GetInvite after a rejected RevokeInvite returned nil, want the row still present")
	}
	if invite.InvitedUserID != invitedUserID {
		t.Errorf("invite.InvitedUserID = %q, want %q (untouched)", invite.InvitedUserID, invitedUserID)
	}
}

// TestRevokeInviteMissingFails pins that revoking a never-created (or
// already-swept/already-revoked) invite id fails rather than silently
// succeeding.
func TestRevokeInviteMissingFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	err := c.RevokeInvite(ctx, "nonexistent-invite-"+randomSuffix(t), "some-inviter-"+randomSuffix(t))
	if !errors.Is(err, ErrInviteAlreadyAcceptedForRevoke) {
		t.Fatalf("RevokeInvite on a missing invite: err = %v, want ErrInviteAlreadyAcceptedForRevoke", err)
	}
}

// TestAcceptInviteMissingSentRowFails pins non-blocking review finding #5:
// the SENT# update's own ConditionExpression (attribute_exists(PK)) must
// refuse to upsert a fresh row into the inviter's own partition when that
// row is somehow already missing at accept time (e.g. a future revocation
// path that only deleted the SENT# half, or the two rows falling out of
// sync some other way) -- simulated here by deleting the SENT# row
// directly after CreateInvite, before ever calling AcceptInvite.
func TestAcceptInviteMissingSentRowFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviteID := "test-invite-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	inviterUserID := "test-inviter-" + randomSuffix(t)
	invitedUserID := "test-invitee-" + randomSuffix(t)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, groupID, inviterUserID, expiresAt)); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	if _, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + inviterUserID},
			"SK": &types.AttributeValueMemberS{Value: "SENT#" + inviteID},
		},
	}); err != nil {
		t.Fatalf("DeleteItem SENT#: %v", err)
	}

	err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, invitedUserID))
	if !errors.Is(err, ErrInviteNotFound) {
		t.Fatalf("AcceptInvite with a missing SENT# row: err = %v, want ErrInviteNotFound", err)
	}

	// The INVITE# row must NOT have been updated either -- a partial write
	// (INVITE# accepted, SENT# never touched because it didn't exist)
	// would be worse than this all-or-nothing failure.
	invite, err := c.GetInvite(ctx, inviteID)
	if err != nil {
		t.Fatalf("GetInvite: %v", err)
	}
	if invite == nil {
		t.Fatal("GetInvite returned nil, want the row still present")
	}
	if invite.InvitedUserID != "" {
		t.Errorf("invite.InvitedUserID = %q after a failed accept, want empty (no partial write)", invite.InvitedUserID)
	}
}

func TestListSentInvitesEnforcesExpiryOnRead(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviterUserID := "test-inviter-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	liveID := "test-invite-live-" + randomSuffix(t)
	expiredID := "test-invite-expired-" + randomSuffix(t)
	acceptedID := "test-invite-accepted-" + randomSuffix(t)
	revokedID := "test-invite-revoked-" + randomSuffix(t)

	future := time.Now().Add(7 * 24 * time.Hour)
	// Expired by an hour, but the row's TTL (end of that UTC day) has not
	// passed, so only the read-side check can drop it.
	past := time.Now().Add(-time.Hour)
	for id, exp := range map[string]time.Time{liveID: future, expiredID: past, acceptedID: future, revokedID: future} {
		if err := c.CreateInvite(ctx, testCreateInviteInput(t, id, groupID, inviterUserID, exp)); err != nil {
			t.Fatalf("CreateInvite %s: %v", id, err)
		}
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(acceptedID, "test-invitee-"+randomSuffix(t))); err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}
	if err := c.RevokeInvite(ctx, revokedID, inviterUserID); err != nil {
		t.Fatalf("RevokeInvite: %v", err)
	}

	views, err := c.ListSentInvites(ctx, inviterUserID, time.Now())
	if err != nil {
		t.Fatalf("ListSentInvites: %v", err)
	}
	got := map[string]SentInviteView{}
	for _, v := range views {
		got[v.InviteID] = v
	}
	if len(got) != 2 {
		t.Fatalf("ListSentInvites returned %d invites (%v), want 2 (live + accepted)", len(got), got)
	}
	if v, ok := got[liveID]; !ok || v.InvitedUserID != "" || v.ExpiresAt == "" {
		t.Errorf("live invite = %+v (present %v), want pending with ExpiresAt", v, ok)
	}
	if v, ok := got[acceptedID]; !ok || v.InvitedUserID == "" {
		t.Errorf("accepted invite = %+v (present %v), want accepted", v, ok)
	}
}

func TestListSentInvitesKeepsAcceptedPastSignedExpiry(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviterUserID := "test-inviter-" + randomSuffix(t)
	inviteID := "test-invite-" + randomSuffix(t)
	if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, "test-group-"+randomSuffix(t), inviterUserID, time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, "test-invitee-"+randomSuffix(t))); err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}

	// Two hours later the signed expires_at has passed, but acceptance
	// replaced it with the completion deadline: the row must stay listed.
	views, err := c.ListSentInvites(ctx, inviterUserID, time.Now().Add(2*time.Hour))
	if err != nil {
		t.Fatalf("ListSentInvites: %v", err)
	}
	if len(views) != 1 || views[0].InviteID != inviteID {
		t.Fatalf("ListSentInvites = %+v, want the accepted invite still listed", views)
	}
}

func TestListReceivedInvitesOnlyCallersAcceptedInvites(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviterUserID := "test-inviter-" + randomSuffix(t)
	groupID := "test-group-" + randomSuffix(t)
	me := "test-invitee-" + randomSuffix(t)
	other := "test-invitee-" + randomSuffix(t)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	mineID := "test-invite-mine-" + randomSuffix(t)
	otherID := "test-invite-other-" + randomSuffix(t)
	unacceptedID := "test-invite-unaccepted-" + randomSuffix(t)
	for _, id := range []string{mineID, otherID, unacceptedID} {
		if err := c.CreateInvite(ctx, testCreateInviteInput(t, id, groupID, inviterUserID, expiresAt)); err != nil {
			t.Fatalf("CreateInvite %s: %v", id, err)
		}
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(mineID, me)); err != nil {
		t.Fatalf("AcceptInvite mine: %v", err)
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(otherID, other)); err != nil {
		t.Fatalf("AcceptInvite other: %v", err)
	}

	invites, err := c.ListReceivedInvites(ctx, me)
	if err != nil {
		t.Fatalf("ListReceivedInvites: %v", err)
	}
	if len(invites) != 1 || invites[0].PK != "INVITE#"+mineID {
		t.Fatalf("ListReceivedInvites = %+v, want only INVITE#%s", invites, mineID)
	}
	if invites[0].InviterUserID != inviterUserID || invites[0].GroupID != groupID {
		t.Errorf("received invite = %+v, want inviter/group carried through", invites[0])
	}
}

// DynamoDB sweeps the two rows of an accepted invite independently once the
// shared completion-deadline TTL passes, so the sent list must not depend on
// the INVITE# row for an accepted invite (PR #154 review).
func TestListSentInvitesKeepsAcceptedWhenInviteRowSwept(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	inviterUserID := "test-inviter-" + randomSuffix(t)
	inviteID := "test-invite-" + randomSuffix(t)
	if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, "test-group-"+randomSuffix(t), inviterUserID, time.Now().Add(7*24*time.Hour))); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, "test-invitee-"+randomSuffix(t))); err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}
	if _, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "INVITE#" + inviteID},
			"SK": &types.AttributeValueMemberS{Value: "META"},
		},
	}); err != nil {
		t.Fatalf("simulating INVITE# sweep: %v", err)
	}

	views, err := c.ListSentInvites(ctx, inviterUserID, time.Now())
	if err != nil {
		t.Fatalf("ListSentInvites: %v", err)
	}
	if len(views) != 1 || views[0].InviteID != inviteID || views[0].InvitedUserID == "" {
		t.Fatalf("ListSentInvites = %+v, want the accepted invite still listed", views)
	}
}
