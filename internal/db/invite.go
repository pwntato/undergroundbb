package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// GetMembership reads one member's own GROUP#<gid>/MEMBER#<uuid> item, or
// nil if the caller is not a member -- the plain GetItem docs/DESIGN.md
// describes as the hot-path role check ("the current role lives on the
// membership item and gates writes... with a plain GetItem"). Used by
// createInvite (issue #38) to check the caller holds Admin or Ambassador
// before letting them invite anyone.
func (c *Client) GetMembership(ctx context.Context, groupID, userID string) (*models.Membership, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + userID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("db: get membership: %w", err)
	}
	if out.Item == nil {
		return nil, nil
	}
	var m models.Membership
	if err := attributevalue.UnmarshalMap(out.Item, &m); err != nil {
		return nil, fmt.Errorf("db: unmarshal membership: %w", err)
	}
	return &m, nil
}

// CreateInviteInput is everything CreateInvite needs to write a new invite's
// two rows. InviteID is client-generated -- like GroupID and
// RootGrantSortKey before it, the client must know the real invite id before
// it signs CreationSignature (crypto.InviteCreationPayload binds it), which
// is before the server could ever assign one.
type CreateInviteInput struct {
	InviteID string
	GroupID  string

	InviterUserID           string
	InviterSigningPublicKey []byte
	// CreationSignature is crypto.Sign(inviterPriv, ContextInvite,
	// crypto.InviteCreationPayload(inviteID, groupID, inviterSigningPublicKey,
	// expiresAt)). This package does not verify it -- see CreateInvite's own
	// doc comment for why that belongs in the handler, matching every other
	// signature this package stores without checking.
	CreationSignature []byte

	// ExpiresAt is the EXACT RFC 3339 string the inviter signed (the wire
	// request's own expiresAt field, byte-for-byte) -- stored verbatim as
	// models.Invite.ExpiresAt and never reformatted, because
	// crypto.InviteCreationPayload signs this string's bytes, not any
	// parsed/re-rendered value derived from it. A real bug this comment
	// exists to prevent recurring: time.Time.Format(time.RFC3339) drops
	// sub-second precision, so re-deriving this field from a parsed
	// time.Time (e.g. a client's real toISOString(), which always carries
	// milliseconds) silently produces a DIFFERENT string than the one that
	// was signed -- acceptInvite's later re-verification of
	// CreationSignature against the stored ExpiresAt would then fail for
	// every real invite, caught live against the actual browser UI, not
	// by any unit test using a fixed, millisecond-free fixture string.
	ExpiresAt string
	// ExpiresAtParsed is ExpiresAt, already parsed by the caller (the
	// handler validates it as a well-formed RFC 3339 timestamp before this
	// call) -- used only for TTL arithmetic (RoundUpToEndOfUTCDay), which
	// needs a time.Time and has no reason to duplicate ExpiresAt's own
	// parsing.
	ExpiresAtParsed time.Time
}

// ErrInviteIDTaken is returned when the INVITE#<iid> META item already
// exists -- InviteID is client-generated (CreateInviteInput's own doc
// comment), so like ErrGroupIDTaken and ErrUserIDTaken before it, this
// package cannot assume it is collision-free.
var ErrInviteIDTaken = errors.New("db: invite id taken")

// CreateInvite writes a new invite's two rows -- INVITE#<iid>/META (no GSI1
// entry: an invite has no invitee identity until acceptance, see
// models.Invite's own doc comment) and the inviter's own USER#<inviter>/
// SENT#<iid> copy -- as one TransactWriteItems, for the same partial-write
// reasoning CreateGroup's own doc comment gives: an interruption must not
// leave the inviter's own copy missing (which would make step 3 unable to
// ever discover this invite) or the INVITE# row missing (which would make
// the link the inviter is about to hand out simply not work).
//
// The INVITE# write is conditional on attribute_not_exists(PK), matching
// GroupID/UserID's own reasoning for a client-chosen id this package cannot
// assume is collision-free. Unlike CreateGroup, this package does NOT check
// for a lost-response retry on conflict (isOwnGroupCreation's own pattern)
// -- an invite carries no long-lived identity a client would resend
// identically the way a signup or group creation does; a genuine InviteID
// collision is treated as a plain conflict.
func (c *Client) CreateInvite(ctx context.Context, in CreateInviteInput) error {
	now := time.Now().UTC().Format(time.RFC3339)
	// The stored TTL is ExpiresAtParsed rounded up to the end of its UTC
	// day, per the global TTL-rounding rule (RoundUpToEndOfUTCDay's own
	// doc comment) -- the TTL attribute is a separate numeric field from
	// the stored ExpiresAt string below, so rounding IT costs nothing; see
	// CreateInviteInput.ExpiresAt's own doc comment for why the STRING
	// itself must never be reformatted.
	ttl := RoundUpToEndOfUTCDay(in.ExpiresAtParsed).Unix()

	invite := models.Invite{
		Record: models.Record{
			PK:        "INVITE#" + in.InviteID,
			SK:        "META",
			Type:      "Invite",
			CreatedAt: now,
		},
		TTL:                     ttl,
		GroupID:                 in.GroupID,
		InviterUserID:           in.InviterUserID,
		InviterSigningPublicKey: in.InviterSigningPublicKey,
		CreationSignature:       in.CreationSignature,
		// Stored VERBATIM -- see CreateInviteInput.ExpiresAt's own doc
		// comment for why this must never be re-derived from
		// ExpiresAtParsed via .Format().
		ExpiresAt: in.ExpiresAt,
	}
	sent := models.SentInvite{
		Record: models.Record{
			PK:        "USER#" + in.InviterUserID,
			SK:        "SENT#" + in.InviteID,
			Type:      "SentInvite",
			CreatedAt: now,
		},
		TTL:      ttl,
		GroupID:  in.GroupID,
		InviteID: in.InviteID,
	}

	inviteItem, err := attributevalue.MarshalMap(invite)
	if err != nil {
		return err
	}
	sentItem, err := attributevalue.MarshalMap(sent)
	if err != nil {
		return err
	}

	const inviteItemIndex = 0

	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{
				Put: &types.Put{
					TableName:           aws.String(c.table),
					Item:                inviteItem,
					ConditionExpression: aws.String("attribute_not_exists(PK)"),
				},
			},
			{Put: &types.Put{TableName: aws.String(c.table), Item: sentItem}},
		},
	})
	if err != nil {
		if isConditionalCheckFailure(err, inviteItemIndex) {
			return ErrInviteIDTaken
		}
		return err
	}
	return nil
}

// GetInvite reads the INVITE#<iid>/META item, or nil if it does not exist
// (never created, or its TTL has already swept it -- see
// models.Invite's own doc comment on why an expired-but-not-yet-deleted row
// must additionally be checked by the caller, not just relied on here).
// Unauthenticated by design (GET /api/invites/:id) -- this method itself
// enforces no authorization, matching this package's usual "db is a pure
// data-access layer" split.
func (c *Client) GetInvite(ctx context.Context, inviteID string) (*models.Invite, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "INVITE#" + inviteID},
			"SK": &types.AttributeValueMemberS{Value: "META"},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("db: get invite: %w", err)
	}
	if out.Item == nil {
		return nil, nil
	}
	var invite models.Invite
	if err := attributevalue.UnmarshalMap(out.Item, &invite); err != nil {
		return nil, fmt.Errorf("db: unmarshal invite: %w", err)
	}
	return &invite, nil
}

// completionDeadlineDuration bounds how long an accepted invite waits for
// step 3 (the inviter's next login) before the deadline docs/DESIGN.md's
// round-25 comment requires is considered passed -- surfaced by #83, not
// enforced as a deletion by this package (see AcceptInvite's own doc
// comment). A week gives an inviter who is briefly away a real chance to
// complete the handshake without indefinitely extending the "who did this
// account approach" disclosure window THREAT_MODEL treats as the more
// sensitive half.
const completionDeadlineDuration = 7 * 24 * time.Hour

// ErrInviteNotFound is returned by AcceptInvite when the INVITE#<iid> row
// does not exist -- never created, or already swept by TTL.
var ErrInviteNotFound = errors.New("db: invite not found")

// ErrInviteExpired is returned by AcceptInvite when the invite's signed
// ExpiresAt has passed but the row has not yet been TTL-deleted -- TTL
// deletion is eventual, never immediate, so this read-time check is what
// actually enforces the signed lifetime; see models.Invite.ExpiresAt's own
// doc comment and issue #39's own comments: "This read-time check is a
// security control, not a display convenience."
var ErrInviteExpired = errors.New("db: invite expired")

// ErrInviteAlreadyAccepted is returned by AcceptInvite when the invite's
// InvitedUserID is already set -- see models.Invite.InvitedUserID's own doc
// comment: this is what makes acceptance single-use, closing the "second
// holder of the same link" gap issue #39's blocking review comment
// describes.
var ErrInviteAlreadyAccepted = errors.New("db: invite already accepted")

// AcceptInviteInput is everything AcceptInvite needs. InviteID is the
// bearer token the invitee presents (from the URL); the rest is the
// invitee's own signed step-2 material.
type AcceptInviteInput struct {
	InviteID string

	InvitedUserID           string
	InvitedEd25519PublicKey []byte
	InvitedX25519PublicKey  []byte
	// AcceptanceSignature is crypto.Sign(inviteePriv, ContextInvite,
	// crypto.InviteAcceptancePayload(inviteID, invitedEd25519PublicKey,
	// invitedX25519PublicKey)). Verified by the handler before this call,
	// alongside CreationSignature -- see AcceptInvite's own doc comment.
	AcceptanceSignature []byte
}

// AcceptInvite implements step 2 of the invite handshake (issue #39): sets
// the invitee's identity and signed keys on BOTH the INVITE#<iid> row and
// the inviter's USER#<inviter>/SENT#<iid> copy, and replaces both rows'
// signed-expiry TTL with a completion deadline -- one TransactWriteItems
// across the two partitions, server-composed and server-authorized (the
// invitee supplies only InviteID; this package is what looks up
// in.GroupID/InviterUserID from the stored INVITE# row and addresses the
// SENT# row itself -- an invitee must never be able to name a row in the
// inviter's own partition directly, which also holds their PROFILE,
// RECOVERY, CHALLENGE and PIN# items).
//
// The INVITE# write is conditional on attribute_not_exists(InvitedUserID)
// -- the single-use guarantee issue #39's blocking review comment requires:
// without it, a second holder of the same link accepting after the intended
// invitee would silently rename who step 3 wraps the group key to, with the
// signature still verifying (they did sign their own keys) and the original
// invitee never keyed. A conflict here returns ErrInviteAlreadyAccepted.
//
// This package does not itself verify AcceptanceSignature or re-check
// ExpiresAt against now -- both are the handler's job, in the order issue
// #39 requires (signature first, then expiry), matching CreateGroup's own
// "db is a pure data-access layer" split. Callers must have already done
// both before calling this.
//
// The TTL swap does NOT delete either row at the deadline -- see #83
// ("Surface invites accepted but never completed"), a separate issue that
// covers making a passed deadline visible to both parties rather than
// silently sweeping it, which this package has no part in.
func (c *Client) AcceptInvite(ctx context.Context, in AcceptInviteInput) error {
	invite, err := c.GetInvite(ctx, in.InviteID)
	if err != nil {
		return err
	}
	if invite == nil {
		return ErrInviteNotFound
	}

	now := time.Now()
	deadline := RoundUpToEndOfUTCDay(now.Add(completionDeadlineDuration))
	deadlineTTL := deadline.Unix()

	// TTL is a DynamoDB reserved keyword and cannot appear literally in an
	// UpdateExpression -- aliased via ExpressionAttributeNames, matching
	// credentials.go's own "#V" -> "Verifier" precedent for the same
	// reason.
	inviteUpdate := &types.Update{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "INVITE#" + in.InviteID},
			"SK": &types.AttributeValueMemberS{Value: "META"},
		},
		UpdateExpression:         aws.String("SET InvitedUserID = :uid, InvitedEd25519PublicKey = :ed, InvitedX25519PublicKey = :x, AcceptanceSignature = :sig, #TTL = :ttl, GSI1PK = :gsi1pk, GSI1SK = :gsi1sk"),
		ConditionExpression:      aws.String("attribute_not_exists(InvitedUserID)"),
		ExpressionAttributeNames: map[string]string{"#TTL": "TTL"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":uid":    &types.AttributeValueMemberS{Value: in.InvitedUserID},
			":ed":     &types.AttributeValueMemberB{Value: in.InvitedEd25519PublicKey},
			":x":      &types.AttributeValueMemberB{Value: in.InvitedX25519PublicKey},
			":sig":    &types.AttributeValueMemberB{Value: in.AcceptanceSignature},
			":ttl":    &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", deadlineTTL)},
			":gsi1pk": &types.AttributeValueMemberS{Value: "USER#" + in.InvitedUserID},
			":gsi1sk": &types.AttributeValueMemberS{Value: "INVITE#" + inviteDaySuffix(now)},
		},
	}

	sentUpdate := &types.Update{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + invite.InviterUserID},
			"SK": &types.AttributeValueMemberS{Value: "SENT#" + in.InviteID},
		},
		UpdateExpression:         aws.String("SET InvitedUserID = :uid, InvitedEd25519PublicKey = :ed, InvitedX25519PublicKey = :x, AcceptanceSignature = :sig, #TTL = :ttl"),
		ExpressionAttributeNames: map[string]string{"#TTL": "TTL"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":uid": &types.AttributeValueMemberS{Value: in.InvitedUserID},
			":ed":  &types.AttributeValueMemberB{Value: in.InvitedEd25519PublicKey},
			":x":   &types.AttributeValueMemberB{Value: in.InvitedX25519PublicKey},
			":sig": &types.AttributeValueMemberB{Value: in.AcceptanceSignature},
			":ttl": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", deadlineTTL)},
		},
	}

	const inviteItemIndex = 0

	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Update: inviteUpdate},
			{Update: sentUpdate},
		},
	})
	if err != nil {
		if isConditionalCheckFailure(err, inviteItemIndex) {
			return ErrInviteAlreadyAccepted
		}
		return err
	}
	return nil
}

// inviteDaySuffix generates the GSI1SK day component for an accepted
// invite's GSI1 entry ("INVITE#<YYYY-MM-DD, UTC>#<rand>", added at
// acceptance -- models.Invite's own doc comment), using the moment of
// acceptance (now), not the completion deadline -- the GSI1SK's day is meant
// to disclose (at day resolution) when the invitee was invited/accepted, the
// same "association" timing THREAT_MODEL discusses, which is a distinct
// moment from the deadline the TTL attribute separately tracks.
func inviteDaySuffix(now time.Time) string {
	s, err := idgen.DaySuffix(now)
	if err != nil {
		// idgen.DaySuffix's only failure mode is rand.Read failing, which
		// this codebase treats as unrecoverable everywhere else it appears
		// (idgen.UUID, group.ts's generateGrantSortKey has no server-side
		// equivalent that tolerates it either) -- panicking here matches
		// that standard rather than silently degrading the GSI1SK's
		// collision-avoidance suffix.
		panic(fmt.Sprintf("db: generate invite day suffix: %v", err))
	}
	return s
}

// PendingInviteCompletions queries the caller's own USER#<inviter>/SENT#
// partition for invites that have been accepted and are awaiting step 3 --
// "the next time the inviter's client is online" query docs/DESIGN.md
// describes, the one thing that makes step 3 discoverable at all (neither
// INVITE#<iid> nor a GSI keyed to the invitee can answer it -- see
// models.SentInvite's own doc comment). Only rows with InvitedUserID set are
// returned: a SENT# row for an invite nobody has accepted yet has nothing
// for this client to complete, and is filtered out here rather than pushed
// onto every caller of this method to re-check.
//
// This is a plain Query on PK + begins_with(SK, "SENT#"), not a GSI Query --
// the inviter's own partition is the natural home for "my pending work,"
// matching db.go's package doc comment that query construction stays
// confined to this package. Paginates on LastEvaluatedKey, matching
// queryMembershipsByUser's own reasoning: a user's own pending-invite count,
// not the table, is the number that could in principle exceed one page.
func (c *Client) PendingInviteCompletions(ctx context.Context, inviterUserID string) ([]models.SentInvite, error) {
	var pending []models.SentInvite
	var startKey map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
			FilterExpression:       aws.String("attribute_exists(InvitedUserID)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "USER#" + inviterUserID},
				":sk": &types.AttributeValueMemberS{Value: "SENT#"},
			},
			ExclusiveStartKey: startKey,
		})
		if err != nil {
			return nil, fmt.Errorf("db: query pending invite completions: %w", err)
		}
		var page []models.SentInvite
		if err := attributevalue.UnmarshalListOfMaps(out.Items, &page); err != nil {
			return nil, fmt.Errorf("db: unmarshal pending invite completions: %w", err)
		}
		pending = append(pending, page...)
		if out.LastEvaluatedKey == nil {
			break
		}
		startKey = out.LastEvaluatedKey
	}
	return pending, nil
}

// CompleteInviteInput is everything CompleteInvite needs to finish step 3:
// grant the now-accepted invitee membership in the group, wrapped to the
// keys they signed at step 2.
type CompleteInviteInput struct {
	InviteID string
	GroupID  string
	// InviterUserID addresses this invite's own USER#<inviter>/SENT#<iid>
	// row for deletion -- the caller (the inviter's own authenticated
	// session) IS this user, so this is never attacker-influenced the way
	// an invitee-supplied field would be; it comes from
	// PendingInviteCompletions' own result (each models.SentInvite's PK),
	// not from request input the handler trusts blindly.
	InviterUserID string

	InvitedUserID string
	// Generation and WrappedGroupKey are the invitee's own entry point to
	// the group key, exactly like CreateGroupInput.GenerationKeyWrapped --
	// wrapped client-side (the inviter's browser, which alone holds the
	// group key in plaintext) to the invitee's signed X25519 public key,
	// per docs/DESIGN.md: "wraps the group key to the X25519 key that was
	// signed in step 2 -- never to a key the server offers unilaterally."
	Generation      int64
	WrappedGroupKey models.WrappedKey
	// Role is the role this membership is created with -- RoleMember for an
	// ordinary invite (this issue does not build role-at-invite-time
	// selection; #37's grant chain is what changes a role after the fact).
	Role string
}

// ErrInviteAlreadyCompleted is returned by CompleteInvite when the
// SENT#<iid> row this call expected to find and delete is already gone --
// another of the inviter's own sessions (two tabs, two devices) completed
// this same invite first. Not an error the caller needs to alarm about: the
// membership this call would have created already exists.
var ErrInviteAlreadyCompleted = errors.New("db: invite already completed")

// ErrAlreadyMember is returned by CompleteInvite when the invitee already
// holds a GROUP#<gid>/MEMBER#<uuid> item -- e.g. re-invited into a group
// they already joined some other way between acceptance and completion. See
// CompleteInvite's own doc comment for why the membership Put is
// conditional rather than a plain overwrite.
var ErrAlreadyMember = errors.New("db: invitee is already a member")

// CompleteInvite implements step 3 of the invite handshake (issue #40):
// writes the invitee's GROUP#<gid>/MEMBER#<uuid> membership and deletes both
// the INVITE#<iid> and USER#<inviter>/SENT#<iid> rows, as one
// TransactWriteItems -- matching CreateGroup's own partial-write reasoning:
// an interruption must not leave a membership without its SENT# row cleared
// (which would make this same invite look pending forever, and re-running
// this call would then try to create a duplicate membership) or a cleared
// SENT# row without the membership actually written (which would silently
// drop the invitee's group key with no remaining record anything was ever
// pending).
//
// The membership Put is conditional on attribute_not_exists(PK) -- the
// invitee could conceivably already be a member (e.g. re-invited into a
// group they already joined some other way), and a plain overwrite would
// silently replace an existing membership's role/generation with whatever
// this invite happened to grant. The SENT# delete is conditional on the
// item existing at all, which is what makes a second, redundant completion
// attempt (two tabs) fail loudly (ErrInviteAlreadyCompleted) rather than
// double-writing the membership Put's own condition would otherwise mask as
// a plain, unexplained failure.
//
// This package does not verify AcceptanceSignature here -- see AcceptInvite
// and CreateGroup's own doc comments for why: the caller (the inviter's own
// browser, per docs/DESIGN.md, is the party whose verification of this
// signature is what actually protects the handshake) is expected to have
// already checked it against the stored invite before ever calling this,
// using the SAME data PendingInviteCompletions returned.
func (c *Client) CompleteInvite(ctx context.Context, in CompleteInviteInput) error {
	now := time.Now().UTC().Format(time.RFC3339)

	membership := models.Membership{
		Record: models.Record{
			PK:        "GROUP#" + in.GroupID,
			SK:        "MEMBER#" + in.InvitedUserID,
			Type:      "Membership",
			CreatedAt: now,
			GSI1PK:    "USER#" + in.InvitedUserID,
			GSI1SK:    "GROUP#" + in.GroupID,
		},
		Role:            in.Role,
		Generation:      in.Generation,
		WrappedGroupKey: in.WrappedGroupKey,
	}
	membershipItem, err := attributevalue.MarshalMap(membership)
	if err != nil {
		return err
	}

	const (
		membershipItemIndex = 0
		sentDeleteIndex     = 2
	)

	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{
				Put: &types.Put{
					TableName:           aws.String(c.table),
					Item:                membershipItem,
					ConditionExpression: aws.String("attribute_not_exists(PK)"),
				},
			},
			{
				Delete: &types.Delete{
					TableName: aws.String(c.table),
					Key: map[string]types.AttributeValue{
						"PK": &types.AttributeValueMemberS{Value: "INVITE#" + in.InviteID},
						"SK": &types.AttributeValueMemberS{Value: "META"},
					},
				},
			},
			{
				Delete: &types.Delete{
					TableName: aws.String(c.table),
					Key: map[string]types.AttributeValue{
						"PK": &types.AttributeValueMemberS{Value: "USER#" + in.InviterUserID},
						"SK": &types.AttributeValueMemberS{Value: "SENT#" + in.InviteID},
					},
					ConditionExpression: aws.String("attribute_exists(PK)"),
				},
			},
		},
	})
	if err != nil {
		if isConditionalCheckFailure(err, membershipItemIndex) {
			return ErrAlreadyMember
		}
		if isConditionalCheckFailure(err, sentDeleteIndex) {
			return ErrInviteAlreadyCompleted
		}
		return err
	}
	return nil
}
