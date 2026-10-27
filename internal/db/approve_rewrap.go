package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

var (
	// ErrRekeyRequired: the member's entry is at the generation the approver
	// holds, so the keys they rotated away from still read the group. A plain
	// wrap would show them as current while the old keys keep working; only
	// the admin's re-key (a new generation) closes that (docs/DESIGN.md,
	// "Approval: what the admin does, and when it mints"). Nothing written.
	ErrRekeyRequired = errors.New("db: the member's entry is at the current generation; a re-key is required")
	// ErrMemberNotDormant: the member's entry is already wrapped to their
	// current key (WrapEpoch has caught up with KeyEpoch), so there is nothing
	// to approve.
	ErrMemberNotDormant = errors.New("db: the member is not dormant")
)

// ApproveRewrapInput is one approver's plain wrap of the group's current key to
// a dormant member's new key.
type ApproveRewrapInput struct {
	GroupID        string
	ApproverUserID string
	MemberUserID   string
	// Generation is the generation of the key wrapped: the approver's own
	// entry point must be at it, and it is the marker's when one exists.
	Generation int64
	Wrapped    models.WrappedKey
	// KeyEpoch is the member's KeyEpoch the wrap was made to. It must still be
	// their current epoch (checked in the transaction) and is stored as the
	// entry's WrapEpoch, which is what un-dormants them.
	KeyEpoch uint64
	// Open is true for an Open group, which has no re-key: the member may be
	// at the approver's generation (the wrap then replaces the old-key copy).
	// A Rotating group needs the member strictly behind, or it answers
	// ErrRekeyRequired.
	Open bool
	// WrapRecord is the approver's signed record of this wrap, or nil from a
	// client that signs none.
	WrapRecord *WrapRecord
}

// ApproveRewrap writes a dormant member's wrap, generation and WrapEpoch in one
// transaction, enforcing the mint rule itself so a client, old or buggy, cannot
// approve with a plain wrap while the old keys hold the current key. The
// approver is an admin or ambassador at Generation; a marker, if present, must
// name Generation (the same read-then-pin as RewrapMembers).
func (c *Client) ApproveRewrap(ctx context.Context, in ApproveRewrapInput) error {
	const (
		markerIndex  = 0
		callerIndex  = 1
		memberIndex  = 2
		profileIndex = 3
	)
	if in.ApproverUserID == in.MemberUserID {
		return fmt.Errorf("db: approve rewrap: the approver is the member")
	}
	marker, err := c.GetRotation(ctx, in.GroupID)
	if err != nil {
		return err
	}
	if marker != nil && marker.Generation != in.Generation {
		return ErrRotationNotActive
	}
	wrapped, err := attributevalue.Marshal(in.Wrapped)
	if err != nil {
		return err
	}
	genCond := "#gen < :gen"
	if in.Open {
		genCond = "#gen <= :gen"
	}
	items := []types.TransactWriteItem{
		c.markerCheck(in.GroupID, in.Generation, marker != nil),
		{ConditionCheck: &types.ConditionCheck{
			TableName:                aws.String(c.table),
			Key:                      memberKey(in.GroupID, in.ApproverUserID),
			ConditionExpression:      aws.String("(#role = :admin OR #role = :ambassador) AND #gen = :gen"),
			ExpressionAttributeNames: map[string]string{"#role": "Role", "#gen": "Generation"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":admin":      &types.AttributeValueMemberS{Value: models.RoleAdmin},
				":ambassador": &types.AttributeValueMemberS{Value: models.RoleAmbassador},
				":gen":        genAttr(in.Generation),
			},
		}},
		{Update: &types.Update{
			TableName:        aws.String(c.table),
			Key:              memberKey(in.GroupID, in.MemberUserID),
			UpdateExpression: aws.String("SET #gen = :gen, #wrapped = :wrapped, WrapEpoch = :kep"),
			// An account that never rotated (KeyEpoch 0) cannot be dormant,
			// which is what ":kep > :zero" keeps an absent WrapEpoch from
			// reading as.
			ConditionExpression: aws.String("attribute_exists(PK) AND " + genCond +
				" AND ((attribute_not_exists(WrapEpoch) AND :kep > :zero) OR WrapEpoch < :kep)"),
			ExpressionAttributeNames: map[string]string{"#gen": "Generation", "#wrapped": "WrappedGroupKey"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":gen":     genAttr(in.Generation),
				":wrapped": wrapped,
				":kep":     epochAttr(in.KeyEpoch),
				":zero":    epochAttr(0),
			},
		}},
		c.keyEpochCheck(in.MemberUserID, in.KeyEpoch),
	}
	applyWrapRecord(items[memberIndex].Update, in.WrapRecord)
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		switch {
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		case isConditionalCheckFailure(err, profileIndex):
			// A deleted account is a member that went away; otherwise the
			// member rotated again since the approver read their keys.
			deleted, derr := c.whyProfileCheckFailed(ctx, in.MemberUserID)
			if derr != nil {
				return derr
			}
			if deleted {
				return ErrRewrapMemberChanged
			}
			return ErrWrapEpochStale
		case isConditionalCheckFailure(err, markerIndex):
			return ErrRotationNotActive
		case isConditionalCheckFailure(err, callerIndex):
			return ErrRewrapCallerBehind
		case isConditionalCheckFailure(err, memberIndex):
			return c.whyApproveFailed(ctx, in)
		}
		return err
	}
	return nil
}

// whyApproveFailed reads the member back to say which clause of the update's
// condition failed.
func (c *Client) whyApproveFailed(ctx context.Context, in ApproveRewrapInput) error {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(c.table),
		Key:            memberKey(in.GroupID, in.MemberUserID),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("db: read member after approve: %w", err)
	}
	if out.Item == nil {
		return ErrRewrapMemberChanged
	}
	var m models.Membership
	if err := attributevalue.UnmarshalMap(out.Item, &m); err != nil {
		return fmt.Errorf("db: unmarshal member after approve: %w", err)
	}
	switch {
	case m.Generation > in.Generation:
		return ErrRewrapMemberChanged
	case m.WrapEpoch >= in.KeyEpoch:
		return ErrMemberNotDormant
	default:
		// Dormant and not past the generation, yet refused: only a Rotating
		// group's "strictly behind" can have said no.
		return ErrRekeyRequired
	}
}
