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

	"github.com/pwntato/undergroundbb/internal/models"
)

var (
	// ErrRekeyNotRequired: the member's entry is behind the admin's
	// generation, so the old keys do not hold the current key and a plain wrap
	// (POST rewrap/{uid}) approves them without minting. The mirror of
	// ErrRekeyRequired. Nothing written.
	ErrRekeyNotRequired = errors.New("db: the member's entry is behind the current generation; a plain wrap suffices")
	// ErrCallerKeyEpochStale: the admin's own keys were rotated by another
	// request since the handler read them.
	ErrCallerKeyEpochStale = errors.New("db: the caller's keys changed")
)

// ApproveRekeyInput is the rotation an admin starts to approve a dormant
// member's new keys when the member's entry is still at the admin's
// generation (docs/DESIGN.md, "Approval: what the admin does, and when it
// mints"). No one is removed.
type ApproveRekeyInput struct {
	GroupID      string
	AdminUserID  string
	MemberUserID string
	// CurrentGeneration is the admin's own entry-point generation, and the
	// member's: the rotation goes to CurrentGeneration+1.
	CurrentGeneration int64
	Link              models.WrappedBlob
	AdminWrappedKey   models.WrappedKey
	// AdminKeyEpoch is the admin's KeyEpoch as the handler read it; it becomes
	// their WrapEpoch and is checked against PROFILE in the same transaction.
	AdminKeyEpoch uint64
	// MemberWrappedKey is the new key wrapped to the member's new X25519 key,
	// and MemberKeyEpoch the KeyEpoch of that key.
	MemberWrappedKey models.WrappedKey
	MemberKeyEpoch   uint64
	Reason           string
	StartSignature   []byte
}

// ApproveRekey starts a rotation that removes no one and, in the same
// transaction, writes the approved member's entry at the new generation.
// RewrapMembers refuses a dormant member, so without this the ordinary job
// could never reach them. One transaction: the marker (none may exist), the
// GENKEY# link, the admin's entry, the admin's key-epoch check, the member's
// entry (dormant, at the admin's generation) and the member's key-epoch check.
func (c *Client) ApproveRekey(ctx context.Context, in ApproveRekeyInput) error {
	if in.AdminUserID == in.MemberUserID {
		return fmt.Errorf("db: approve rekey: the admin is the member")
	}
	const (
		markerIndex      = 0
		linkIndex        = 1
		adminIndex       = 2
		adminEpochIndex  = 3
		memberIndex      = 4
		memberEpochIndex = 5
	)
	now := time.Now().UTC().Format(time.RFC3339)
	marker, err := attributevalue.MarshalMap(models.Rotation{
		Record:         models.Record{PK: "GROUP#" + in.GroupID, SK: RotationSortKey, Type: "Rotation"},
		Generation:     in.CurrentGeneration + 1,
		StartedAt:      now,
		StartedBy:      in.AdminUserID,
		RekeyedUserID:  in.MemberUserID,
		RekeyReason:    in.Reason,
		StartSignature: in.StartSignature,
	})
	if err != nil {
		return err
	}
	link, err := attributevalue.MarshalMap(models.GenerationKey{
		Record:         models.Record{PK: "GROUP#" + in.GroupID, SK: GenKeySortKey(in.CurrentGeneration), Type: "GenerationKey"},
		Wrapped:        in.Link,
		RemoverUserID:  in.AdminUserID,
		RekeyedUserID:  in.MemberUserID,
		RekeyReason:    in.Reason,
		StartSignature: in.StartSignature,
	})
	if err != nil {
		return err
	}
	adminWrapped, err := attributevalue.Marshal(in.AdminWrappedKey)
	if err != nil {
		return err
	}
	memberWrapped, err := attributevalue.Marshal(in.MemberWrappedKey)
	if err != nil {
		return err
	}
	items := []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(c.table), Item: marker, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Put: &types.Put{TableName: aws.String(c.table), Item: link, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Update: &types.Update{
			TableName:                aws.String(c.table),
			Key:                      memberKey(in.GroupID, in.AdminUserID),
			ConditionExpression:      aws.String("#role = :admin AND #gen = :cur"),
			UpdateExpression:         aws.String("SET #gen = :next, #wrapped = :wrapped, WrapEpoch = :wep"),
			ExpressionAttributeNames: map[string]string{"#role": "Role", "#gen": "Generation", "#wrapped": "WrappedGroupKey"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":admin":   &types.AttributeValueMemberS{Value: models.RoleAdmin},
				":cur":     genAttr(in.CurrentGeneration),
				":next":    genAttr(in.CurrentGeneration + 1),
				":wrapped": adminWrapped,
				":wep":     epochAttr(in.AdminKeyEpoch),
			},
		}},
		c.keyEpochCheck(in.AdminUserID, in.AdminKeyEpoch),
		{Update: &types.Update{
			TableName:        aws.String(c.table),
			Key:              memberKey(in.GroupID, in.MemberUserID),
			UpdateExpression: aws.String("SET #gen = :next, #wrapped = :wrapped, WrapEpoch = :wep"),
			// Dormant (and an account that never rotated is not), and at the
			// generation the admin holds: the old keys still read the group.
			ConditionExpression: aws.String("attribute_exists(PK) AND #gen = :cur" +
				" AND ((attribute_not_exists(WrapEpoch) AND :wep > :zero) OR WrapEpoch < :wep)"),
			ExpressionAttributeNames: map[string]string{"#gen": "Generation", "#wrapped": "WrappedGroupKey"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":cur":     genAttr(in.CurrentGeneration),
				":next":    genAttr(in.CurrentGeneration + 1),
				":wrapped": memberWrapped,
				":wep":     epochAttr(in.MemberKeyEpoch),
				":zero":    epochAttr(0),
			},
		}},
		c.keyEpochCheck(in.MemberUserID, in.MemberKeyEpoch),
	}
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		switch {
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		case isConditionalCheckFailure(err, markerIndex):
			return ErrRotationInProgress
		case isConditionalCheckFailure(err, linkIndex), isConditionalCheckFailure(err, adminIndex):
			// A link at the admin's generation means the group moved on.
			return ErrRewrapCallerBehind
		case isConditionalCheckFailure(err, adminEpochIndex):
			return ErrCallerKeyEpochStale
		case isConditionalCheckFailure(err, memberEpochIndex):
			deleted, derr := c.whyProfileCheckFailed(ctx, in.MemberUserID)
			if derr != nil {
				return derr
			}
			if deleted {
				return ErrRewrapMemberChanged
			}
			return ErrWrapEpochStale
		case isConditionalCheckFailure(err, memberIndex):
			return c.whyApproveRekeyFailed(ctx, in)
		}
		return err
	}
	return nil
}

// whyApproveRekeyFailed reads the member back to say which clause failed.
func (c *Client) whyApproveRekeyFailed(ctx context.Context, in ApproveRekeyInput) error {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(c.table),
		Key:            memberKey(in.GroupID, in.MemberUserID),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("db: read member after approve rekey: %w", err)
	}
	if out.Item == nil {
		return ErrRewrapMemberChanged
	}
	var m models.Membership
	if err := attributevalue.UnmarshalMap(out.Item, &m); err != nil {
		return fmt.Errorf("db: unmarshal member after approve rekey: %w", err)
	}
	switch {
	case m.Generation > in.CurrentGeneration:
		return ErrRewrapMemberChanged
	case m.WrapEpoch >= in.MemberKeyEpoch:
		return ErrMemberNotDormant
	case m.Generation < in.CurrentGeneration:
		return ErrRekeyNotRequired
	default:
		return ErrRoleChangeConflict
	}
}
