package db

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// ErrHandoffStale: the caller's handoff row for the group is missing, names a
// key other than the account's current one, holds a generation other than the
// caller's own entry point's, or the group has moved past the generation the row
// was written at (a dormant admin's row still equals their entry). Nothing was
// written; the client deletes the row.
var ErrHandoffStale = errors.New("db: the handoff row is missing or stale")

// SelfRekeyInput is the rotation an admin starts to bring their own entry
// point to their new X25519 key after rotating their keys (#62). No member
// leaves, so there is no removed subject.
type SelfRekeyInput struct {
	GroupID      string
	CallerUserID string
	// CurrentGeneration is the caller's own entry-point generation; the
	// rotation goes to CurrentGeneration+1.
	CurrentGeneration int64
	Link              models.WrappedBlob
	CallerWrappedKey  models.WrappedKey
	// CallerKeyEpoch is the caller's KeyEpoch as the handler read it; it
	// becomes their WrapEpoch and is checked against PROFILE in the same
	// transaction.
	CallerKeyEpoch uint64
	// CallerWrappingKey is the caller's current X25519 public key: the handoff
	// row must name it.
	CallerWrappingKey []byte
	Reason            string
	StartSignature    []byte
}

// SelfRekey starts a rotation that removes no one, as the caller, and consumes
// their handoff row for the group in the same transaction (docs/DESIGN.md,
// "The self re-key must survive a closed tab"). The row must exist, name the
// caller's current wrapping key and hold the generation the caller's entry is
// at, otherwise ErrHandoffStale and nothing is written.
//
// One transaction: the marker (conditioned on there being none), the GENKEY#
// link for the caller's generation (it must not exist yet), the caller's entry
// point moved to the new key (admin, at the generation the request was built
// against), the key-epoch check, and the row's delete.
func (c *Client) SelfRekey(ctx context.Context, in SelfRekeyInput) error {
	const (
		markerIndex = 0
		linkIndex   = 1
		callerIndex = 2
		epochIndex  = 3
		rowIndex    = 4
	)
	now := time.Now().UTC().Format(time.RFC3339)
	marker, err := attributevalue.MarshalMap(models.Rotation{
		Record: models.Record{
			PK:   "GROUP#" + in.GroupID,
			SK:   RotationSortKey,
			Type: "Rotation",
		},
		Generation:     in.CurrentGeneration + 1,
		StartedAt:      now,
		StartedBy:      in.CallerUserID,
		RekeyedUserID:  in.CallerUserID,
		RekeyReason:    in.Reason,
		StartSignature: in.StartSignature,
	})
	if err != nil {
		return err
	}
	link, err := attributevalue.MarshalMap(models.GenerationKey{
		Record: models.Record{
			PK:   "GROUP#" + in.GroupID,
			SK:   GenKeySortKey(in.CurrentGeneration),
			Type: "GenerationKey",
		},
		Wrapped:        in.Link,
		RemoverUserID:  in.CallerUserID,
		RekeyedUserID:  in.CallerUserID,
		RekeyReason:    in.Reason,
		StartSignature: in.StartSignature,
	})
	if err != nil {
		return err
	}
	wrapped, err := attributevalue.Marshal(in.CallerWrappedKey)
	if err != nil {
		return err
	}
	items := []types.TransactWriteItem{
		{Put: &types.Put{
			TableName:           aws.String(c.table),
			Item:                marker,
			ConditionExpression: aws.String("attribute_not_exists(PK)"),
		}},
		{Put: &types.Put{
			TableName:           aws.String(c.table),
			Item:                link,
			ConditionExpression: aws.String("attribute_not_exists(PK)"),
		}},
		{Update: &types.Update{
			TableName:                aws.String(c.table),
			Key:                      memberKey(in.GroupID, in.CallerUserID),
			ConditionExpression:      aws.String("#role = :admin AND #gen = :cur"),
			UpdateExpression:         aws.String("SET #gen = :next, #wrapped = :wrapped, WrapEpoch = :wep"),
			ExpressionAttributeNames: map[string]string{"#role": "Role", "#gen": "Generation", "#wrapped": "WrappedGroupKey"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":admin":   &types.AttributeValueMemberS{Value: models.RoleAdmin},
				":cur":     genAttr(in.CurrentGeneration),
				":next":    genAttr(in.CurrentGeneration + 1),
				":wrapped": wrapped,
				":wep":     epochAttr(in.CallerKeyEpoch),
			},
		}},
		c.keyEpochCheck(in.CallerUserID, in.CallerKeyEpoch),
		{Delete: &types.Delete{
			TableName:                aws.String(c.table),
			Key:                      handoffKey(in.CallerUserID, in.GroupID),
			ConditionExpression:      aws.String("NewWrappingPublicKey = :pk AND #gen = :cur"),
			ExpressionAttributeNames: map[string]string{"#gen": "Generation"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk":  &types.AttributeValueMemberB{Value: in.CallerWrappingKey},
				":cur": genAttr(in.CurrentGeneration),
			},
		}},
	}
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		switch {
		case isConditionalCheckFailure(err, markerIndex):
			return ErrRotationInProgress
		case isConditionalCheckFailure(err, linkIndex):
			// With no marker, a link at the caller's generation means the group
			// moved past it while the caller was dormant: the row holds a key
			// that is no longer current ("One window remains", DESIGN.md), the
			// same answer as a row at another generation.
			return ErrHandoffStale
		case isConditionalCheckFailure(err, callerIndex):
			return ErrRewrapCallerBehind
		case isConditionalCheckFailure(err, epochIndex):
			return ErrWrapEpochStale
		case isConditionalCheckFailure(err, rowIndex):
			return ErrHandoffStale
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		}
		return err
	}
	return nil
}
