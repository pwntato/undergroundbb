package db

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// SelfWrapInput is a member's wrap of the key they hold to their own new X25519
// key, in a group with no rotation (Open or public).
type SelfWrapInput struct {
	GroupID      string
	CallerUserID string
	// Generation is the caller's own entry-point generation, which the handoff
	// row must hold too. An Open group never mints a generation, so the wrap
	// replaces the entry in place.
	Generation int64
	Wrapped    models.WrappedKey
	// CallerKeyEpoch is the caller's KeyEpoch as the handler read it; it becomes
	// the entry's WrapEpoch and is checked against PROFILE in the same
	// transaction.
	CallerKeyEpoch uint64
	// CallerWrappingKey is the caller's current X25519 public key: the handoff
	// row must name it.
	CallerWrappingKey []byte
	// WrapRecord is the caller's signed record of this wrap, or nil from a
	// client that signs none.
	WrapRecord *WrapRecord
}

// SelfWrap moves the caller's entry point to their new key and consumes their
// handoff row in one transaction (docs/DESIGN.md, "The self re-key must survive
// a closed tab"). It is the Open-group counterpart of SelfRekey: there is no
// marker and no link, since no key is minted. The row must exist, name the
// caller's current wrapping key and hold Generation, and the caller's entry
// must be at Generation, otherwise ErrHandoffStale and nothing is written.
func (c *Client) SelfWrap(ctx context.Context, in SelfWrapInput) error {
	const (
		entryIndex = 0
		epochIndex = 1
		rowIndex   = 2
	)
	wrapped, err := attributevalue.Marshal(in.Wrapped)
	if err != nil {
		return err
	}
	items := []types.TransactWriteItem{
		{Update: &types.Update{
			TableName:                aws.String(c.table),
			Key:                      memberKey(in.GroupID, in.CallerUserID),
			ConditionExpression:      aws.String("#gen = :gen"),
			UpdateExpression:         aws.String("SET #wrapped = :wrapped, WrapEpoch = :wep"),
			ExpressionAttributeNames: map[string]string{"#gen": "Generation", "#wrapped": "WrappedGroupKey"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":gen":     genAttr(in.Generation),
				":wrapped": wrapped,
				":wep":     epochAttr(in.CallerKeyEpoch),
			},
		}},
		c.keyEpochCheck(in.CallerUserID, in.CallerKeyEpoch),
		{Delete: &types.Delete{
			TableName:                aws.String(c.table),
			Key:                      handoffKey(in.CallerUserID, in.GroupID),
			ConditionExpression:      aws.String("NewWrappingPublicKey = :pk AND #gen = :gen"),
			ExpressionAttributeNames: map[string]string{"#gen": "Generation"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk":  &types.AttributeValueMemberB{Value: in.CallerWrappingKey},
				":gen": genAttr(in.Generation),
			},
		}},
	}
	applyWrapRecord(items[entryIndex].Update, in.WrapRecord)
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		switch {
		case isConditionalCheckFailure(err, entryIndex), isConditionalCheckFailure(err, rowIndex):
			return ErrHandoffStale
		case isConditionalCheckFailure(err, epochIndex):
			return ErrWrapEpochStale
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		}
		return err
	}
	return nil
}
