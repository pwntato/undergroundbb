package db

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// TakeOverLeaveRotationInput is the rotation an admin starts in place of the
// bare marker a leaver left behind.
type TakeOverLeaveRotationInput struct {
	GroupID      string
	CallerUserID string
	// LeaverUserID is the marker's RemovedUserID as the caller read it.
	LeaverUserID string
	// CurrentGeneration is the caller's own entry-point generation; the
	// rotation goes to CurrentGeneration+1, the marker's generation.
	CurrentGeneration int64
	Link              models.WrappedBlob
	CallerWrappedKey  models.WrappedKey
	StartSignature    []byte
}

// TakeOverLeaveRotation turns the marker a leaving member left (#178) into a
// rotation an admin mints. The leaver supplies only a signed statement that
// they are the member being removed; the new key is the admin's, so a hostile
// leaver never holds it.
//
// One transaction: the marker is replaced (conditioned on it still being the
// leaver's, at the next generation), the GENKEY# link for the caller's
// generation is written (it must not exist yet: the leave wrote none), and the
// caller's entry point moves to the new key. The new marker and link name the
// same leaver as removed, signed by the admin, so the removal history covers
// them. Two admins racing is settled by the marker condition: the second sees
// ErrRotationNotActive, re-reads, and is re-wrapped by the first like any
// other member.
func (c *Client) TakeOverLeaveRotation(ctx context.Context, in TakeOverLeaveRotationInput) error {
	const (
		markerIndex = 0
		linkIndex   = 1
		callerIndex = 2
	)
	now := time.Now().UTC().Format(time.RFC3339)
	marker, err := attributevalue.MarshalMap(models.Rotation{
		Record: models.Record{
			PK:        "GROUP#" + in.GroupID,
			SK:        RotationSortKey,
			Type:      "Rotation",
			CreatedAt: now,
		},
		Generation:     in.CurrentGeneration + 1,
		StartedAt:      now,
		StartedBy:      in.CallerUserID,
		RemovedUserID:  in.LeaverUserID,
		StartSignature: in.StartSignature,
	})
	if err != nil {
		return err
	}
	link, err := attributevalue.MarshalMap(models.GenerationKey{
		Record: models.Record{
			PK:        "GROUP#" + in.GroupID,
			SK:        GenKeySortKey(in.CurrentGeneration),
			Type:      "GenerationKey",
			CreatedAt: now,
		},
		Wrapped:        in.Link,
		RemoverUserID:  in.CallerUserID,
		RemovedUserID:  in.LeaverUserID,
		StartSignature: in.StartSignature,
	})
	if err != nil {
		return err
	}
	wrapped, err := attributevalue.Marshal(in.CallerWrappedKey)
	if err != nil {
		return err
	}
	leaver := &types.AttributeValueMemberS{Value: in.LeaverUserID}
	items := []types.TransactWriteItem{
		{Put: &types.Put{
			TableName:                aws.String(c.table),
			Item:                     marker,
			ConditionExpression:      aws.String("#gen = :next AND #by = :leaver AND #removed = :leaver"),
			ExpressionAttributeNames: map[string]string{"#gen": "Generation", "#by": "StartedBy", "#removed": "RemovedUserID"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":next":   genAttr(in.CurrentGeneration + 1),
				":leaver": leaver,
			},
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
			UpdateExpression:         aws.String("SET #gen = :next, #wrapped = :wrapped"),
			ExpressionAttributeNames: map[string]string{"#role": "Role", "#gen": "Generation", "#wrapped": "WrappedGroupKey"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":admin":   &types.AttributeValueMemberS{Value: models.RoleAdmin},
				":cur":     genAttr(in.CurrentGeneration),
				":next":    genAttr(in.CurrentGeneration + 1),
				":wrapped": wrapped,
			},
		}},
	}
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		switch {
		case isConditionalCheckFailure(err, markerIndex), isConditionalCheckFailure(err, linkIndex):
			return ErrRotationNotActive
		case isConditionalCheckFailure(err, callerIndex):
			return ErrRewrapCallerBehind
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		}
		return err
	}
	return nil
}
