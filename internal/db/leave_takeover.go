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
	// CallerKeyEpoch is the caller's KeyEpoch as the handler read it (#62): it
	// becomes their WrapEpoch and is checked against PROFILE in the same
	// transaction, as RemoveRotation.RemoverKeyEpoch is.
	CallerKeyEpoch uint64
	StartSignature []byte
	// WrapRecord is the caller's signed record of their own entry at the new
	// generation (#280), or nil from a client that signs none.
	WrapRecord *WrapRecord
}

// TakeOverLeaveRotation turns the marker a leaving member left (#178) into a
// rotation an admin mints, and deletes the leaver's ADMISSION# row, which the
// leave kept for the admin's check of the leaver's key. The leaver supplies only a signed statement that
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
	// CreatedAt is unset on both rows; the marker's StartedAt stays (see
	// RemoveMember) (#258).
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
		RemovedUserID:  in.LeaverUserID,
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
		// The leave kept the leaver's admission so this admin could check the
		// leaver's key against it; it has served its purpose. Last, so no
		// condition-check index above shifts.
		admissionDelete(c.table, in.GroupID, in.LeaverUserID),
		// The caller's re-wrap is to the key they hold now (#62); last, so no
		// index above shifts.
		c.keyEpochCheck(in.CallerUserID, in.CallerKeyEpoch),
		// A takeover is a start like a removal's: it consumes the caller's
		// handoff row for this group, in the same transaction.
		{Delete: &types.Delete{
			TableName: aws.String(c.table),
			Key:       handoffKey(in.CallerUserID, in.GroupID),
		}},
	}
	const epochIndex = 4
	applyWrapRecord(items[callerIndex].Update, in.WrapRecord)
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		switch {
		case isConditionalCheckFailure(err, markerIndex), isConditionalCheckFailure(err, linkIndex):
			return ErrRotationNotActive
		case isConditionalCheckFailure(err, epochIndex):
			return ErrWrapEpochStale
		case isConditionalCheckFailure(err, callerIndex):
			return ErrRewrapCallerBehind
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		}
		return err
	}
	return nil
}
