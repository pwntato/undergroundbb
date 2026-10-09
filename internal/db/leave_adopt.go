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

var (
	// ErrNoPendingKey: the caller has no leave-supplied key waiting, or is not
	// an admin at the generation before the rotation's.
	ErrNoPendingKey = errors.New("db: no pending key for this admin at the previous generation")
	// ErrRotationAdopted: an admin has already adopted the leaver's key, so the
	// rotation can no longer be replaced; the others wait to be re-wrapped from
	// that admin's verified copy.
	ErrRotationAdopted = errors.New("db: an admin already adopted this rotation's key")
)

// AdoptPendingKey moves an admin's entry point onto the key a leaving member
// wrapped for them (#178), in one transaction with a count on the marker.
//
// The server cannot read the key, so the admin's CLIENT is the check: it opens
// the GENKEY# link with the pending key and requires its own current key
// inside before asking for this. What the server adds is atomicity with
// RestartLeaveRotation through the marker's Adopted count: an adoption bumps
// it in the same commit that moves the admin, and a restart requires it to be
// zero, so a rotation is never replaced under an admin who has already moved
// onto its key.
//
// gen is the rotation's generation. The caller must be an admin at gen-1 with
// a pending key; the marker must name gen and be one a leaver started.
func (c *Client) AdoptPendingKey(ctx context.Context, groupID, userID string, gen int64) error {
	const (
		markerIndex = 0
		memberIndex = 1
	)
	items := []types.TransactWriteItem{
		{Update: &types.Update{
			TableName:                aws.String(c.table),
			Key:                      rotationKey(groupID),
			ConditionExpression:      aws.String("#gen = :gen AND #by = #removed"),
			UpdateExpression:         aws.String("SET #adopted = if_not_exists(#adopted, :zero) + :one"),
			ExpressionAttributeNames: map[string]string{"#gen": "Generation", "#by": "StartedBy", "#removed": "RemovedUserID", "#adopted": "Adopted"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":gen":  genAttr(gen),
				":zero": genAttr(0),
				":one":  genAttr(1),
			},
		}},
		{Update: &types.Update{
			TableName:                aws.String(c.table),
			Key:                      memberKey(groupID, userID),
			ConditionExpression:      aws.String("#role = :admin AND #gen = :prev AND attribute_exists(#pending)"),
			UpdateExpression:         aws.String("SET #gen = :gen, #wrapped = #pending REMOVE #pending"),
			ExpressionAttributeNames: map[string]string{"#role": "Role", "#gen": "Generation", "#wrapped": "WrappedGroupKey", "#pending": "PendingWrappedKey"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin},
				":prev":  genAttr(gen - 1),
				":gen":   genAttr(gen),
			},
		}},
	}
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		switch {
		case isConditionalCheckFailure(err, markerIndex):
			return ErrRotationNotActive
		case isConditionalCheckFailure(err, memberIndex):
			return ErrNoPendingKey
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		}
		return err
	}
	return nil
}

// RestartLeaveRotation replaces a rotation a LEAVER started whose key no admin
// could verify (#178), with one the calling admin starts. It is the recovery
// for a hostile leaver who sent key material that opens to nothing: that
// rotation can never finish, and without this the group would be stuck behind
// its marker for good.
//
// One transaction: the marker is replaced (conditioned on it still being the
// leaver's, at the next generation, with nobody having adopted), the leaver's
// GENKEY# link is replaced by the admin's, and the admin's entry point moves
// to the new key. The new marker and link name the same leaver as removed,
// now signed by the admin, so the removal history still covers them. Every
// other holder's stale pending key is ignored, and removed when they are
// re-wrapped (RewrapMembers).
//
// RestartLeaveRotationInput is the admin's replacement rotation.
type RestartLeaveRotationInput struct {
	GroupID      string
	CallerUserID string
	// LeaverUserID is the marker's RemovedUserID as the caller read it.
	LeaverUserID string
	// CurrentGeneration is the caller's own entry-point generation; the
	// replacement goes to CurrentGeneration+1, the marker's generation.
	CurrentGeneration int64
	Link              models.WrappedBlob
	CallerWrappedKey  models.WrappedKey
	StartSignature    []byte
}

// RestartLeaveRotation: see RestartLeaveRotationInput.
func (c *Client) RestartLeaveRotation(ctx context.Context, in RestartLeaveRotationInput) error {
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
			ConditionExpression:      aws.String("#gen = :next AND #by = :leaver AND #removed = :leaver AND attribute_not_exists(#adopted)"),
			ExpressionAttributeNames: map[string]string{"#gen": "Generation", "#by": "StartedBy", "#removed": "RemovedUserID", "#adopted": "Adopted"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":next":   genAttr(in.CurrentGeneration + 1),
				":leaver": leaver,
			},
		}},
		{Put: &types.Put{
			TableName:                aws.String(c.table),
			Item:                     link,
			ConditionExpression:      aws.String("#remover = :leaver"),
			ExpressionAttributeNames: map[string]string{"#remover": "RemoverUserID"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":leaver": leaver,
			},
		}},
		{Update: &types.Update{
			TableName:                aws.String(c.table),
			Key:                      memberKey(in.GroupID, in.CallerUserID),
			ConditionExpression:      aws.String("#role = :admin AND #gen = :cur"),
			UpdateExpression:         aws.String("SET #gen = :next, #wrapped = :wrapped REMOVE #pending"),
			ExpressionAttributeNames: map[string]string{"#role": "Role", "#gen": "Generation", "#wrapped": "WrappedGroupKey", "#pending": "PendingWrappedKey"},
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
		case isConditionalCheckFailure(err, markerIndex):
			// One condition covers "not the leaver's", "other generation" and
			// "adopted"; the marker says which, for a better answer.
			if cur, gerr := c.GetRotation(ctx, in.GroupID); gerr == nil && cur != nil &&
				cur.Generation == in.CurrentGeneration+1 && cur.StartedBy == cur.RemovedUserID &&
				cur.RemovedUserID == in.LeaverUserID && cur.Adopted > 0 {
				return ErrRotationAdopted
			}
			return ErrRotationNotActive
		case isConditionalCheckFailure(err, linkIndex):
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
