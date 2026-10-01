package db

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// MaxRewrapBatch is how many members one RewrapMembers call may touch. A
// transaction allows 100 items; the rest of the budget is the marker and
// caller checks, with headroom.
const MaxRewrapBatch = 25

var (
	// ErrRotationNotActive: no marker exists, or it is for a different
	// generation than the request names (the rotation finished, or a newer one
	// started). The client reloads and re-derives what to do.
	ErrRotationNotActive = errors.New("db: no matching key rotation in progress")
	// ErrRewrapCallerBehind: the caller is not an admin currently holding the
	// rotation's generation, so they cannot be holding the key they are
	// wrapping.
	ErrRewrapCallerBehind = errors.New("db: caller is not an admin at the rotation's generation")
	// ErrRewrapMemberChanged: a member in the batch left, or already moved past
	// the rotation's generation. Nothing in the batch was written; the client
	// re-lists members and resends.
	ErrRewrapMemberChanged = errors.New("db: a member in the batch changed")
	// ErrMembersBehind: completion refused because some member's entry point
	// is still at an older generation.
	ErrMembersBehind = errors.New("db: members are still on an older key generation")
)

// MemberRewrap is one member's entry point wrapped for the new generation.
type MemberRewrap struct {
	UserID  string
	Wrapped models.WrappedKey
}

// RewrapMembersInput moves a batch of members' entry points to generation
// Generation, the one the group's ROTATION marker names.
type RewrapMembersInput struct {
	GroupID      string
	CallerUserID string
	Generation   int64
	Wraps        []MemberRewrap
}

// GetRotation returns the group's ROTATION marker, or nil when none exists.
func (c *Client) GetRotation(ctx context.Context, groupID string) (*models.Rotation, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(c.table),
		ConsistentRead: aws.Bool(true),
		Key:            rotationKey(groupID),
	})
	if err != nil {
		return nil, fmt.Errorf("db: get rotation: %w", err)
	}
	if out.Item == nil {
		return nil, nil
	}
	var r models.Rotation
	if err := attributevalue.UnmarshalMap(out.Item, &r); err != nil {
		return nil, fmt.Errorf("db: unmarshal rotation: %w", err)
	}
	return &r, nil
}

func rotationKey(groupID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
		"SK": &types.AttributeValueMemberS{Value: RotationSortKey},
	}
}

func genAttr(n int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(n, 10)}
}

// callerAtGenerationCheck asserts the caller is still an admin whose own entry
// point is at gen: the only way to hold the key they are wrapping.
func (c *Client) callerAtGenerationCheck(groupID, userID string, gen int64) types.TransactWriteItem {
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName:                aws.String(c.table),
		Key:                      memberKey(groupID, userID),
		ConditionExpression:      aws.String("#role = :admin AND #gen = :gen"),
		ExpressionAttributeNames: map[string]string{"#role": "Role", "#gen": "Generation"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin},
			":gen":   genAttr(gen),
		},
	}}
}

// markerAtGenerationCheck asserts the marker exists and names gen.
func (c *Client) markerAtGenerationCheck(groupID string, gen int64) types.TransactWriteItem {
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName:                aws.String(c.table),
		Key:                      rotationKey(groupID),
		ConditionExpression:      aws.String("#gen = :gen"),
		ExpressionAttributeNames: map[string]string{"#gen": "Generation"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":gen": genAttr(gen),
		},
	}}
}

// RewrapMembers writes the batch in one transaction: the marker still names
// the generation, the caller is an admin at it, and every member exists and is
// not already past it. Re-wrapping a member already AT the generation is
// allowed, so a retry after a lost response is safe (it rewrites the same key
// under a fresh ephemeral). All or nothing, so there are no UnprocessedItems
// to chase; resume is still state-driven, by re-listing members behind.
func (c *Client) RewrapMembers(ctx context.Context, in RewrapMembersInput) error {
	if len(in.Wraps) == 0 || len(in.Wraps) > MaxRewrapBatch {
		return fmt.Errorf("db: rewrap batch of %d members, want 1..%d", len(in.Wraps), MaxRewrapBatch)
	}
	const (
		markerIndex = 0
		callerIndex = 1
		firstWrap   = 2
	)
	items := []types.TransactWriteItem{
		c.markerAtGenerationCheck(in.GroupID, in.Generation),
		c.callerAtGenerationCheck(in.GroupID, in.CallerUserID, in.Generation),
	}
	seen := map[string]bool{in.CallerUserID: true} // the caller's own item is checked, not written
	for _, w := range in.Wraps {
		if seen[w.UserID] {
			return fmt.Errorf("db: rewrap batch repeats or includes the caller: %s", w.UserID)
		}
		seen[w.UserID] = true
		wrapped, err := attributevalue.Marshal(w.Wrapped)
		if err != nil {
			return err
		}
		items = append(items, types.TransactWriteItem{Update: &types.Update{
			TableName:                aws.String(c.table),
			Key:                      memberKey(in.GroupID, w.UserID),
			UpdateExpression:         aws.String("SET #gen = :gen, #wrapped = :wrapped"),
			ConditionExpression:      aws.String("attribute_exists(PK) AND #gen <= :gen"),
			ExpressionAttributeNames: map[string]string{"#gen": "Generation", "#wrapped": "WrappedGroupKey"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":gen":     genAttr(in.Generation),
				":wrapped": wrapped,
			},
		}})
	}
	_, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if err != nil {
		switch {
		case isConditionalCheckFailure(err, markerIndex):
			return ErrRotationNotActive
		case isConditionalCheckFailure(err, callerIndex):
			return ErrRewrapCallerBehind
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		}
		for i := firstWrap; i < len(items); i++ {
			if isConditionalCheckFailure(err, i) {
				return ErrRewrapMemberChanged
			}
		}
		return err
	}
	return nil
}

// CompleteRotation deletes the marker, only once every member's entry point is
// at the rotation's generation. The membership scan is not atomic with the
// delete: a member added at an older generation in between is possible, and is
// caught the same way as any other behind member, by an admin client comparing
// generations on load.
func (c *Client) CompleteRotation(ctx context.Context, groupID, callerUserID string, gen int64) error {
	after := ""
	for {
		page, next, err := c.ListMembers(ctx, groupID, after, 200)
		if err != nil {
			return err
		}
		for _, m := range page {
			if m.Generation < gen {
				return ErrMembersBehind
			}
		}
		if next == "" {
			break
		}
		after = next
	}
	items := []types.TransactWriteItem{
		c.callerAtGenerationCheck(groupID, callerUserID, gen),
		{Delete: &types.Delete{
			TableName:                aws.String(c.table),
			Key:                      rotationKey(groupID),
			ConditionExpression:      aws.String("#gen = :gen"),
			ExpressionAttributeNames: map[string]string{"#gen": "Generation"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":gen": genAttr(gen),
			},
		}},
	}
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		switch {
		case isConditionalCheckFailure(err, 0):
			return ErrRewrapCallerBehind
		case isConditionalCheckFailure(err, 1):
			return ErrRotationNotActive
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		}
		return err
	}
	return nil
}
