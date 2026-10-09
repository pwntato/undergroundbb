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

// markerCheck pins the marker's state to what RewrapMembers read, so a marker
// that appears, vanishes or changes generation between the read and the write
// fails the transaction (and the client re-reads) instead of being re-wrapped
// under the wrong mode. With a marker it must still name gen; without one it
// must still be absent.
func (c *Client) markerCheck(groupID string, gen int64, markerPresent bool) types.TransactWriteItem {
	check := &types.ConditionCheck{
		TableName:           aws.String(c.table),
		Key:                 rotationKey(groupID),
		ConditionExpression: aws.String("attribute_not_exists(PK)"),
	}
	if markerPresent {
		check.ConditionExpression = aws.String("#gen = :gen")
		check.ExpressionAttributeNames = map[string]string{"#gen": "Generation"}
		check.ExpressionAttributeValues = map[string]types.AttributeValue{":gen": genAttr(gen)}
	}
	return types.TransactWriteItem{ConditionCheck: check}
}

// RewrapMembers writes the batch in one transaction, in one of two modes
// decided by a consistent read of the marker:
//
//   - Rotation in progress (marker names Generation): every member must exist
//     and be at or behind it (Generation <= N). Accepting a member already AT N
//     is what makes a retry after a lost response safe.
//   - No marker, the catch-up for a member left behind after completion: every
//     member must be STRICTLY behind (Generation < N). Without that, any admin
//     could overwrite the wrapped key of any member already at the current
//     generation in a group that never rotates. A lost-response retry of a
//     catch-up then reports member_changed and the client re-lists, which is
//     the documented contract.
//
// In both modes the caller is an admin whose own entry point is at N (the only
// way to hold the key, and it pins N to the current generation when there is no
// marker), and nobody is ever moved backward. A client should re-wrap only
// members who are behind; a wrong key written over a member at the generation
// would lock out exactly the admins able to resume. All or nothing, so there
// are no UnprocessedItems to chase; resume is still state-driven, by
// re-listing members behind.
func (c *Client) RewrapMembers(ctx context.Context, in RewrapMembersInput) error {
	if len(in.Wraps) == 0 || len(in.Wraps) > MaxRewrapBatch {
		return fmt.Errorf("db: rewrap batch of %d members, want 1..%d", len(in.Wraps), MaxRewrapBatch)
	}
	const (
		markerIndex = 0
		callerIndex = 1
		firstWrap   = 2
	)
	marker, err := c.GetRotation(ctx, in.GroupID)
	if err != nil {
		return err
	}
	if marker != nil && marker.Generation != in.Generation {
		return ErrRotationNotActive
	}
	memberCond := "attribute_exists(PK) AND #gen < :gen" // catch-up: strictly behind
	if marker != nil {
		memberCond = "attribute_exists(PK) AND #gen <= :gen"
	}
	items := []types.TransactWriteItem{
		c.markerCheck(in.GroupID, in.Generation, marker != nil),
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
			UpdateExpression:         aws.String("SET #gen = :gen, #wrapped = :wrapped REMOVE #pending"),
			ConditionExpression:      aws.String(memberCond),
			ExpressionAttributeNames: map[string]string{"#gen": "Generation", "#wrapped": "WrappedGroupKey", "#pending": "PendingWrappedKey"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":gen":     genAttr(in.Generation),
				":wrapped": wrapped,
			},
		}})
	}
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
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
// delete: a member added at an older generation in between is possible. The
// scan is a consistent read so it cannot miss a just-written membership, and
// such a member is moved by a catch-up RewrapMembers (no marker needed).
func (c *Client) CompleteRotation(ctx context.Context, groupID, callerUserID string, gen int64) error {
	after := ""
	for {
		page, next, err := c.listMembers(ctx, groupID, after, 200, true)
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
		// The marker first, as RewrapMembers does: when both fail (a stale tab
		// completing a rotation its admin has since moved past) "not active"
		// is the answer the client treats as done.
		case isConditionalCheckFailure(err, 1):
			return ErrRotationNotActive
		case isConditionalCheckFailure(err, 0):
			return ErrRewrapCallerBehind
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		}
		return err
	}
	return nil
}

// ListGenerationKeys returns the group's GENKEY# chain links for generations
// from..to inclusive, in ascending order, at most limit of them. When the
// range holds more, next is the generation to resume from (the first one not
// returned); otherwise next is -1. A generation with no link is simply absent:
// the caller decides whether that is the floor of a truncated chain or a gap.
func (c *Client) ListGenerationKeys(ctx context.Context, groupID string, from, to int64, limit int) (links []models.GenerationKey, next int64, err error) {
	out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		KeyConditionExpression: aws.String("PK = :pk AND SK BETWEEN :from AND :to"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":   &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			":from": &types.AttributeValueMemberS{Value: GenKeySortKey(from)},
			":to":   &types.AttributeValueMemberS{Value: GenKeySortKey(to)},
		},
		ConsistentRead: aws.Bool(true),
		Limit:          aws.Int32(int32(limit + 1)),
	})
	if err != nil {
		return nil, -1, fmt.Errorf("db: list generation keys: %w", err)
	}
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &links); err != nil {
		return nil, -1, fmt.Errorf("db: unmarshal generation keys: %w", err)
	}
	next = -1
	if len(links) > limit {
		n, err := ParseGenKeySortKey(links[limit].SK)
		if err != nil {
			return nil, -1, err
		}
		links = links[:limit]
		next = n
	}
	return links, next, nil
}
