package db

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

var (
	// ErrNotMember: the caller has no MEMBER# row in the group.
	ErrNotMember = errors.New("db: not a member of this group")
	// ErrLastAdmin: the caller is the group's only Admin and other members
	// remain. They must promote a successor first (issue #66).
	ErrLastAdmin = errors.New("db: last admin cannot leave while other members remain")
	// ErrLeaveConflict: the roster changed between the read and the write
	// (a role change, another admin leaving). Nothing was written; retry.
	ErrLeaveConflict = errors.New("db: roster changed during leave, retry")
	// ErrGroupSweepIncomplete accompanies groupDeleted=true when the group's
	// remaining rows could not all be removed. The group is already gone
	// (its META and the caller's membership are deleted); what is left is
	// unreachable garbage.
	ErrGroupSweepIncomplete = errors.New("db: group deleted but leftover rows remain")
)

// memberRoles reads every MEMBER# row's user id and role in the group. Only
// SK and Role are projected: a roster of 1,000 members must not drag 1,000
// wrapped keys through this read.
func (c *Client) memberRoles(ctx context.Context, groupID string) (map[string]string, error) {
	roles := map[string]string{}
	var start map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:                aws.String(c.table),
			KeyConditionExpression:   aws.String("PK = :pk AND begins_with(SK, :sk)"),
			ProjectionExpression:     aws.String("SK, #role"),
			ExpressionAttributeNames: map[string]string{"#role": "Role"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
				":sk": &types.AttributeValueMemberS{Value: "MEMBER#"},
			},
			ExclusiveStartKey: start,
			ConsistentRead:    aws.Bool(true),
		})
		if err != nil {
			return nil, fmt.Errorf("db: read roster: %w", err)
		}
		var rows []models.Membership
		if err := attributevalue.UnmarshalListOfMaps(out.Items, &rows); err != nil {
			return nil, fmt.Errorf("db: unmarshal roster: %w", err)
		}
		for _, r := range rows {
			roles[strings.TrimPrefix(r.SK, "MEMBER#")] = r.Role
		}
		if out.LastEvaluatedKey == nil {
			return roles, nil
		}
		start = out.LastEvaluatedKey
	}
}

func memberKey(groupID, userID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
		"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + userID},
	}
}

// LeaveGroup removes userID from the group -- issue #66.
//
//   - Anyone but the last Admin: their MEMBER# row is deleted. Grants they
//     signed or received stay; history is append-only.
//   - The last Admin while others remain: ErrLastAdmin, nothing written.
//   - The only member: the group is deleted (groupDeleted true) rather than
//     trapping the user in it.
//
// The last-admin rule is enforced by the transaction, not just the read: an
// admin's delete carries a ConditionCheck that another admin still holds the
// role, so two admins leaving at once cannot both succeed (one sees the
// other's row deleted or in conflict).
//
// Leaving does not rotate keys. A member of a Rotating group keeps the
// generation keys they already hold until #58 exists.
func (c *Client) LeaveGroup(ctx context.Context, groupID, userID string) (groupDeleted bool, err error) {
	roles, err := c.memberRoles(ctx, groupID)
	if err != nil {
		return false, err
	}
	role, ok := roles[userID]
	if !ok {
		return false, ErrNotMember
	}
	if len(roles) == 1 {
		return c.deleteGroup(ctx, groupID, userID)
	}

	items := []types.TransactWriteItem{{Delete: &types.Delete{
		TableName:                aws.String(c.table),
		Key:                      memberKey(groupID, userID),
		ConditionExpression:      aws.String("#role = :role"),
		ExpressionAttributeNames: map[string]string{"#role": "Role"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":role": &types.AttributeValueMemberS{Value: role},
		},
	}}}
	if role == models.RoleAdmin {
		other := ""
		for id, r := range roles {
			if id != userID && r == models.RoleAdmin {
				other = id
				break
			}
		}
		if other == "" {
			return false, ErrLastAdmin
		}
		items = append(items, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName:                aws.String(c.table),
			Key:                      memberKey(groupID, other),
			ConditionExpression:      aws.String("#role = :admin"),
			ExpressionAttributeNames: map[string]string{"#role": "Role"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin},
			},
		}})
	}
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		if isConditionalCheckFailure(err, 0) || isConditionalCheckFailure(err, 1) || isTransactionConflict(err) {
			return false, ErrLeaveConflict
		}
		return false, err
	}
	return false, nil
}

// deleteGroup removes the last member and the group's META in one
// transaction, then sweeps everything else under the partition. META going
// first is what stops a late invite completion (CompleteInvite conditions on
// META existing); the sweep also removes any membership that slipped in
// between the roster read and the transaction, since that member's group no
// longer exists.
func (c *Client) deleteGroup(ctx context.Context, groupID, userID string) (bool, error) {
	_, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Delete: &types.Delete{
				TableName:           aws.String(c.table),
				Key:                 memberKey(groupID, userID),
				ConditionExpression: aws.String("attribute_exists(PK)"),
			}},
			{Delete: &types.Delete{
				TableName: aws.String(c.table),
				Key: map[string]types.AttributeValue{
					"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
					"SK": &types.AttributeValueMemberS{Value: "META"},
				},
				ConditionExpression: aws.String("attribute_exists(PK)"),
			}},
		},
	})
	if err != nil {
		if isConditionalCheckFailure(err, 0) {
			return false, ErrNotMember
		}
		if isConditionalCheckFailure(err, 1) || isTransactionConflict(err) {
			return false, ErrLeaveConflict
		}
		return false, err
	}
	if err := c.sweepPartition(ctx, "GROUP#"+groupID); err != nil {
		return true, fmt.Errorf("%w: %v", ErrGroupSweepIncomplete, err)
	}
	return true, nil
}

// sweepPartition deletes every item under pk, 25 at a time.
func (c *Client) sweepPartition(ctx context.Context, pk string) error {
	var start map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(c.table),
			KeyConditionExpression:    aws.String("PK = :pk"),
			ProjectionExpression:      aws.String("PK, SK"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":pk": &types.AttributeValueMemberS{Value: pk}},
			ExclusiveStartKey:         start,
			ConsistentRead:            aws.Bool(true),
		})
		if err != nil {
			return err
		}
		for i := 0; i < len(out.Items); i += 25 {
			end := min(i+25, len(out.Items))
			reqs := make([]types.WriteRequest, 0, end-i)
			for _, it := range out.Items[i:end] {
				reqs = append(reqs, types.WriteRequest{DeleteRequest: &types.DeleteRequest{
					Key: map[string]types.AttributeValue{"PK": it["PK"], "SK": it["SK"]},
				}})
			}
			for attempt := 0; len(reqs) > 0; attempt++ {
				if attempt == 5 {
					return errors.New("unprocessed deletes after retries")
				}
				res, err := c.ddb.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
					RequestItems: map[string][]types.WriteRequest{c.table: reqs},
				})
				if err != nil {
					return err
				}
				reqs = res.UnprocessedItems[c.table]
			}
		}
		if out.LastEvaluatedKey == nil {
			return nil
		}
		start = out.LastEvaluatedKey
	}
}
