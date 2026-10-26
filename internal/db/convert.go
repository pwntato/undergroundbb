package db

import (
	"context"
	"errors"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

var (
	// ErrGroupAlreadyOpen: the group is not Rotating, so there is nothing to
	// convert (Open is one-way, so a second conversion is a no-op the caller
	// should hear about).
	ErrGroupAlreadyOpen = errors.New("db: group is already open")
)

// ConvertGroupToOpen switches a Rotating group to Open, once and only in that
// direction (#61, docs/DESIGN.md "Revocation mode"). One transaction: the
// caller is still an Admin, no rotation marker exists, and META is Rotating.
// META's Version is bumped so a settings edit loaded before the conversion
// does not land after it.
//
// A group that is mid-removal is refused, because Open never completes a
// marker and the removed member's cut-off would silently never happen; the
// same for a member whose entry point is behind the caller's generation, who
// is waiting on a rotation's wrap. A dormant member (their entry is wrapped to
// a key they replaced) does not count as behind, as in CompleteRotation: in an
// Open group they bring their own entry current from their handoff row.
//
// The chain (GENKEY# links) is left exactly as it is: it stays load-bearing
// for older content and is never extended again.
func (c *Client) ConvertGroupToOpen(ctx context.Context, groupID, adminUserID string, callerGeneration int64) error {
	// The marker first: a running rotation always has members behind, and the
	// more useful answer is that it is running. The transaction below still
	// holds the line against one that starts after this read.
	marker, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(c.table),
		Key:            rotationKey(groupID),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return err
	}
	if marker.Item != nil {
		return ErrRotationInProgress
	}
	after := ""
	for {
		page, next, err := c.listMembers(ctx, groupID, after, 200, true)
		if err != nil {
			return err
		}
		for _, m := range page {
			if m.Generation >= callerGeneration {
				continue
			}
			dormant, err := c.memberIsDormant(ctx, m)
			if err != nil {
				return err
			}
			if !dormant {
				return ErrMembersBehind
			}
		}
		if next == "" {
			break
		}
		after = next
	}

	return c.convertTx(ctx, groupID, adminUserID, callerGeneration)
}

// convertTx is the transaction half of ConvertGroupToOpen, on its own so a
// test can reach it past the pre-reads.
func (c *Client) convertTx(ctx context.Context, groupID, adminUserID string, callerGeneration int64) error {
	const (
		adminIndex  = 0
		markerIndex = 1
		metaIndex   = 2
	)
	items := []types.TransactWriteItem{
		{ConditionCheck: &types.ConditionCheck{
			TableName:                aws.String(c.table),
			Key:                      memberKey(groupID, adminUserID),
			ConditionExpression:      aws.String("#role = :admin AND #gen = :gen"),
			ExpressionAttributeNames: map[string]string{"#role": "Role", "#gen": "Generation"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin},
				":gen":   &types.AttributeValueMemberN{Value: strconv.FormatInt(callerGeneration, 10)},
			},
		}},
		{ConditionCheck: &types.ConditionCheck{
			TableName:           aws.String(c.table),
			Key:                 rotationKey(groupID),
			ConditionExpression: aws.String("attribute_not_exists(PK)"),
		}},
		{Update: &types.Update{
			TableName: aws.String(c.table),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
				"SK": &types.AttributeValueMemberS{Value: "META"},
			},
			UpdateExpression:    aws.String("SET #mode = :open, #ver = if_not_exists(#ver, :zero) + :one"),
			ConditionExpression: aws.String("attribute_exists(PK) AND #mode = :rotating AND attribute_not_exists(GroupType)"),
			ExpressionAttributeNames: map[string]string{
				"#mode": "RevocationMode",
				"#ver":  "Version",
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":open":     &types.AttributeValueMemberS{Value: models.RevocationOpen},
				":rotating": &types.AttributeValueMemberS{Value: models.RevocationRotating},
				":zero":     &types.AttributeValueMemberN{Value: "0"},
				":one":      &types.AttributeValueMemberN{Value: "1"},
			},
		}},
	}
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		switch {
		case isConditionalCheckFailure(err, adminIndex):
			return ErrNotGroupAdmin
		case isConditionalCheckFailure(err, markerIndex):
			return ErrRotationInProgress
		case isConditionalCheckFailure(err, metaIndex):
			return ErrGroupAlreadyOpen
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		}
		return err
	}
	return nil
}
