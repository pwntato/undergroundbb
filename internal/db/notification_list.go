package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// MaxReactionNotifications caps how many reaction notifications one read of the undated range
// returns (#69). Their keys are hashes, so "newest post first" cannot be paged in key order: the
// whole range is read once and sorted. 500 small rows is about 20 read units.
const MaxReactionNotifications = 500

// notifKeyPrefix is the sort key prefix of every notification; the reaction range sits under the
// undated placeholder day, so in key order it sorts before any real day.
const notifKeyPrefix = "NOTIF#"

// ListReplyNotifications reads up to limit of userID's reply notifications, newest day first,
// strictly after afterSK (a sort key from an earlier call, "" for the start). The reaction range
// is excluded. It returns the rows and the sort key of the last row READ (to resume after), and
// done when the reply range is exhausted.
func (c *Client) ListReplyNotifications(ctx context.Context, userID, afterSK string, limit int) (rows []models.Notification, lastSK string, done bool, err error) {
	var start map[string]types.AttributeValue
	if afterSK != "" {
		start = map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: afterSK},
		}
	}
	// Real days sort above the undated placeholder "0000-00-00", so a lower bound of "0001"
	// keeps the reaction range out without a filter.
	out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		KeyConditionExpression: aws.String("PK = :pk AND SK BETWEEN :lo AND :hi"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "USER#" + userID},
			":lo": &types.AttributeValueMemberS{Value: notifKeyPrefix + "0001"},
			":hi": &types.AttributeValueMemberS{Value: notifKeyPrefix + "9999-99-99~"},
		},
		ScanIndexForward:  aws.Bool(false),
		ConsistentRead:    aws.Bool(true),
		Limit:             aws.Int32(int32(limit)),
		ExclusiveStartKey: start,
	})
	if err != nil {
		return nil, "", false, fmt.Errorf("db: list reply notifications: %w", err)
	}
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &rows); err != nil {
		return nil, "", false, fmt.Errorf("db: unmarshal notifications: %w", err)
	}
	if n := len(rows); n > 0 {
		lastSK = rows[n-1].SK
	}
	return rows, lastSK, len(out.LastEvaluatedKey) == 0, nil
}

// ListReactionNotifications reads userID's reaction notifications (the undated range), at most
// MaxReactionNotifications of them, in key order. The caller sorts: the order the list shows is
// by the day inside post_id, which the key does not carry.
func (c *Client) ListReactionNotifications(ctx context.Context, userID string) ([]models.Notification, error) {
	var rows []models.Notification
	var start map[string]types.AttributeValue
	for len(rows) < MaxReactionNotifications {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "USER#" + userID},
				":sk": &types.AttributeValueMemberS{Value: notifKeyPrefix + idgen.UndatedNotificationDay + "#"},
			},
			ConsistentRead:    aws.Bool(true),
			Limit:             aws.Int32(int32(MaxReactionNotifications - len(rows))),
			ExclusiveStartKey: start,
		})
		if err != nil {
			return nil, fmt.Errorf("db: list reaction notifications: %w", err)
		}
		var page []models.Notification
		if err := attributevalue.UnmarshalListOfMaps(out.Items, &page); err != nil {
			return nil, fmt.Errorf("db: unmarshal notifications: %w", err)
		}
		rows = append(rows, page...)
		if len(out.LastEvaluatedKey) == 0 {
			break
		}
		start = out.LastEvaluatedKey
	}
	return rows, nil
}

// MarkNotificationRead sets Read on one of userID's notifications. The partition is the caller's
// own, so nobody can mark another person's. A row that is gone (deleted with what sent it, or
// expired) is not an error: there is nothing left to mark.
func (c *Client) MarkNotificationRead(ctx context.Context, userID, sortKey string) error {
	_, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: sortKey},
		},
		ConditionExpression:       aws.String("attribute_exists(PK)"),
		UpdateExpression:          aws.String("SET #read = :true"),
		ExpressionAttributeNames:  map[string]string{"#read": "Read"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":true": &types.AttributeValueMemberBOOL{Value: true}},
	})
	var cond *types.ConditionalCheckFailedException
	if err != nil && !errors.As(err, &cond) {
		return fmt.Errorf("db: mark notification read: %w", err)
	}
	return nil
}
