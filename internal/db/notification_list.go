package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// notifKeyPrefix is the sort key prefix of every notification.
const notifKeyPrefix = "NOTIF#"

// ListNotifications reads up to limit of userID's notifications in descending key order, strictly
// after afterSK ("" for the start). That one order is the list's order (#69): replies carry a real
// day and sort above the reaction range, whose placeholder day is 0000-00-00, so replies come
// newest day first and then reactions newest post first (ReactionNotificationSortKey carries the
// post's day). It returns the rows, the sort key of the last row READ (to resume after) and done
// when the range is exhausted.
func (c *Client) ListNotifications(ctx context.Context, userID, afterSK string, limit int) (rows []models.Notification, lastSK string, done bool, err error) {
	var start map[string]types.AttributeValue
	if afterSK != "" {
		start = map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: afterSK},
		}
	}
	out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "USER#" + userID},
			":sk": &types.AttributeValueMemberS{Value: notifKeyPrefix},
		},
		ScanIndexForward:  aws.Bool(false),
		ConsistentRead:    aws.Bool(true),
		Limit:             aws.Int32(int32(limit)),
		ExclusiveStartKey: start,
	})
	if err != nil {
		return nil, "", false, fmt.Errorf("db: list notifications: %w", err)
	}
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &rows); err != nil {
		return nil, "", false, fmt.Errorf("db: unmarshal notifications: %w", err)
	}
	if n := len(rows); n > 0 {
		lastSK = rows[n-1].SK
	}
	return rows, lastSK, len(out.LastEvaluatedKey) == 0, nil
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
