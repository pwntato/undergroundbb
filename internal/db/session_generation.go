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
)

// GetSessionGeneration returns userID's current session generation (#224).
// The read is strongly consistent: a logout must end the session on the very
// next request, not after replication catches up, and a login must be issued
// the generation a following request will compare against. A missing PROFILE
// answers ErrUserNotFound. A deleted account's tombstone still reads: the
// handlers answer it with 410 account_deleted, which the web client needs.
func (c *Client) GetSessionGeneration(ctx context.Context, userID string) (int64, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		ProjectionExpression: aws.String("SessionGeneration"),
		ConsistentRead:       aws.Bool(true),
	})
	if err != nil {
		return 0, fmt.Errorf("db: get session generation: %w", err)
	}
	if out.Item == nil {
		return 0, ErrUserNotFound
	}
	var row struct {
		SessionGeneration int64 `dynamodbav:"SessionGeneration"`
	}
	if err := attributevalue.UnmarshalMap(out.Item, &row); err != nil {
		return 0, fmt.Errorf("db: get session generation: %w", err)
	}
	return row.SessionGeneration, nil
}

// RevokeSessions increments userID's session generation if it is still gen,
// which invalidates every token issued at gen or lower. The condition makes a
// repeat idempotent: a token that was already revoked cannot bump the counter
// again and sign out a newer login. A failed condition is not an error.
func (c *Client) RevokeSessions(ctx context.Context, userID string, gen int64) error {
	cond := "SessionGeneration = :gen"
	if gen == 0 {
		// A row from before the counter existed has no attribute at all.
		cond = "attribute_not_exists(SessionGeneration) OR SessionGeneration = :gen"
	}
	_, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		UpdateExpression:    aws.String("ADD SessionGeneration :one"),
		ConditionExpression: aws.String("attribute_exists(PK) AND (" + cond + ")"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one": &types.AttributeValueMemberN{Value: "1"},
			":gen": &types.AttributeValueMemberN{Value: strconv.FormatInt(gen, 10)},
		},
	})
	if err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			return nil
		}
		return fmt.Errorf("db: revoke sessions: %w", err)
	}
	return nil
}
