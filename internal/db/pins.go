package db

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// PutPin writes or replaces the pinner's pin of pinnedUserID. Replacing is
// deliberate: a person resolving a key change re-pins, and only the pinner can
// write their own partition, so an overwrite is never someone else's.
func (c *Client) PutPin(ctx context.Context, pinnerID, pinnedUserID string, signingKeys [][]byte, wrappingKey, pinnerSigningKey, signature []byte) error {
	item, err := attributevalue.MarshalMap(models.Pin{
		Record: models.Record{
			PK:   "USER#" + pinnerID,
			SK:   "PIN#" + pinnedUserID,
			Type: "Pin",
		},
		SigningPublicKeys:      signingKeys,
		WrappingPublicKey:      wrappingKey,
		PinnerSigningPublicKey: pinnerSigningKey,
		Signature:              signature,
	})
	if err != nil {
		return fmt.Errorf("db: marshal pin: %w", err)
	}
	if _, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(c.table),
		Item:      item,
	}); err != nil {
		return fmt.Errorf("db: put pin: %w", err)
	}
	return nil
}

// ListPins returns one page of the pinner's own pins in pinned-uuid order,
// starting strictly after afterPinnedUserID (empty for the first page), plus
// the last pinned uuid returned when more may follow. The cursor is a uuid, so
// a caller-supplied one can only move within the caller's own partition.
func (c *Client) ListPins(ctx context.Context, pinnerID, afterPinnedUserID string, limit int) ([]models.Pin, string, error) {
	in := &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "USER#" + pinnerID},
			":sk": &types.AttributeValueMemberS{Value: "PIN#"},
		},
		ConsistentRead: aws.Bool(true),
		Limit:          aws.Int32(int32(limit + 1)),
	}
	if afterPinnedUserID != "" {
		in.ExclusiveStartKey = map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + pinnerID},
			"SK": &types.AttributeValueMemberS{Value: "PIN#" + afterPinnedUserID},
		}
	}
	out, err := c.ddb.Query(ctx, in)
	if err != nil {
		return nil, "", fmt.Errorf("db: list pins: %w", err)
	}
	var pins []models.Pin
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &pins); err != nil {
		return nil, "", fmt.Errorf("db: unmarshal pins: %w", err)
	}
	next := ""
	if len(pins) > limit {
		pins = pins[:limit]
		next = pins[limit-1].SK[len("PIN#"):]
	}
	return pins, next, nil
}
