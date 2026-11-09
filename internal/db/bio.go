package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// SetBio writes PROFILE.Bio (#75); an empty bio removes the attribute. The
// caller validates the text. A missing or tombstoned account is
// ErrUserNotFound, so a stale session cannot put a bio back on a deleted
// account (DeleteAccount removes it).
func (c *Client) SetBio(ctx context.Context, userID, bio string) error {
	in := &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		ConditionExpression: aws.String("attribute_exists(PK) AND attribute_not_exists(DeletedAt)"),
	}
	if bio == "" {
		in.UpdateExpression = aws.String("REMOVE Bio")
	} else {
		in.UpdateExpression = aws.String("SET Bio = :bio")
		in.ExpressionAttributeValues = map[string]types.AttributeValue{":bio": &types.AttributeValueMemberS{Value: bio}}
	}
	if _, err := c.ddb.UpdateItem(ctx, in); err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			return ErrUserNotFound
		}
		return fmt.Errorf("db: set bio: %w", err)
	}
	return nil
}
