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

// GetRecovery reads the USER#<uuid>/RECOVERY item for userID. Returns
// ErrUserNotFound if it doesn't exist -- the same sentinel
// LookupUserByUsername uses for the equivalent PROFILE gap, since a caller
// (recoveryCodeRelease/recoveryCodeReset) that resolved userID via a
// username lookup has no more use for a distinct error here than it would
// for a missing PROFILE: either way there is nothing to recover.
//
// Unlike LookupUserByUsername, this takes userID directly rather than a
// username -- callers here always already hold a resolved *models.User
// (they look one up first, to reach RECOVERY's release/reset gate at all),
// so there is no second username-to-claim resolution to repeat.
func (c *Client) GetRecovery(ctx context.Context, userID string) (*models.Recovery, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "RECOVERY"},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("db: get recovery: %w", err)
	}
	if out.Item == nil {
		return nil, ErrUserNotFound
	}
	var recovery models.Recovery
	if err := attributevalue.UnmarshalMap(out.Item, &recovery); err != nil {
		return nil, fmt.Errorf("db: unmarshal recovery: %w", err)
	}
	return &recovery, nil
}
