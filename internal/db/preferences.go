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

// SetPreferences replaces PROFILE.PreferencesBlob (#366) with ciphertext the
// server never opens. The blob is sealed under a key derived from the X25519
// private key, so a write sealed under a key a rotation has since replaced
// would be unreadable: the write is conditioned on the KeyEpoch the client
// sealed for, and a mismatch is ErrKeyEpochStale (the client reloads). A
// missing or tombstoned account is ErrUserNotFound.
func (c *Client) SetPreferences(ctx context.Context, userID string, expectedKeyEpoch uint64, blob models.WrappedBlob) error {
	av, err := attributevalue.Marshal(blob)
	if err != nil {
		return fmt.Errorf("db: marshal preferences: %w", err)
	}
	cond := "attribute_exists(PK) AND attribute_not_exists(DeletedAt) AND KeyEpoch = :epoch"
	if expectedKeyEpoch == 0 {
		cond = "attribute_exists(PK) AND attribute_not_exists(DeletedAt) AND (attribute_not_exists(KeyEpoch) OR KeyEpoch = :epoch)"
	}
	epoch, err := attributevalue.Marshal(expectedKeyEpoch)
	if err != nil {
		return fmt.Errorf("db: marshal key epoch: %w", err)
	}
	_, err = c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		UpdateExpression:                    aws.String("SET PreferencesBlob = :prefs"),
		ConditionExpression:                 aws.String(cond),
		ExpressionAttributeValues:           map[string]types.AttributeValue{":prefs": av, ":epoch": epoch},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			// Which condition failed decides the answer: a gone account is
			// not found, a moved epoch is stale.
			if len(ccf.Item) == 0 {
				return ErrUserNotFound
			}
			if _, deleted := ccf.Item["DeletedAt"]; deleted {
				return ErrUserNotFound
			}
			return ErrKeyEpochStale
		}
		return fmt.Errorf("db: set preferences: %w", err)
	}
	return nil
}
