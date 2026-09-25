package db

import (
	"context"
	"fmt"
	"time"

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

// RecordFailedRecoveryVerify increments userID's RECOVERY item's
// FailedVerifyCount and, if this failure is the lockThreshold-th within the
// counting window, sets its LockUntil. Issue #136 -- the recovery-code twin
// of login.go's RecordFailedVerify, same rolling-window design (LockUntil
// itself as the window marker, an attempted conditional reset before a
// plain increment; see that function's own doc comment for the full
// reasoning) but counting failed recovery-verifier checks
// (resolveRecovery, internal/handlers/recovery.go) against the RECOVERY
// item instead of failed login signatures against PROFILE.
//
// Deliberately a distinct counter from User.FailedVerifyCount/LockUntil --
// see resolveRecovery's own doc comment for why the two must never share
// state.
func (c *Client) RecordFailedRecoveryVerify(ctx context.Context, userID string, lockThreshold int64, lockDuration time.Duration) error {
	key := map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
		"SK": &types.AttributeValueMemberS{Value: "RECOVERY"},
	}
	now := time.Now().UTC().Format(time.RFC3339)

	resetOut, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(c.table),
		Key:                 key,
		UpdateExpression:    aws.String("SET FailedVerifyCount = :one REMOVE LockUntil"),
		ConditionExpression: aws.String("attribute_exists(LockUntil) AND LockUntil < :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one": &types.AttributeValueMemberN{Value: "1"},
			":now": &types.AttributeValueMemberS{Value: now},
		},
		ReturnValues: types.ReturnValueUpdatedNew,
	})

	var updated struct {
		FailedVerifyCount int64 `dynamodbav:"FailedVerifyCount"`
	}
	switch {
	case err == nil:
		// The expired-lock reset applied: this failure starts a fresh budget
		// at 1, well under lockThreshold (which is > 1 in every real
		// configuration), so there's nothing further to do.
		if uErr := attributevalue.UnmarshalMap(resetOut.Attributes, &updated); uErr != nil {
			return fmt.Errorf("db: unmarshal reset failed-recovery-verify count: %w", uErr)
		}
		if updated.FailedVerifyCount < lockThreshold {
			return nil
		}
	case isUpdateConditionFailure(err):
		// No lock, or a lock still in effect -- normal increment path.
		incOut, incErr := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName:        aws.String(c.table),
			Key:              key,
			UpdateExpression: aws.String("SET FailedVerifyCount = if_not_exists(FailedVerifyCount, :zero) + :one"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":zero": &types.AttributeValueMemberN{Value: "0"},
				":one":  &types.AttributeValueMemberN{Value: "1"},
			},
			ReturnValues: types.ReturnValueUpdatedNew,
		})
		if incErr != nil {
			return fmt.Errorf("db: record failed recovery verify: %w", incErr)
		}
		if uErr := attributevalue.UnmarshalMap(incOut.Attributes, &updated); uErr != nil {
			return fmt.Errorf("db: unmarshal updated failed-recovery-verify count: %w", uErr)
		}
		if updated.FailedVerifyCount < lockThreshold {
			return nil
		}
	default:
		return fmt.Errorf("db: record failed recovery verify: %w", err)
	}

	lockUntil := time.Now().Add(lockDuration).UTC().Format(time.RFC3339)
	_, err = c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(c.table),
		Key:              key,
		UpdateExpression: aws.String("SET LockUntil = :lockUntil"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":lockUntil": &types.AttributeValueMemberS{Value: lockUntil},
		},
	})
	if err != nil {
		return fmt.Errorf("db: set recovery lock until: %w", err)
	}
	return nil
}

// ClearFailedRecoveryVerify resets userID's RECOVERY item's
// FailedVerifyCount and LockUntil after a successful recovery-verifier
// check. Issue #136 -- the recovery-code twin of login.go's
// ClearFailedVerify.
func (c *Client) ClearFailedRecoveryVerify(ctx context.Context, userID string) error {
	_, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "RECOVERY"},
		},
		UpdateExpression: aws.String("REMOVE FailedVerifyCount, LockUntil"),
	})
	if err != nil {
		return fmt.Errorf("db: clear failed recovery verify: %w", err)
	}
	return nil
}
