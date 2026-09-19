package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// ErrUserNotFound is returned when a username's claim, or the PROFILE item
// it points at, does not exist.
var ErrUserNotFound = errors.New("db: user not found")

// LookupUserByUsername resolves usernameLower through the USERNAME#<lower>
// claim to the uuid it names, then reads that user's PROFILE. Returns
// ErrUserNotFound if either the claim or the profile is missing -- callers
// must not distinguish the two to an unauthenticated caller (see
// docs/DESIGN.md on enumeration being an accepted, not a hidden, property
// only where the design says so explicitly; this method itself makes no
// claim about what a handler does with the distinction).
func (c *Client) LookupUserByUsername(ctx context.Context, usernameLower string) (*models.User, error) {
	claimOut, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USERNAME#" + usernameLower},
			"SK": &types.AttributeValueMemberS{Value: "CLAIM"},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("db: lookup username claim: %w", err)
	}
	if claimOut.Item == nil {
		return nil, ErrUserNotFound
	}
	var claim models.UsernameClaim
	if err := attributevalue.UnmarshalMap(claimOut.Item, &claim); err != nil {
		return nil, fmt.Errorf("db: unmarshal username claim: %w", err)
	}

	userOut, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + claim.UserID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("db: get user profile: %w", err)
	}
	if userOut.Item == nil {
		// The claim exists without a profile -- docs/DESIGN.md names this as
		// the quietest of the two signup partial-write routes, foreclosed by
		// Register's transaction, but a caller reading this far back should
		// not assume that transaction is the only writer forever. Report it
		// the same as "no such user" rather than a distinct error: nothing
		// downstream of a login attempt should behave differently for an
		// account that doesn't exist versus one that exists but is broken.
		return nil, ErrUserNotFound
	}
	var user models.User
	if err := attributevalue.UnmarshalMap(userOut.Item, &user); err != nil {
		return nil, fmt.Errorf("db: unmarshal user profile: %w", err)
	}
	return &user, nil
}

// PutChallenge (over)writes the single CHALLENGE slot for userID with a
// fresh nonce and TTL. Unconditional by design -- see models.Challenge and
// issue #27's round-22 comment: the slot is single, keyed without the nonce,
// specifically so this write never grows the partition regardless of how
// often it's called.
func (c *Client) PutChallenge(ctx context.Context, userID string, nonce []byte, ttl time.Duration) error {
	item, err := attributevalue.MarshalMap(models.Challenge{
		Record: models.Record{
			PK:   "USER#" + userID,
			SK:   "CHALLENGE",
			Type: "Challenge",
		},
		Nonce: nonce,
		TTL:   time.Now().Add(ttl).Unix(),
	})
	if err != nil {
		return fmt.Errorf("db: marshal challenge: %w", err)
	}
	_, err = c.ddb.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(c.table),
		Item:      item,
	})
	if err != nil {
		return fmt.Errorf("db: put challenge: %w", err)
	}
	return nil
}

// ErrChallengeMismatch is returned by ConsumeChallenge when there is no
// outstanding challenge for the user, or the one that exists carries a
// different nonce than the caller presented. See ConsumeChallenge's own doc
// comment -- this is NOT a signature failure and callers must not treat it
// as one.
var ErrChallengeMismatch = errors.New("db: no matching outstanding challenge")

// ConsumeChallenge deletes the CHALLENGE item for userID, but only if it
// still holds nonce -- a conditional delete keyed on the nonce VALUE, not
// merely on the item's existence. This is what makes the single-slot design
// (models.Challenge, PutChallenge) safe: because the slot is overwritten
// rather than uniquely keyed, a second PutChallenge call can replace an
// outstanding nonce before the first is used. Conditioning only on
// existence would let a stale client, still holding the FIRST nonce, delete
// (and thereby "spend") a challenge that was actually issued for a later,
// unrelated request -- silently letting one login attempt consume another's
// single-use guarantee. Conditioning on the value closes that: a stale
// nonce's delete fails exactly like an already-consumed one.
//
// See docs/DESIGN.md, "Server deletes the challenge item with a conditional
// write and, only if that delete succeeds, verifies the signature" -- the
// delete is the spend, prior to and independent of signature verification.
// A failed delete (ErrChallengeMismatch) covers replay, a flooded/
// overwritten slot, and simple expiry alike; callers must NOT treat it as a
// failed signature verification -- see issue #27's round-24 review comment:
// "a failed conditional delete on the challenge is not a signature failure
// and must not increment the lockout counter."
func (c *Client) ConsumeChallenge(ctx context.Context, userID string, nonce []byte) error {
	_, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "CHALLENGE"},
		},
		ConditionExpression: aws.String("Nonce = :nonce"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":nonce": &types.AttributeValueMemberB{Value: nonce},
		},
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return ErrChallengeMismatch
		}
		return fmt.Errorf("db: consume challenge: %w", err)
	}
	return nil
}

// RecordFailedVerify increments userID's FailedVerifyCount and, if this
// failure is the 5th within the counting window, sets LockUntil. See
// docs/DESIGN.md, "five-attempts-in-five-minutes" and "This means the
// server cannot count wrong passwords" -- this counts failed step-4
// signature verifications specifically, never a failed ConsumeChallenge
// (see that method's own doc comment) and never a wrong password (which
// fails inside the browser and never reaches the server at all).
//
// The rolling window is implemented without a second contested attribute
// (no separate "window start" timestamp, which would add write contention
// to the hottest item in the partition -- the same tradeoff docs/DESIGN.md
// already reasons about for the credential-version case): LockUntil is
// itself the window marker. A failure observed while an existing LockUntil
// is in the past resets FailedVerifyCount to 1 instead of incrementing it
// -- the expired lock is exactly the signal that a fresh five-attempt
// budget should start. Implemented as an attempted conditional reset first
// (condition: LockUntil exists and is before now), falling back to a plain
// increment when that condition fails -- which it does both for "never
// locked" (LockUntil absent) and "currently locked" (LockUntil in the
// future), the two cases where incrementing is the right behavior.
//
// PR #117 round-1 review found the earlier version of this function was a
// one-strike latch, not a rolling window: FailedVerifyCount only ever
// incremented and was cleared only by a successful verify, which was
// itself gated behind the lock -- so once a user reached the threshold,
// every single subsequent failure re-locked them for a full lockDuration,
// indefinitely, reproduced live against DynamoDB Local. This is the fix.
func (c *Client) RecordFailedVerify(ctx context.Context, userID string, lockThreshold int64, lockDuration time.Duration) error {
	key := map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
		"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
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
		// The expired-lock reset applied: this failure starts a fresh
		// budget at 1, well under lockThreshold (which is > 1 in every
		// real configuration), so there's nothing further to do.
		if uErr := attributevalue.UnmarshalMap(resetOut.Attributes, &updated); uErr != nil {
			return fmt.Errorf("db: unmarshal reset failed-verify count: %w", uErr)
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
			return fmt.Errorf("db: record failed verify: %w", incErr)
		}
		if uErr := attributevalue.UnmarshalMap(incOut.Attributes, &updated); uErr != nil {
			return fmt.Errorf("db: unmarshal updated failed-verify count: %w", uErr)
		}
		if updated.FailedVerifyCount < lockThreshold {
			return nil
		}
	default:
		return fmt.Errorf("db: record failed verify: %w", err)
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
		return fmt.Errorf("db: set lock until: %w", err)
	}
	return nil
}

// isUpdateConditionFailure reports whether err is a plain UpdateItem's
// ConditionalCheckFailedException -- the single-item equivalent of
// isConditionalCheckFailure in register.go, which instead unwraps a
// TransactWriteItems TransactionCanceledException. The two error shapes are
// unrelated types in the SDK, so a single helper can't cover both.
func isUpdateConditionFailure(err error) bool {
	var condErr *types.ConditionalCheckFailedException
	return errors.As(err, &condErr)
}

// ClearFailedVerify resets userID's FailedVerifyCount and LockUntil after a
// successful verification. See docs/DESIGN.md: "incremented on a failed
// step 4 and cleared on a successful one."
func (c *Client) ClearFailedVerify(ctx context.Context, userID string) error {
	_, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		UpdateExpression: aws.String("REMOVE FailedVerifyCount, LockUntil"),
	})
	if err != nil {
		return fmt.Errorf("db: clear failed verify: %w", err)
	}
	return nil
}
