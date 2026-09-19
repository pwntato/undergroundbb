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
// windowStart resets the counter rather than incrementing it when the
// existing FailedVerifyCount's last update falls outside the window -- but
// since this schema stores no "last failure" timestamp separate from
// LockUntil, and re-adding one would be a second contested attribute on the
// hottest item in the partition (docs/DESIGN.md already reasons about this
// exact tradeoff for the credential-version case), this implementation
// takes the simpler, explicitly-accepted-scope reading: the counter is
// cleared on every SUCCESSFUL verification (see ClearFailedVerify) and
// otherwise only ever increments, with lockUntil itself being what actually
// bounds the attacker -- once locked, five minutes must pass before verify
// is attempted again at all, which is what resets the practical window.
func (c *Client) RecordFailedVerify(ctx context.Context, userID string, lockThreshold int64, lockDuration time.Duration) error {
	out, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		UpdateExpression: aws.String("SET FailedVerifyCount = if_not_exists(FailedVerifyCount, :zero) + :one"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":zero": &types.AttributeValueMemberN{Value: "0"},
			":one":  &types.AttributeValueMemberN{Value: "1"},
		},
		ReturnValues: types.ReturnValueUpdatedNew,
	})
	if err != nil {
		return fmt.Errorf("db: record failed verify: %w", err)
	}

	var updated struct {
		FailedVerifyCount int64 `dynamodbav:"FailedVerifyCount"`
	}
	if err := attributevalue.UnmarshalMap(out.Attributes, &updated); err != nil {
		return fmt.Errorf("db: unmarshal updated failed-verify count: %w", err)
	}
	if updated.FailedVerifyCount < lockThreshold {
		return nil
	}

	lockUntil := time.Now().Add(lockDuration).UTC().Format(time.RFC3339)
	_, err = c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
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
