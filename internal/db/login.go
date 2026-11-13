package db

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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

// The two challenge slots (#390). A user's outstanding login challenge lives in
// one of exactly two items, so an unauthenticated caller can never grow the
// partition (the bound docs/DESIGN.md's "The challenge is a bounded pair of
// slots per user" paragraph exists to keep), and a flood of requests cannot
// replace the nonce a real user is still deriving a signature for.
const (
	challengeSlotA = "CHALLENGE"
	challengeSlotB = "CHALLENGE#2"
)

// challengeSlots lists both slots in the order IssueChallenge prefers to
// write them.
var challengeSlots = [...]string{challengeSlotA, challengeSlotB}

// challengeIssueAttempts caps IssueChallenge's read-then-write loop. A lost
// race re-reads and then finds the winner's fresh nonce, so a second pass
// nearly always ends it; the cap only stops a pathological loop.
const challengeIssueAttempts = 5

// ErrNoChallengeSlot means neither slot was free to write and neither held a
// nonce with enough life left to hand out. IssueChallenge's own
// ttl > 2*minUsable check makes that impossible; it is returned rather than
// panicked on so a future change to the arithmetic fails one request, not
// the process.
var ErrNoChallengeSlot = errors.New("db: no free login challenge slot")

// challengeSlot is what IssueChallenge reads from one slot.
type challengeSlot struct {
	sk    string
	nonce []byte
	ttl   int64
}

// IssueChallenge returns the nonce to hand to a login attempt for userID. It
// is the answer to #390: the challenge request is unauthenticated, so
// anyone who knows a username can call it in a loop, and a plain overwrite
// let that replace the nonce a real user was still deriving a signature for.
//
// The rule is that a nonce is only ever replaced after it has expired, and
// is only handed out while it has at least minUsable of its life left:
//
//  1. If a slot holds a nonce expiring after now+minUsable, return that one.
//     It is not a secret (the server sends it in plaintext and only a valid
//     signature can spend it), so sharing it with whoever asks, the attacker
//     included, gives them nothing they can use, and the real user's
//     signature still lands.
//  2. Otherwise write candidate into a slot that is absent or already
//     expired, conditionally, so two concurrent requests cannot both
//     overwrite it. A lost race re-reads and returns the winner's nonce.
//
// Why two slots, not one: with one slot, "write a fresh nonce once less than
// minUsable is left" is itself an overwrite of a nonce that was handed out
// moments earlier, so a user who asked just before the refresh would have
// theirs replaced mid-derivation. With two, the nonce being retired keeps
// its slot until it has really expired, and the new one goes in the other.
// That needs ttl > 2*minUsable: a slot is rewritten only once expired, and
// the other one was written no earlier than minUsable before the first
// stopped being fresh, so one of the two is always expired or absent when
// no fresh nonce exists. IssueChallenge refuses arguments that break it.
//
// TTL is the table's TTL attribute and is deliberately not rounded to a day
// (see the note on CHALLENGE in db.go's TTL rounding comment). Items past their TTL can linger until
// DynamoDB sweeps them, so expiry is judged here against now, never by
// whether the item exists. now is a parameter so tests can run a flood
// across minutes of simulated time.
func (c *Client) IssueChallenge(ctx context.Context, userID string, candidate []byte, ttl, minUsable time.Duration, now time.Time) ([]byte, error) {
	if minUsable <= 0 || ttl <= 2*minUsable {
		return nil, fmt.Errorf("db: challenge ttl %s must exceed twice the minimum usable time %s", ttl, minUsable)
	}
	nowSec := now.Unix()
	freshAfter := now.Add(minUsable).Unix()

	for range challengeIssueAttempts {
		slots, err := c.readChallengeSlots(ctx, userID)
		if err != nil {
			return nil, err
		}

		var fresh *challengeSlot
		for i := range slots {
			if slots[i].ttl > freshAfter && (fresh == nil || slots[i].ttl > fresh.ttl) {
				fresh = &slots[i]
			}
		}
		if fresh != nil {
			return fresh.nonce, nil
		}

		target := ""
		for _, sk := range challengeSlots {
			if !slotLive(slots, sk, nowSec) {
				target = sk
				break
			}
		}
		if target == "" {
			return nil, ErrNoChallengeSlot
		}

		item, err := attributevalue.MarshalMap(models.Challenge{
			Record: models.Record{PK: "USER#" + userID, SK: target, Type: "Challenge"},
			Nonce:  candidate,
			TTL:    now.Add(ttl).Unix(),
		})
		if err != nil {
			return nil, fmt.Errorf("db: marshal challenge: %w", err)
		}
		_, err = c.ddb.PutItem(ctx, &dynamodb.PutItemInput{
			TableName:           aws.String(c.table),
			Item:                item,
			ConditionExpression: aws.String("attribute_not_exists(PK) OR #ttl <= :now"),
			ExpressionAttributeNames: map[string]string{
				"#ttl": "TTL",
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":now": &types.AttributeValueMemberN{Value: strconv.FormatInt(nowSec, 10)},
			},
		})
		if err == nil {
			return candidate, nil
		}
		var condErr *types.ConditionalCheckFailedException
		if !errors.As(err, &condErr) {
			return nil, fmt.Errorf("db: put challenge: %w", err)
		}
		// Someone else wrote this slot between our read and our write. Read again:
		// their nonce is now the fresh one.
	}
	return nil, ErrNoChallengeSlot
}

// slotLive reports whether sk holds a nonce that has not expired at nowSec.
func slotLive(slots []challengeSlot, sk string, nowSec int64) bool {
	for _, s := range slots {
		if s.sk == sk {
			return s.ttl > nowSec
		}
	}
	return false
}

// readChallengeSlots reads the user's challenge slots with a strongly
// consistent query: IssueChallenge decides what to hand out from this, and an
// eventually consistent read could miss a nonce written a moment ago.
func (c *Client) readChallengeSlots(ctx context.Context, userID string) ([]challengeSlot, error) {
	out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :c)"),
		ProjectionExpression:   aws.String("SK, Nonce, #ttl"),
		ExpressionAttributeNames: map[string]string{
			"#ttl": "TTL",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "USER#" + userID},
			":c":  &types.AttributeValueMemberS{Value: challengeSlotA},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("db: read challenge slots: %w", err)
	}
	var slots []challengeSlot
	for _, it := range out.Items {
		var row struct {
			SK    string `dynamodbav:"SK"`
			Nonce []byte `dynamodbav:"Nonce"`
			TTL   int64  `dynamodbav:"TTL"`
		}
		if err := attributevalue.UnmarshalMap(it, &row); err != nil {
			return nil, fmt.Errorf("db: unmarshal challenge slot: %w", err)
		}
		if row.SK != challengeSlotA && row.SK != challengeSlotB {
			continue
		}
		slots = append(slots, challengeSlot{sk: row.SK, nonce: row.Nonce, ttl: row.TTL})
	}
	return slots, nil
}

// ErrChallengeMismatch is returned by ConsumeChallenge when there is no
// outstanding challenge for the user, or the one that exists carries a
// different nonce than the caller presented. See ConsumeChallenge's own doc
// comment -- this is NOT a signature failure and callers must not treat it
// as one.
var ErrChallengeMismatch = errors.New("db: no matching outstanding challenge")

// ConsumeChallenge deletes the challenge item for userID that holds nonce --
// a conditional delete keyed on the nonce VALUE, not merely on the item's
// existence -- trying each of the two slots. Keying on the value is what
// makes a bounded set of slots safe: conditioning only on existence would let
// a stale client, still holding an old nonce, delete (and thereby "spend") a
// challenge issued for a later, unrelated request. A stale nonce's delete
// fails exactly like an already-consumed one.
//
// See docs/DESIGN.md, "Server deletes the challenge item with a conditional
// write and, only if that delete succeeds, verifies the signature" -- the
// delete is the spend, prior to and independent of signature verification.
// A failed delete (ErrChallengeMismatch) covers replay, a replaced nonce, and
// simple expiry alike; callers must NOT treat it as a failed signature
// verification -- see issue #27's round-24 review comment: "a failed
// conditional delete on the challenge is not a signature failure and must not
// increment the lockout counter."
func (c *Client) ConsumeChallenge(ctx context.Context, userID string, nonce []byte) error {
	for _, sk := range challengeSlots {
		_, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: aws.String(c.table),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
				"SK": &types.AttributeValueMemberS{Value: sk},
			},
			ConditionExpression: aws.String("Nonce = :nonce"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":nonce": &types.AttributeValueMemberB{Value: nonce},
			},
		})
		if err == nil {
			return nil
		}
		var condErr *types.ConditionalCheckFailedException
		if !errors.As(err, &condErr) {
			return fmt.Errorf("db: consume challenge: %w", err)
		}
	}
	return ErrChallengeMismatch
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
	if err := c.recordFailedVerify(ctx, userID, "PROFILE", lockThreshold, lockDuration); err != nil {
		return fmt.Errorf("db: record failed verify: %w", err)
	}
	return nil
}

// recordFailedVerify is the rolling-window lockout logic itself, shared by
// RecordFailedVerify (PROFILE, login's step-4 signature failures) and
// RecordFailedRecoveryVerify (RECOVERY, resolveRecovery's verifier
// mismatches, issue #136) -- identical in every respect except which item's
// SK it targets. Kept as one implementation, parameterized on sk, rather
// than two copies that could silently drift apart the way PR #117's bug
// crept in -- issue #136 round 1 review nit.
func (c *Client) recordFailedVerify(ctx context.Context, userID, sk string, lockThreshold int64, lockDuration time.Duration) error {
	key := map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
		"SK": &types.AttributeValueMemberS{Value: sk},
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
			return fmt.Errorf("unmarshal reset failed-verify count: %w", uErr)
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
			return fmt.Errorf("record failed verify: %w", incErr)
		}
		if uErr := attributevalue.UnmarshalMap(incOut.Attributes, &updated); uErr != nil {
			return fmt.Errorf("unmarshal updated failed-verify count: %w", uErr)
		}
		if updated.FailedVerifyCount < lockThreshold {
			return nil
		}
	default:
		return fmt.Errorf("record failed verify: %w", err)
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
		return fmt.Errorf("set lock until: %w", err)
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
