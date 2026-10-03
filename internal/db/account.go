package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

var (
	// ErrStillMember: the account still holds a membership. Account deletion
	// never removes one itself, because leaving a group is what signs the
	// leaver's demotion and enforces the last-admin rule (#66). The client
	// leaves every group first.
	ErrStillMember = errors.New("db: account still belongs to a group; leave every group first")
	// ErrAccountCleanupIncomplete accompanies a successful deletion when some
	// of the user's own rows (pins, sent or received invites, challenge) could
	// not all be removed. The account is already unreachable; the leftovers
	// are harmless and the same call can be repeated to finish.
	ErrAccountCleanupIncomplete = errors.New("db: account deleted but some rows remain")
)

// DeleteAccount deletes userID's account -- issue #77.
//
// It refuses (ErrStillMember) while any membership exists. Otherwise one
// transaction tombstones PROFILE (DeletedAt set; Username, Salt, wrapped
// private keys, preferences and lock state removed; public keys kept so grants
// and signatures the user made still verify), deletes the USERNAME claim
// (conditioned on it still naming this user, so the name is free again) and
// deletes the RECOVERY item. Login resolves through the claim, so the account
// can no longer be signed in to. A repeated call on an already-tombstoned
// account skips the transaction and only repeats the cleanup, which is how an
// ErrAccountCleanupIncomplete is finished.
//
// PROFILE is never deleted: user uuids are never reused (docs/DESIGN.md, AAD
// table), and CompleteInvite refuses to add a membership to a tombstone.
// The membership check and the tombstone are separate steps, so a membership
// completed between them survives the deletion. That fails safe: the row is
// visible to the group as a member whose profile is deleted, and an admin can
// remove them with the ordinary removal flow.
//
// A session cookie issued before deletion stays valid until it expires (there
// is no session store); the handler clears the caller's own cookie.
func (c *Client) DeleteAccount(ctx context.Context, userID string) error {
	user, err := c.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.DeletedAt == "" {
		memberships, err := c.queryMembershipsByUser(ctx, userID)
		if err != nil {
			return fmt.Errorf("db: read memberships: %w", err)
		}
		if len(memberships) > 0 {
			return ErrStillMember
		}
		if err := c.tombstoneAccount(ctx, userID, strings.ToLower(user.Username)); err != nil {
			return err
		}
	}
	if err := c.sweepUserRows(ctx, userID); err != nil {
		return fmt.Errorf("%w: %v", ErrAccountCleanupIncomplete, err)
	}
	return nil
}

func (c *Client) tombstoneAccount(ctx context.Context, userID, usernameLower string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	const (
		profileIndex = 0
		claimIndex   = 1
	)
	_, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Update: &types.Update{
				TableName: aws.String(c.table),
				Key: map[string]types.AttributeValue{
					"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
					"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
				},
				UpdateExpression: aws.String("SET DeletedAt = :now, Username = :empty " +
					"REMOVE Salt, Argon2Params, WrappedPrivateKeys, PreferencesBlob, FailedVerifyCount, LockUntil"),
				ConditionExpression: aws.String("attribute_exists(PK) AND attribute_not_exists(DeletedAt)"),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":now":   &types.AttributeValueMemberS{Value: now},
					":empty": &types.AttributeValueMemberS{Value: ""},
				},
			}},
			{Delete: &types.Delete{
				TableName: aws.String(c.table),
				Key: map[string]types.AttributeValue{
					"PK": &types.AttributeValueMemberS{Value: "USERNAME#" + usernameLower},
					"SK": &types.AttributeValueMemberS{Value: "CLAIM"},
				},
				ConditionExpression: aws.String("UserID = :uid"),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":uid": &types.AttributeValueMemberS{Value: userID},
				},
			}},
			{Delete: &types.Delete{
				TableName: aws.String(c.table),
				Key: map[string]types.AttributeValue{
					"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
					"SK": &types.AttributeValueMemberS{Value: "RECOVERY"},
				},
			}},
		},
	})
	if err != nil {
		if isConditionalCheckFailure(err, profileIndex) {
			// Deleted concurrently: the other call finished the tombstone.
			return nil
		}
		if isConditionalCheckFailure(err, claimIndex) || isTransactionConflict(err) {
			return fmt.Errorf("db: account changed during deletion, retry: %w", err)
		}
		return err
	}
	return nil
}

// sweepUserRows removes the user's own PIN#, SENT# and CHALLENGE rows, the
// INVITE# row behind each SENT#, and the invites addressed to them (the GSI1
// "INVITE#" reverse lookup). Invites others sent are removed because the
// invitee can no longer complete them. A SENT# copy held by another inviter
// for an invite addressed to this user is left to its TTL.
func (c *Client) sweepUserRows(ctx context.Context, userID string) error {
	var keys []map[string]types.AttributeValue
	var start map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			KeyConditionExpression: aws.String("PK = :pk"),
			ProjectionExpression:   aws.String("PK, SK, InviteID"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "USER#" + userID},
			},
			ExclusiveStartKey: start,
			ConsistentRead:    aws.Bool(true),
		})
		if err != nil {
			return err
		}
		for _, it := range out.Items {
			sk, _ := it["SK"].(*types.AttributeValueMemberS)
			if sk == nil {
				continue
			}
			switch {
			case strings.HasPrefix(sk.Value, "PIN#"), sk.Value == "CHALLENGE":
			case strings.HasPrefix(sk.Value, "SENT#"):
				if iid, ok := it["InviteID"].(*types.AttributeValueMemberS); ok && iid.Value != "" {
					keys = append(keys, map[string]types.AttributeValue{
						"PK": &types.AttributeValueMemberS{Value: "INVITE#" + iid.Value},
						"SK": &types.AttributeValueMemberS{Value: "META"},
					})
				}
			default:
				// PROFILE (tombstone) and anything unrecognised stay.
				continue
			}
			keys = append(keys, map[string]types.AttributeValue{"PK": it["PK"], "SK": it["SK"]})
		}
		if out.LastEvaluatedKey == nil {
			break
		}
		start = out.LastEvaluatedKey
	}
	start = nil
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			IndexName:              aws.String("GSI1"),
			KeyConditionExpression: aws.String("GSI1PK = :pk AND begins_with(GSI1SK, :sk)"),
			ProjectionExpression:   aws.String("PK, SK"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "USER#" + userID},
				":sk": &types.AttributeValueMemberS{Value: "INVITE#"},
			},
			ExclusiveStartKey: start,
		})
		if err != nil {
			return err
		}
		for _, it := range out.Items {
			keys = append(keys, map[string]types.AttributeValue{"PK": it["PK"], "SK": it["SK"]})
		}
		if out.LastEvaluatedKey == nil {
			break
		}
		start = out.LastEvaluatedKey
	}
	return c.batchDelete(ctx, dedupeKeys(keys))
}

// dedupeKeys drops repeated PK/SK pairs: BatchWriteItem rejects a request that
// names one key twice, which a batch spanning two queries could otherwise do.
func dedupeKeys(keys []map[string]types.AttributeValue) []map[string]types.AttributeValue {
	seen := make(map[string]bool, len(keys))
	out := keys[:0:0]
	for _, k := range keys {
		pk, _ := k["PK"].(*types.AttributeValueMemberS)
		sk, _ := k["SK"].(*types.AttributeValueMemberS)
		if pk == nil || sk == nil {
			continue
		}
		id := pk.Value + "\x00" + sk.Value
		if !seen[id] {
			seen[id] = true
			out = append(out, k)
		}
	}
	return out
}
