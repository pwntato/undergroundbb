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

	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// ErrReactionTargetGone: the comment the reaction is on does not exist. Nothing
// was written.
var ErrReactionTargetGone = errors.New("db: the comment being reacted to is gone")

func reactionKey(postID, target, reactorID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: PostPartition(postID)},
		"SK": &types.AttributeValueMemberS{Value: ReactionSortKeyPrefix + target + "#" + reactorID},
	}
}

// PutReactionInput is one reaction. The handler has checked the sizes.
type PutReactionInput struct {
	GroupID     string
	PostID      string
	PostSortKey string
	// PostTTL is the post's TTL as the handler just read it, copied onto the
	// reaction; the transaction still checks the post exists and has not
	// expired. It is never computed from the time of the write, which would put
	// a creation time on the row in the clear.
	PostTTL int64
	// Target is the comment path, or PostLevelReactionTarget for the post.
	Target     string
	ReactorID  string
	Generation int64
	Nonce      []byte
	Ciphertext []byte
	// ReactorKeyEpoch, MarkerPresent and MarkerGeneration are pinned in the
	// transaction exactly as CreateCommentInput pins them.
	ReactorKeyEpoch  uint64
	MarkerPresent    bool
	MarkerGeneration int64
	Now              time.Time
}

// PutReaction writes a reaction in one transaction with the checks that make
// the write safe (the same as CreateComment's, and the comment it is on must
// still exist). A reaction is keyed by its reactor, so the write replaces the
// reactor's earlier one on that target and a resend is the same row again:
// one reaction per user per target, and nothing to confirm on a retry.
func (c *Client) PutReaction(ctx context.Context, in PutReactionInput) error {
	item, err := attributevalue.MarshalMap(models.Reaction{
		Record: models.Record{
			PK:   PostPartition(in.PostID),
			SK:   ReactionSortKeyPrefix + in.Target + "#" + in.ReactorID,
			Type: "REACTION",
		},
		Generation: in.Generation,
		Nonce:      in.Nonce,
		Ciphertext: in.Ciphertext,
		TTL:        in.PostTTL,
	})
	if err != nil {
		return fmt.Errorf("db: marshal reaction: %w", err)
	}
	items := []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(c.table), Item: item}},
		{ConditionCheck: &types.ConditionCheck{
			TableName:                aws.String(c.table),
			Key:                      map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: "GROUP#" + in.GroupID}, "SK": &types.AttributeValueMemberS{Value: in.PostSortKey}},
			ConditionExpression:      aws.String("attribute_exists(PK) AND (attribute_not_exists(#ttl) OR #ttl > :now)"),
			ExpressionAttributeNames: map[string]string{"#ttl": "TTL"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":now": &types.AttributeValueMemberN{Value: strconv.FormatInt(in.Now.Unix(), 10)},
			},
		}},
		{ConditionCheck: &types.ConditionCheck{
			TableName:                aws.String(c.table),
			Key:                      memberKey(in.GroupID, in.ReactorID),
			ConditionExpression:      aws.String("#gen >= :gen AND " + epochEquals("WrapEpoch", ":wep", in.ReactorKeyEpoch)),
			ExpressionAttributeNames: map[string]string{"#gen": "Generation"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":gen": genAttr(in.Generation),
				":wep": epochAttr(in.ReactorKeyEpoch),
			},
		}},
		c.keyEpochCheck(in.ReactorID, in.ReactorKeyEpoch),
		c.markerCheck(in.GroupID, in.MarkerGeneration, in.MarkerPresent),
	}
	const (
		postIndex   = 1
		memberIndex = 2
		epochIndex  = 3
		markerIndex = 4
	)
	targetIndex := -1
	if in.Target != PostLevelReactionTarget {
		targetIndex = len(items)
		items = append(items, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName:           aws.String(c.table),
			Key:                 commentKey(in.PostID, in.Target),
			ConditionExpression: aws.String("attribute_exists(PK)"),
		}})
	}
	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	switch {
	case err == nil:
		return nil
	case isConditionalCheckFailure(err, postIndex):
		return ErrCommentPostGone
	case targetIndex >= 0 && isConditionalCheckFailure(err, targetIndex):
		return ErrReactionTargetGone
	case isConditionalCheckFailure(err, memberIndex):
		return ErrPostMemberChanged
	case isConditionalCheckFailure(err, epochIndex):
		return ErrWrapEpochStale
	case isConditionalCheckFailure(err, markerIndex):
		return ErrPostMarkerChanged
	case isTransactionConflict(err):
		return ErrRoleChangeConflict
	}
	return fmt.Errorf("db: put reaction: %w", err)
}

// DeleteReaction removes the reactor's reaction on a target. Removing one that
// is not there is not an error, so undoing is safe to repeat. It reads no key
// and checks no generation: taking back what you said needs neither.
func (c *Client) DeleteReaction(ctx context.Context, postID, target, reactorID string) error {
	if _, ok := idgen.ValidCommentPath(target); !ok && target != PostLevelReactionTarget {
		return fmt.Errorf("db: delete reaction: bad target %q", target)
	}
	_, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(c.table),
		Key:       reactionKey(postID, target, reactorID),
	})
	if err != nil {
		return fmt.Errorf("db: delete reaction: %w", err)
	}
	return nil
}
