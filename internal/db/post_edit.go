package db

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// ErrPostGone: the post being edited does not exist, is past its TTL or is a
// tombstone. Nothing was written.
var ErrPostGone = errors.New("db: the post is gone")

func postKey(groupID, sortKey string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
		"SK": &types.AttributeValueMemberS{Value: sortKey},
	}
}

// EditPostInput is a post's new sealed text. The handler has verified the
// signature (over the post's sort key and SignedDay, today) and that the caller
// wrote the post.
type EditPostInput struct {
	GroupID      string
	SortKey      string
	AuthorUserID string
	Generation   int64
	SignedDay    string
	Nonce        []byte
	Ciphertext   []byte
	Signature    []byte
	// PriorNonce is the nonce of the edition the handler read and is replacing;
	// see EditCommentInput.
	PriorNonce       []byte
	AuthorKeyEpoch   uint64
	MarkerPresent    bool
	MarkerGeneration int64
	Now              time.Time
}

// Matches reports whether the stored post already holds exactly these bytes,
// so a resend after a lost response is answered by what was written.
func (in EditPostInput) Matches(have *models.Post) bool {
	return have != nil && !have.Deleted && have.AuthorUserID == in.AuthorUserID && have.Generation == in.Generation &&
		have.SignedDay == in.SignedDay && bytes.Equal(have.Nonce, in.Nonce) &&
		bytes.Equal(have.Ciphertext, in.Ciphertext) && bytes.Equal(have.Signature, in.Signature)
}

// ReusesNonce is EditCommentInput.ReusesNonce for a post.
func (in EditPostInput) ReusesNonce(have *models.Post) bool {
	return reusesNonce(have.Nonce, have.Ciphertext, have.UsedNonces, in.Nonce, in.Ciphertext)
}

// EditPost replaces a post's sealed text in one transaction with the checks
// EditComment makes (current member holding the generation, keys at the epoch,
// rotation marker; the row a live post by AuthorUserID holding the edition
// PriorNonce names; the new nonce not one an earlier edition used). It also
// writes SignedDay, which a post's sort key cannot carry for an edit. A
// tombstone cannot be edited back to life.
func (c *Client) EditPost(ctx context.Context, in EditPostInput) error {
	values := map[string]types.AttributeValue{
		":gen":    genAttr(in.Generation),
		":day":    &types.AttributeValueMemberS{Value: in.SignedDay},
		":nonce":  &types.AttributeValueMemberB{Value: in.Nonce},
		":ct":     &types.AttributeValueMemberB{Value: in.Ciphertext},
		":sig":    &types.AttributeValueMemberB{Value: in.Signature},
		":author": &types.AttributeValueMemberS{Value: in.AuthorUserID},
		":prior":  &types.AttributeValueMemberB{Value: in.PriorNonce},
		":now":    &types.AttributeValueMemberN{Value: strconv.FormatInt(in.Now.Unix(), 10)},
	}
	expr := "SET #gen = :gen, SignedDay = :day, Nonce = :nonce, Ciphertext = :ct, Signature = :sig"
	cond := "attribute_exists(PK) AND attribute_not_exists(Deleted) AND (attribute_not_exists(#ttl) OR #ttl > :now)" +
		" AND AuthorUserID = :author AND Nonce = :prior AND NOT contains(UsedNonces, :nonce)"
	if bytes.Equal(in.Nonce, in.PriorNonce) {
		cond += " AND Ciphertext = :ct"
	} else {
		expr += " ADD UsedNonces :used"
		values[":used"] = &types.AttributeValueMemberBS{Value: [][]byte{in.PriorNonce}}
	}
	items := []types.TransactWriteItem{
		{Update: &types.Update{
			TableName:                 aws.String(c.table),
			Key:                       postKey(in.GroupID, in.SortKey),
			UpdateExpression:          aws.String(expr),
			ConditionExpression:       aws.String(cond),
			ExpressionAttributeNames:  map[string]string{"#gen": "Generation", "#ttl": "TTL"},
			ExpressionAttributeValues: values,
		}},
		{ConditionCheck: &types.ConditionCheck{
			TableName:                aws.String(c.table),
			Key:                      memberKey(in.GroupID, in.AuthorUserID),
			ConditionExpression:      aws.String("#gen >= :gen AND " + epochEquals("WrapEpoch", ":wep", in.AuthorKeyEpoch)),
			ExpressionAttributeNames: map[string]string{"#gen": "Generation"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":gen": genAttr(in.Generation),
				":wep": epochAttr(in.AuthorKeyEpoch),
			},
		}},
		c.keyEpochCheck(in.AuthorUserID, in.AuthorKeyEpoch),
		c.markerCheck(in.GroupID, in.MarkerGeneration, in.MarkerPresent),
	}
	const (
		postIndex   = 0
		memberIndex = 1
		epochIndex  = 2
		markerIndex = 3
	)
	_, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	switch {
	case err == nil:
		return nil
	case isConditionalCheckFailure(err, postIndex):
		// Gone, or another edit got there first (or the nonce was filed away
		// meanwhile); the client reads again to find out which.
		if have, gerr := c.GetPost(ctx, in.GroupID, in.SortKey); gerr == nil && (have == nil || have.Deleted || PostExpired(have, in.Now)) {
			return ErrPostGone
		}
		return ErrRoleChangeConflict
	case isConditionalCheckFailure(err, memberIndex):
		return ErrPostMemberChanged
	case isConditionalCheckFailure(err, epochIndex):
		return ErrWrapEpochStale
	case isConditionalCheckFailure(err, markerIndex):
		return ErrPostMarkerChanged
	case isTransactionConflict(err):
		return ErrRoleChangeConflict
	}
	return fmt.Errorf("db: edit post: %w", err)
}

// DeletePost turns a post into a tombstone and then removes the reactions on
// the post itself. As DeleteComment does: the row stays (its comments keep
// their place, and stay readable), the sealed text and everything that dates
// it go, Deleted is set, repeating the delete finishes a half-done sweep, and
// ErrPostGone says the row does not exist. A deleted post takes no new
// comments or reactions and cannot be edited: their transactions check it is
// not a tombstone. Comments already on it, and their reactions, are untouched.
func (c *Client) DeletePost(ctx context.Context, groupID, sortKey, postID string) error {
	_, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(c.table),
		Key:                      postKey(groupID, sortKey),
		UpdateExpression:         aws.String("SET Deleted = :t REMOVE Nonce, Ciphertext, Signature, SignedDay, UsedNonces, #gen"),
		ConditionExpression:      aws.String("attribute_exists(PK)"),
		ExpressionAttributeNames: map[string]string{"#gen": "Generation"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":t": &types.AttributeValueMemberBOOL{Value: true},
		},
	})
	if err != nil {
		var failed *types.ConditionalCheckFailedException
		if errors.As(err, &failed) {
			return ErrPostGone
		}
		return fmt.Errorf("db: delete post: %w", err)
	}
	return c.sweepReactions(ctx, postID, PostLevelReactionTarget)
}
