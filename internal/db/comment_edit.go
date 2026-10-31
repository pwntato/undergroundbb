package db

import (
	"bytes"
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

// ErrCommentGone: the comment being edited does not exist, or is a tombstone.
// Nothing was written.
var ErrCommentGone = errors.New("db: the comment is gone")

// GetComment reads one comment row with a consistent read; nil when it does
// not exist. A tombstone is returned (Deleted set).
func (c *Client) GetComment(ctx context.Context, postID, path string) (*models.Comment, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(c.table),
		ConsistentRead: aws.Bool(true),
		Key:            commentKey(postID, path),
	})
	if err != nil {
		return nil, fmt.Errorf("db: get comment: %w", err)
	}
	if out.Item == nil {
		return nil, nil
	}
	var cm models.Comment
	if err := attributevalue.UnmarshalMap(out.Item, &cm); err != nil {
		return nil, fmt.Errorf("db: unmarshal comment: %w", err)
	}
	return &cm, nil
}

// EditCommentInput is a comment's new sealed text. The handler has verified the
// signature, the signing day and that the caller wrote the comment.
type EditCommentInput struct {
	GroupID      string
	PostID       string
	PostSortKey  string
	Path         string
	AuthorUserID string
	Generation   int64
	SignedDay    string
	Nonce        []byte
	Ciphertext   []byte
	Signature    []byte
	// PriorNonce is the nonce of the edition the handler read and is replacing;
	// the write is conditional on it still being the stored one, so two edits
	// racing cannot both replace the same edition.
	PriorNonce       []byte
	AuthorKeyEpoch   uint64
	MarkerPresent    bool
	MarkerGeneration int64
	Now              time.Time
}

// Matches reports whether the stored comment already holds exactly these
// bytes, so a resend after a lost response is answered by what was written.
func (in EditCommentInput) Matches(have *models.Comment) bool {
	return have != nil && !have.Deleted && have.AuthorUserID == in.AuthorUserID && have.Generation == in.Generation &&
		have.SignedDay == in.SignedDay && bytes.Equal(have.Nonce, in.Nonce) &&
		bytes.Equal(have.Ciphertext, in.Ciphertext) && bytes.Equal(have.Signature, in.Signature)
}

// ReusesNonce reports whether the edit would seal under a nonce the comment has
// already used. The current nonce may be repeated only with the same
// ciphertext, which is the same plaintext sealed once and signed again (a
// client signing a lost-response resend after midnight); any other use of it,
// or any use of an earlier edition's nonce, is a reuse.
func (in EditCommentInput) ReusesNonce(have *models.Comment) bool {
	return reusesNonce(have.Nonce, have.Ciphertext, have.UsedNonces, in.Nonce, in.Ciphertext)
}

// reusesNonce is the rule both comments and posts follow; see ReusesNonce.
func reusesNonce(curNonce, curCiphertext []byte, used [][]byte, nonce, ciphertext []byte) bool {
	if bytes.Equal(nonce, curNonce) {
		return !bytes.Equal(ciphertext, curCiphertext)
	}
	for _, u := range used {
		if bytes.Equal(nonce, u) {
			return true
		}
	}
	return false
}

// EditComment replaces a comment's sealed text in one transaction with the
// checks CreateComment makes (live post, current member holding the
// generation, keys at the epoch, rotation marker) and one more: the row must
// still be a live comment written by AuthorUserID. A tombstone cannot be
// edited back to life.
func (c *Client) EditComment(ctx context.Context, in EditCommentInput) error {
	// The row must still hold the edition the handler read (PriorNonce) and the
	// new nonce must not be a superseded one. A new nonce files the old one
	// away; the same nonce is only a fresh signature over the same ciphertext.
	values := map[string]types.AttributeValue{
		":gen":    genAttr(in.Generation),
		":day":    &types.AttributeValueMemberS{Value: in.SignedDay},
		":nonce":  &types.AttributeValueMemberB{Value: in.Nonce},
		":ct":     &types.AttributeValueMemberB{Value: in.Ciphertext},
		":sig":    &types.AttributeValueMemberB{Value: in.Signature},
		":author": &types.AttributeValueMemberS{Value: in.AuthorUserID},
		":prior":  &types.AttributeValueMemberB{Value: in.PriorNonce},
	}
	expr := "SET #gen = :gen, SignedDay = :day, Nonce = :nonce, Ciphertext = :ct, Signature = :sig"
	cond := "attribute_exists(PK) AND attribute_not_exists(Deleted) AND AuthorUserID = :author AND Nonce = :prior" +
		" AND NOT contains(UsedNonces, :nonce)"
	if bytes.Equal(in.Nonce, in.PriorNonce) {
		cond += " AND Ciphertext = :ct"
	} else {
		expr += " ADD UsedNonces :used"
		values[":used"] = &types.AttributeValueMemberBS{Value: [][]byte{in.PriorNonce}}
	}
	update := types.TransactWriteItem{Update: &types.Update{
		TableName:                 aws.String(c.table),
		Key:                       commentKey(in.PostID, in.Path),
		UpdateExpression:          aws.String(expr),
		ConditionExpression:       aws.String(cond),
		ExpressionAttributeNames:  map[string]string{"#gen": "Generation"},
		ExpressionAttributeValues: values,
	}}
	items := []types.TransactWriteItem{
		update,
		{ConditionCheck: &types.ConditionCheck{
			TableName:                aws.String(c.table),
			Key:                      map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: "GROUP#" + in.GroupID}, "SK": &types.AttributeValueMemberS{Value: in.PostSortKey}},
			ConditionExpression:      aws.String("attribute_exists(PK) AND attribute_not_exists(Deleted) AND (attribute_not_exists(#ttl) OR #ttl > :now)"),
			ExpressionAttributeNames: map[string]string{"#ttl": "TTL"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":now": &types.AttributeValueMemberN{Value: strconv.FormatInt(in.Now.Unix(), 10)},
			},
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
		commentIndex = 0
		postIndex    = 1
		memberIndex  = 2
		epochIndex   = 3
		markerIndex  = 4
	)
	_, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	switch {
	case err == nil:
		return nil
	case isConditionalCheckFailure(err, commentIndex):
		// Gone, or another edit got there first (or the nonce was filed away
		// meanwhile); the client reads again to find out which.
		if have, gerr := c.GetComment(ctx, in.PostID, in.Path); gerr == nil && (have == nil || have.Deleted) {
			return ErrCommentGone
		}
		return ErrRoleChangeConflict
	case isConditionalCheckFailure(err, postIndex):
		return ErrCommentPostGone
	case isConditionalCheckFailure(err, memberIndex):
		return ErrPostMemberChanged
	case isConditionalCheckFailure(err, epochIndex):
		return ErrWrapEpochStale
	case isConditionalCheckFailure(err, markerIndex):
		return ErrPostMarkerChanged
	case isTransactionConflict(err):
		return ErrRoleChangeConflict
	}
	return fmt.Errorf("db: edit comment: %w", err)
}

// DeleteComment turns a comment into a tombstone and then removes every
// reaction on it. The row stays, so its replies keep their place; the text,
// nonce, signature, signing day and generation go, and Deleted is set. Deleting
// a tombstone is not an error, and the sweep runs again, so a delete that
// stopped half way is finished by repeating it.
//
// The tombstone is written first, and PutReaction's transaction checks the
// comment is not one, so no reaction can land after it: the sweep that follows
// sees them all. Until the sweep ends the reader ignores reactions on a
// tombstone anyway (getThread drops them). ErrCommentGone when the row does
// not exist.
func (c *Client) DeleteComment(ctx context.Context, postID, path string) error {
	_, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(c.table),
		Key:                      commentKey(postID, path),
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
			return ErrCommentGone
		}
		return fmt.Errorf("db: delete comment: %w", err)
	}
	return c.sweepReactions(ctx, postID, path)
}

// sweepReactions deletes every reaction on one comment: the keys that begin
// RXN#<path># (the closing '#' keeps a reply's "<path>.0001" out).
func (c *Client) sweepReactions(ctx context.Context, postID, path string) error {
	var start map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: PostPartition(postID)},
				":sk": &types.AttributeValueMemberS{Value: ReactionSortKeyPrefix + path + "#"},
			},
			ProjectionExpression: aws.String("PK, SK"),
			ConsistentRead:       aws.Bool(true),
			ExclusiveStartKey:    start,
		})
		if err != nil {
			return fmt.Errorf("db: sweep reactions: %w", err)
		}
		keys := make([]map[string]types.AttributeValue, 0, len(out.Items))
		for _, it := range out.Items {
			keys = append(keys, map[string]types.AttributeValue{"PK": it["PK"], "SK": it["SK"]})
		}
		if err := c.batchDelete(ctx, keys); err != nil {
			return fmt.Errorf("db: sweep reactions: %w", err)
		}
		if len(out.LastEvaluatedKey) == 0 {
			return nil
		}
		start = out.LastEvaluatedKey
	}
}
