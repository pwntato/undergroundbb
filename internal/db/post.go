package db

import (
	"bytes"
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

var (
	// ErrPostMemberChanged: the author's membership is gone, behind the post's
	// generation, or wrapped to another key epoch than the handler read. Nothing
	// was written; the client reloads and signs again.
	ErrPostMemberChanged = errors.New("db: the author's membership changed")
	// ErrPostExists: a post already holds this sort key with different content.
	ErrPostExists = errors.New("db: a different post already holds this address")
)

// PostSortKeyPrefix begins every POST# sort key.
const PostSortKeyPrefix = "POST#"

// CreatePostInput is one signed post. The handler has already verified
// Signature against the author's current key and checked the day; like every
// signature this package stores, db does not check it.
type CreatePostInput struct {
	GroupID      string
	SortKey      string
	AuthorUserID string
	Generation   int64
	Nonce        []byte
	Ciphertext   []byte
	Signature    []byte
	// AuthorKeyEpoch is the author's KeyEpoch as the handler read it; the
	// membership's WrapEpoch must equal it (not dormant) and PROFILE must still
	// hold it, both in the write's own transaction.
	AuthorKeyEpoch uint64
	// ExpirationDays is the group's policy as the handler read it; 0 means the
	// post never expires.
	ExpirationDays int64
	// Now is the write time the TTL is computed from.
	Now time.Time
}

// CreatePost writes a post in one transaction with the checks that make the
// write safe: the author is still a member holding at least Generation and not
// dormant, and their keys are still at AuthorKeyEpoch. A retry after a lost
// response, with the same bytes, succeeds without writing again; the same
// address with different content is ErrPostExists.
func (c *Client) CreatePost(ctx context.Context, in CreatePostInput) error {
	const (
		postIndex   = 0
		memberIndex = 1
		epochIndex  = 2
	)
	post := models.Post{
		Record: models.Record{
			PK:   "GROUP#" + in.GroupID,
			SK:   in.SortKey,
			Type: "POST",
		},
		AuthorUserID: in.AuthorUserID,
		Generation:   in.Generation,
		Nonce:        in.Nonce,
		Ciphertext:   in.Ciphertext,
		Signature:    in.Signature,
	}
	if in.ExpirationDays > 0 {
		post.TTL = RoundUpToEndOfUTCDay(in.Now.AddDate(0, 0, int(in.ExpirationDays))).Unix()
	}
	item, err := attributevalue.MarshalMap(post)
	if err != nil {
		return fmt.Errorf("db: marshal post: %w", err)
	}
	items := []types.TransactWriteItem{
		{Put: &types.Put{
			TableName:           aws.String(c.table),
			Item:                item,
			ConditionExpression: aws.String("attribute_not_exists(PK)"),
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
	}
	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	switch {
	case err == nil:
		return nil
	case isConditionalCheckFailure(err, postIndex):
		return c.confirmSamePost(ctx, in)
	case isConditionalCheckFailure(err, memberIndex):
		return ErrPostMemberChanged
	case isConditionalCheckFailure(err, epochIndex):
		return ErrWrapEpochStale
	case isTransactionConflict(err):
		return ErrRoleChangeConflict
	}
	return fmt.Errorf("db: create post: %w", err)
}

// confirmSamePost decides a retry: nil when the stored post is this request's
// bytes, ErrPostExists when it is anything else.
func (c *Client) confirmSamePost(ctx context.Context, in CreatePostInput) error {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(c.table),
		ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + in.GroupID},
			"SK": &types.AttributeValueMemberS{Value: in.SortKey},
		},
	})
	if err != nil {
		return fmt.Errorf("db: read existing post: %w", err)
	}
	if out.Item == nil {
		// Expired or removed between the two calls; the client retries.
		return ErrRoleChangeConflict
	}
	var have models.Post
	if err := attributevalue.UnmarshalMap(out.Item, &have); err != nil {
		return fmt.Errorf("db: unmarshal existing post: %w", err)
	}
	if have.AuthorUserID == in.AuthorUserID && have.Generation == in.Generation &&
		bytes.Equal(have.Nonce, in.Nonce) && bytes.Equal(have.Ciphertext, in.Ciphertext) &&
		bytes.Equal(have.Signature, in.Signature) {
		return nil
	}
	return ErrPostExists
}
