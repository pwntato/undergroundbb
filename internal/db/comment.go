package db

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

var (
	// ErrCommentPostGone: the post the comment hangs off is missing or past its
	// TTL. Nothing was written.
	ErrCommentPostGone = errors.New("db: the post is gone")
	// ErrCommentParentGone: the comment's parent comment does not exist, so the
	// path would hang off nothing. Nothing was written.
	ErrCommentParentGone = errors.New("db: the parent comment is gone")
	// ErrCommentPathTaken: a different comment already holds this path (a second
	// replier chose the same next ordinal). Nothing was written; the client
	// asks for the next free path (NextCommentPath), reseals and sends again.
	ErrCommentPathTaken = errors.New("db: a different comment already holds this path")
	// ErrCommentSiblingsFull: the parent already has 9,999 replies, the most
	// four digits can number.
	ErrCommentSiblingsFull = errors.New("db: no free reply number under this comment")
)

// CommentSortKeyPrefix and ReactionSortKeyPrefix begin the CMT# and RXN# sort
// keys of a post's partition.
const (
	CommentSortKeyPrefix  = "CMT#"
	ReactionSortKeyPrefix = "RXN#"
)

// PostPartition is the partition key of everything hanging off a post.
func PostPartition(postID string) string { return "POST#" + postID }

// CreateCommentInput is one signed comment. The handler has verified Signature
// against the author's current key and checked the signing day; db does not.
type CreateCommentInput struct {
	GroupID     string
	PostID      string
	PostSortKey string
	// PostTTL is the post's TTL as the handler just read it, copied onto the
	// comment; the transaction still checks the post exists and has not expired.
	PostTTL      int64
	Path         string
	AuthorUserID string
	Generation   int64
	SignedDay    string
	Nonce        []byte
	Ciphertext   []byte
	Signature    []byte
	// AuthorKeyEpoch, MarkerPresent and MarkerGeneration are pinned in the
	// transaction exactly as CreatePostInput pins them.
	AuthorKeyEpoch   uint64
	MarkerPresent    bool
	MarkerGeneration int64
	// Now is when the write happens, to refuse a post that has just expired.
	Now time.Time
}

// GetPost reads one post row with a consistent read; nil when it does not
// exist. A post past its TTL but not yet deleted is returned: the caller
// decides (PostExpired).
func (c *Client) GetPost(ctx context.Context, groupID, postSortKey string) (*models.Post, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(c.table),
		ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			"SK": &types.AttributeValueMemberS{Value: postSortKey},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("db: get post: %w", err)
	}
	if out.Item == nil {
		return nil, nil
	}
	var p models.Post
	if err := attributevalue.UnmarshalMap(out.Item, &p); err != nil {
		return nil, fmt.Errorf("db: unmarshal post: %w", err)
	}
	return &p, nil
}

// PostExpired reports whether a stored post is past its TTL and so must not
// be shown or commented on, however long DynamoDB takes to delete it.
func PostExpired(p *models.Post, now time.Time) bool {
	return p.TTL != 0 && p.TTL <= now.Unix()
}

func commentKey(postID, path string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: PostPartition(postID)},
		"SK": &types.AttributeValueMemberS{Value: CommentSortKeyPrefix + path},
	}
}

// CreateComment writes a comment in one transaction with the checks that make
// the write safe: the post still exists and has not expired, the parent
// comment (for a reply) still exists, the author is still a non-dormant member
// holding at least Generation with their keys at AuthorKeyEpoch, and the
// group's rotation marker is as the handler read it. The write is conditional
// on the path being free: a retry with the same bytes succeeds without writing
// again, and the same path with different content is ErrCommentPathTaken.
//
// The TTL is the parent post's, copied rather than computed from now, so the
// row says when the post expires and nothing about when the comment was made.
func (c *Client) CreateComment(ctx context.Context, in CreateCommentInput) error {
	comment := models.Comment{
		Record: models.Record{
			PK:   PostPartition(in.PostID),
			SK:   CommentSortKeyPrefix + in.Path,
			Type: "COMMENT",
		},
		AuthorUserID: in.AuthorUserID,
		Generation:   in.Generation,
		SignedDay:    in.SignedDay,
		Nonce:        in.Nonce,
		Ciphertext:   in.Ciphertext,
		Signature:    in.Signature,
		TTL:          in.PostTTL,
	}
	item, err := attributevalue.MarshalMap(comment)
	if err != nil {
		return fmt.Errorf("db: marshal comment: %w", err)
	}
	postCheck := types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName:                aws.String(c.table),
		Key:                      map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: "GROUP#" + in.GroupID}, "SK": &types.AttributeValueMemberS{Value: in.PostSortKey}},
		ConditionExpression:      aws.String("attribute_exists(PK) AND (attribute_not_exists(#ttl) OR #ttl > :now)"),
		ExpressionAttributeNames: map[string]string{"#ttl": "TTL"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now": &types.AttributeValueMemberN{Value: strconv.FormatInt(in.Now.Unix(), 10)},
		},
	}}
	memberCheck := types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName:                aws.String(c.table),
		Key:                      memberKey(in.GroupID, in.AuthorUserID),
		ConditionExpression:      aws.String("#gen >= :gen AND " + epochEquals("WrapEpoch", ":wep", in.AuthorKeyEpoch)),
		ExpressionAttributeNames: map[string]string{"#gen": "Generation"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":gen": genAttr(in.Generation),
			":wep": epochAttr(in.AuthorKeyEpoch),
		},
	}}
	items := []types.TransactWriteItem{
		{Put: &types.Put{
			TableName:           aws.String(c.table),
			Item:                item,
			ConditionExpression: aws.String("attribute_not_exists(PK)"),
		}},
		postCheck,
		memberCheck,
		c.keyEpochCheck(in.AuthorUserID, in.AuthorKeyEpoch),
		c.markerCheck(in.GroupID, in.MarkerGeneration, in.MarkerPresent),
	}
	const (
		putIndex    = 0
		postIndex   = 1
		memberIndex = 2
		epochIndex  = 3
		markerIndex = 4
	)
	parentIndex := -1
	if parent := idgen.CommentParentPath(in.Path); parent != "" {
		parentIndex = len(items)
		items = append(items, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName:           aws.String(c.table),
			Key:                 commentKey(in.PostID, parent),
			ConditionExpression: aws.String("attribute_exists(PK)"),
		}})
	}
	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	switch {
	case err == nil:
		return nil
	case isConditionalCheckFailure(err, putIndex):
		return c.confirmSameComment(ctx, in)
	case isConditionalCheckFailure(err, postIndex):
		return ErrCommentPostGone
	case parentIndex >= 0 && isConditionalCheckFailure(err, parentIndex):
		return ErrCommentParentGone
	case isConditionalCheckFailure(err, memberIndex):
		return ErrPostMemberChanged
	case isConditionalCheckFailure(err, epochIndex):
		return ErrWrapEpochStale
	case isConditionalCheckFailure(err, markerIndex):
		return ErrPostMarkerChanged
	case isTransactionConflict(err):
		return ErrRoleChangeConflict
	}
	return fmt.Errorf("db: create comment: %w", err)
}

// confirmSameComment decides a retry: nil when the stored comment is this
// request's bytes, ErrCommentPathTaken when it is anything else.
func (c *Client) confirmSameComment(ctx context.Context, in CreateCommentInput) error {
	same, exists, err := c.storedCommentMatches(ctx, in)
	switch {
	case err != nil:
		return err
	case !exists:
		// Expired or removed between the two calls; the client retries.
		return ErrRoleChangeConflict
	case same:
		return nil
	}
	return ErrCommentPathTaken
}

// CommentAlreadyStored reports whether a comment with exactly this request's
// bytes is already stored at its path. The handler asks before its freshness
// checks, for the reason PostAlreadyStored gives: a resend after a lost
// response is answered by what was written.
func (c *Client) CommentAlreadyStored(ctx context.Context, in CreateCommentInput) (bool, error) {
	same, _, err := c.storedCommentMatches(ctx, in)
	return same, err
}

func (c *Client) storedCommentMatches(ctx context.Context, in CreateCommentInput) (same, exists bool, err error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(c.table),
		ConsistentRead: aws.Bool(true),
		Key:            commentKey(in.PostID, in.Path),
	})
	if err != nil {
		return false, false, fmt.Errorf("db: get comment: %w", err)
	}
	if out.Item == nil {
		return false, false, nil
	}
	var have models.Comment
	if err := attributevalue.UnmarshalMap(out.Item, &have); err != nil {
		return false, true, fmt.Errorf("db: unmarshal existing comment: %w", err)
	}
	same = have.AuthorUserID == in.AuthorUserID && have.Generation == in.Generation &&
		have.SignedDay == in.SignedDay && bytes.Equal(have.Nonce, in.Nonce) &&
		bytes.Equal(have.Ciphertext, in.Ciphertext) && bytes.Equal(have.Signature, in.Signature)
	return same, true, nil
}

// NextCommentPath returns the first free path under parentPath ("" for a
// top-level comment): one past the highest direct child. The highest key
// beneath a parent is either its last child or a descendant of it, and either
// way its first segments past the parent name that child, so one descending
// query of one item is enough. The handler refuses a path past this one, so
// the numbers under a parent have no gaps.
func (c *Client) NextCommentPath(ctx context.Context, postID, parentPath string) (string, error) {
	prefix := CommentSortKeyPrefix
	if parentPath != "" {
		prefix += parentPath + "."
	}
	out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: PostPartition(postID)},
			":sk": &types.AttributeValueMemberS{Value: prefix},
		},
		ScanIndexForward: aws.Bool(false),
		ConsistentRead:   aws.Bool(true),
		Limit:            aws.Int32(1),
	})
	if err != nil {
		return "", fmt.Errorf("db: next comment path: %w", err)
	}
	next := 1
	if len(out.Items) == 1 {
		sk, ok := out.Items[0]["SK"].(*types.AttributeValueMemberS)
		if !ok || len(sk.Value) < len(prefix)+4 {
			return "", fmt.Errorf("db: next comment path: unexpected key under %s", prefix)
		}
		last, err := strconv.Atoi(sk.Value[len(prefix) : len(prefix)+4])
		if err != nil {
			return "", fmt.Errorf("db: next comment path: %w", err)
		}
		next = last + 1
	}
	if next > 9999 {
		return "", ErrCommentSiblingsFull
	}
	seg := fmt.Sprintf("%04d", next)
	if parentPath == "" {
		return seg, nil
	}
	return parentPath + "." + seg, nil
}

// ListComments returns one page of a post's comments in display order
// (depth-first), starting strictly after the comment at afterPath ("" for the
// first page), plus the last path returned when more follow. The cursor is a
// path rather than a DynamoDB key, so a caller-supplied one can only move
// within this post's partition. A page may be shorter than limit and still
// carry a cursor: a query returns at most 1 MB. Comments share their post's
// TTL, so a caller that has checked the post is live needs no per-comment
// expiry test.
func (c *Client) ListComments(ctx context.Context, postID, afterPath string, limit int) ([]models.Comment, string, error) {
	in := &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: PostPartition(postID)},
			":sk": &types.AttributeValueMemberS{Value: CommentSortKeyPrefix},
		},
		ConsistentRead: aws.Bool(true),
		Limit:          aws.Int32(int32(limit + 1)),
	}
	if afterPath != "" {
		in.ExclusiveStartKey = commentKey(postID, afterPath)
	}
	out, err := c.ddb.Query(ctx, in)
	if err != nil {
		return nil, "", fmt.Errorf("db: list comments: %w", err)
	}
	var comments []models.Comment
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &comments); err != nil {
		return nil, "", fmt.Errorf("db: unmarshal comments: %w", err)
	}
	next := ""
	switch {
	case len(comments) > limit:
		comments = comments[:limit]
		next = strings.TrimPrefix(comments[limit-1].SK, CommentSortKeyPrefix)
	case len(out.LastEvaluatedKey) > 0 && len(comments) > 0:
		// A query stops at 1 MB however high Limit is, and says so only through
		// LastEvaluatedKey. Large comments can fill a page short of limit+1
		// items; without this the reader would take the short page for the end
		// of the thread.
		next = strings.TrimPrefix(comments[len(comments)-1].SK, CommentSortKeyPrefix)
	}
	return comments, next, nil
}

// PostLevelReactionTarget is the <cmtpath> of a reaction on the post itself.
const PostLevelReactionTarget = "0000"

// ListReactions returns the reactions that belong to a page of comments: those
// targeting any comment from firstPath to lastPath in thread order, plus the
// post's own reactions (target 0000) when includePost is set, which the first
// page carries. A reaction's key is RXN#<cmtpath>#<reactor> and the cmtpath
// order is the thread's order, so the page's comments are a contiguous slice
// of the reaction block and one range query reads exactly their reactions.
//
// The upper bound is "RXN#<lastPath>$": '$' sorts after the '#' that follows
// the cmtpath and before the '.' that would begin a descendant's path, so the
// reactions on lastPath are in and those on its replies (a later page) are out.
// There is one reaction per user per target, so the range holds at most the
// page's comments times the group's members.
func (c *Client) ListReactions(ctx context.Context, postID, firstPath, lastPath string, includePost bool) ([]models.Reaction, error) {
	lo, hi := "", ""
	switch {
	case includePost:
		lo = ReactionSortKeyPrefix + PostLevelReactionTarget
	case firstPath != "":
		lo = ReactionSortKeyPrefix + firstPath
	default:
		return nil, nil
	}
	if lastPath != "" {
		hi = ReactionSortKeyPrefix + lastPath + "$"
	} else {
		hi = ReactionSortKeyPrefix + PostLevelReactionTarget + "$"
	}
	var reactions []models.Reaction
	var start map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			KeyConditionExpression: aws.String("PK = :pk AND SK BETWEEN :lo AND :hi"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: PostPartition(postID)},
				":lo": &types.AttributeValueMemberS{Value: lo},
				":hi": &types.AttributeValueMemberS{Value: hi},
			},
			ConsistentRead:    aws.Bool(true),
			ExclusiveStartKey: start,
		})
		if err != nil {
			return nil, fmt.Errorf("db: list reactions: %w", err)
		}
		var page []models.Reaction
		if err := attributevalue.UnmarshalListOfMaps(out.Items, &page); err != nil {
			return nil, fmt.Errorf("db: unmarshal reactions: %w", err)
		}
		reactions = append(reactions, page...)
		if len(out.LastEvaluatedKey) == 0 {
			return reactions, nil
		}
		start = out.LastEvaluatedKey
	}
}
