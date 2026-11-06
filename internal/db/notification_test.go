package db

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go/middleware"
)

func notifCount(t *testing.T, c *Client, userID string) int {
	t.Helper()
	out, err := c.ddb.Query(context.Background(), &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		ConsistentRead:         aws.Bool(true),
		KeyConditionExpression: aws.String("PK = :p AND begins_with(SK, :n)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":p": &types.AttributeValueMemberS{Value: "USER#" + userID},
			":n": &types.AttributeValueMemberS{Value: "NOTIF#"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return int(out.Count)
}

// A notification rides in the transaction of what causes it, so when that transaction is refused
// (here: the post is not there) nobody is told of a comment or reaction that never landed.
func TestARefusedCommentOrReactionWritesNoNotification(t *testing.T) {
	c := testClient(t)
	gid, author, recipient := newUserID(t), newUserID(t), newUserID(t)
	postKey := "POST#2026-10-28#00112233445566ff"
	pid := gid + "#2026-10-28#00112233445566ff"

	err := c.CreateComment(context.Background(), CreateCommentInput{
		GroupID: gid, PostID: pid, PostSortKey: postKey, Path: "0001", AuthorUserID: author,
		NotifyUserID: recipient, Now: time.Now(),
	})
	if err == nil {
		t.Fatal("a comment on a post that is not there was accepted")
	}
	err = c.PutReaction(context.Background(), PutReactionInput{
		GroupID: gid, PostID: pid, PostSortKey: postKey, Target: PostLevelReactionTarget, ReactorID: author,
		NotifyUserID: recipient, Now: time.Now(),
	})
	if err == nil {
		t.Fatal("a reaction on a post that is not there was accepted")
	}
	if n := notifCount(t, c, recipient); n != 0 {
		t.Errorf("%d notifications for things that never landed", n)
	}
}

// racingClient is a client whose requests pass through fn first (Initialize step, before the call
// is sent). fn may return an error to fail the call, or change its input.
func racingClient(c *Client, fn func(op string, in middleware.InitializeInput) error) *Client {
	r := *c
	r.ddb = dynamodb.New(c.ddb.Options(), func(o *dynamodb.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("notification-test",
				func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
					if err := fn(middleware.GetOperationName(ctx), in); err != nil {
						return middleware.InitializeOutput{}, middleware.Metadata{}, err
					}
					return next.HandleInitialize(ctx, in)
				}), middleware.Before)
		})
	})
	return &r
}

func putRow(t *testing.T, c *Client, item map[string]types.AttributeValue) {
	t.Helper()
	if _, err := c.ddb.PutItem(context.Background(), &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: item}); err != nil {
		t.Fatal(err)
	}
}

func rowExists(t *testing.T, c *Client, key map[string]types.AttributeValue) bool {
	t.Helper()
	out, err := c.ddb.GetItem(context.Background(), &dynamodb.GetItemInput{TableName: aws.String(c.table), Key: key, ConsistentRead: aws.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	return out.Item != nil
}

// A sweep that fails half way must leave something a repeat can finish. The reaction row is the
// only pointer to its notification's key (computed from the reactor), so the notifications go
// first: with 13 reactions the old single list of 26 keys put reaction 13 in the first batch and
// its notification in the second, and a failure between them stranded that notification.
func TestAnInterruptedSweepOfReactionsLeavesNoStrandedNotification(t *testing.T) {
	c := testClient(t)
	gid, author := newUserID(t), newUserID(t)
	pid := gid + "#2026-10-28#00112233445566ff"
	var reactors []string
	for i := 0; i < 13; i++ {
		reactor := fmt.Sprintf("reactor-%02d-%s", i, newUserID(t))
		reactors = append(reactors, reactor)
		putRow(t, c, map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: PostPartition(pid)},
			"SK": &types.AttributeValueMemberS{Value: ReactionSortKeyPrefix + "0001#" + reactor},
		})
		putRow(t, c, mergeKey(reactionNotificationKey(author, pid, "0001", reactor), map[string]types.AttributeValue{
			"Kind": &types.AttributeValueMemberS{Value: NotificationReaction},
		}))
	}
	batches := 0
	failing := racingClient(c, func(op string, _ middleware.InitializeInput) error {
		if op == "BatchWriteItem" {
			batches++
			if batches == 2 {
				return errors.New("injected failure")
			}
		}
		return nil
	})
	if err := failing.sweepReactions(context.Background(), pid, "0001", author); err == nil {
		t.Fatal("the sweep survived an injected failure, so this tested nothing")
	}
	// The repair is a repeat on a healthy client.
	if err := c.sweepReactions(context.Background(), pid, "0001", author); err != nil {
		t.Fatal(err)
	}
	for _, reactor := range reactors {
		if rowExists(t, c, reactionKey(pid, "0001", reactor)) {
			t.Errorf("reaction by %s survived the repeat", reactor)
		}
		if rowExists(t, c, reactionNotificationKey(author, pid, "0001", reactor)) {
			t.Errorf("notification for %s's reaction is stranded: no repeat can find it", reactor)
		}
	}
}

func mergeKey(key, extra map[string]types.AttributeValue) map[string]types.AttributeValue {
	for k, v := range extra {
		key[k] = v
	}
	return key
}

func replyNotification(t *testing.T, c *Client, recipient, pid, path string) map[string]types.AttributeValue {
	t.Helper()
	put, err := notification{
		recipientID: recipient, kind: NotificationReply, actorID: "actor", groupID: "g", postID: pid,
		cmtPath: path, now: time.Now(),
	}.put(c.table)
	if err != nil {
		t.Fatal(err)
	}
	putRow(t, c, put.Put.Item)
	return map[string]types.AttributeValue{"PK": put.Put.Item["PK"], "SK": put.Put.Item["SK"]}
}

// Paths repeat across posts, so deleting comment 0001 on one post must not take the recipient's
// notification for 0001 on another; and the filtered read must walk every page, since a filter is
// applied after each page is read (here forced to one row a page).
func TestDeletingReplyNotificationsIsScopedToThePostAndWalksEveryPage(t *testing.T) {
	c := testClient(t)
	recipient := newUserID(t)
	gid := newUserID(t)
	p1, p2 := gid+"#2026-10-28#00112233445566a1", gid+"#2026-10-28#00112233445566a2"
	var mine, others []map[string]types.AttributeValue
	for i := 0; i < 3; i++ {
		mine = append(mine, replyNotification(t, c, recipient, p1, "0001"))
	}
	others = append(others, replyNotification(t, c, recipient, p2, "0001")) // same path, another post
	others = append(others, replyNotification(t, c, recipient, p1, "0002")) // same post, another path
	for i := 0; i < 4; i++ {
		others = append(others, replyNotification(t, c, recipient, p1, fmt.Sprintf("00%02d", 3+i)))
	}
	// A reaction notification on the same post and path is not a reply notification.
	react := mergeKey(reactionNotificationKey(recipient, p1, "0001", "someone"), map[string]types.AttributeValue{
		"Kind":   &types.AttributeValueMemberS{Value: NotificationReaction},
		"PostID": &types.AttributeValueMemberS{Value: p1}, "CmtPath": &types.AttributeValueMemberS{Value: "0001"},
	})
	putRow(t, c, react)
	others = append(others, map[string]types.AttributeValue{"PK": react["PK"], "SK": react["SK"]})

	queries := 0
	onePerPage := racingClient(c, func(op string, in middleware.InitializeInput) error {
		if op == "Query" {
			queries++
			in.Parameters.(*dynamodb.QueryInput).Limit = aws.Int32(1)
		}
		return nil
	})
	if err := onePerPage.deleteReplyNotifications(context.Background(), recipient, p1, "0001"); err != nil {
		t.Fatal(err)
	}
	if queries < 9 {
		t.Fatalf("only %d queries ran, so the one-row pages were not in force", queries)
	}
	for _, k := range mine {
		if rowExists(t, c, k) {
			t.Errorf("a notification for the deleted comment survived (a later page was missed): %v", k["SK"])
		}
	}
	for _, k := range others {
		if !rowExists(t, c, k) {
			t.Errorf("a notification that was not the deleted comment's was removed: %v", k["SK"])
		}
	}
}

func TestReactionNotificationKeyCarriesThePostsDayAndIsComputed(t *testing.T) {
	gid := "11111111-1111-4111-8111-111111111111"
	old := gid + "#2026-10-01#00112233445566a1"
	newer := gid + "#2026-10-28#00112233445566a2"
	sk := func(pid, target, reactor string) string {
		return reactionNotificationKey("recipient", pid, target, reactor)["SK"].(*types.AttributeValueMemberS).Value
	}
	k := sk(old, "0001", "bob")
	if !regexp.MustCompile(`^NOTIF#0000-00-00#2026-10-01#[0-9a-f]{32}$`).MatchString(k) {
		t.Fatalf("key %q: want the placeholder, the post's day, a 32-hex hash", k)
	}
	if k != sk(old, "0001", "bob") {
		t.Error("the key is not computed: the same reaction gave two keys")
	}
	for name, other := range map[string]string{
		"target": sk(old, "0002", "bob"), "reactor": sk(old, "0001", "carol"), "post": sk(newer, "0001", "bob"),
	} {
		if other == k {
			t.Errorf("a different %s gave the same key", name)
		}
	}
	// Newest post first is plain descending key order.
	if !(sk(newer, "0001", "bob") > sk(old, "0001", "bob")) {
		t.Error("a newer post does not sort above an older one")
	}
	// The migration builds the same key from the hash alone.
	hash := k[strings.LastIndex(k, "#")+1:]
	if got := ReactionNotificationSortKey(old, hash); got != k {
		t.Errorf("ReactionNotificationSortKey = %q, want %q", got, k)
	}
}
