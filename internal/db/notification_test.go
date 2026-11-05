package db

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
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
