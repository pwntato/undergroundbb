package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// The two kinds of notification (#68): someone replied beneath the recipient's post or comment,
// or reacted to it.
const (
	NotificationReply    = "reply"
	NotificationReaction = "reaction"
)

// notification describes one notification put into the transaction that causes it.
type notification struct {
	recipientID string
	kind        string
	actorID     string
	groupID     string
	postID      string
	cmtPath     string
	ttl         int64
	now         time.Time
}

// put is the transaction item that writes a reply notification. The sort key is random, so it
// never collides and needs no condition; what stops a retry writing a second one is that the item
// that causes it rides in the same transaction (a repeated comment fails its own write, so none of
// it lands).
func (n notification) put(table string) (types.TransactWriteItem, error) {
	sk, err := idgen.NotificationSortKey(idgen.NotificationDay(n.now))
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(models.Notification{
		Record:      models.Record{PK: "USER#" + n.recipientID, SK: sk, Type: "NOTIFICATION"},
		Kind:        n.kind,
		ActorUserID: n.actorID,
		GroupID:     n.groupID,
		PostID:      n.postID,
		CmtPath:     n.cmtPath,
		TTL:         n.ttl,
	})
	if err != nil {
		return types.TransactWriteItem{}, fmt.Errorf("db: marshal notification: %w", err)
	}
	return types.TransactWriteItem{Put: &types.Put{TableName: aws.String(table), Item: item}}, nil
}

// reactionNotificationKey is the address of the notification a reaction sends: computed from the
// post, the target and the reactor rather than random, so taking the reaction back (or deleting
// the comment it is on) can delete it directly, and giving the same reaction again lands on the
// same row. The day is the placeholder, never the real one: a reaction is the one item the schema
// keeps undated (docs/THREAT_MODEL.md). The hash hides nothing the row does not already hold, which
// names the post, the target and the reactor in the clear.
func reactionNotificationKey(recipientID, postID, target, reactorID string) map[string]types.AttributeValue {
	h := sha256.Sum256([]byte("reaction\x00" + postID + "\x00" + target + "\x00" + reactorID))
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "USER#" + recipientID},
		"SK": &types.AttributeValueMemberS{Value: "NOTIF#" + idgen.UndatedNotificationDay + "#" + hex.EncodeToString(h[:16])},
	}
}

// putReaction is the transaction item that writes a reaction's notification: an update, so a
// replaced emoji or a resend lands on the same row and keeps whether the recipient has read it,
// while a reaction given again after being taken back starts a new, unread one (taking it back
// deleted the old row).
func (n notification) putReaction(table string) types.TransactWriteItem {
	names := map[string]string{
		"#type": "Type", "#kind": "Kind", "#actor": "ActorUserID", "#gid": "GroupID",
		"#pid": "PostID", "#cmt": "CmtPath", "#read": "Read",
	}
	values := map[string]types.AttributeValue{
		":type":  &types.AttributeValueMemberS{Value: "NOTIFICATION"},
		":kind":  &types.AttributeValueMemberS{Value: n.kind},
		":actor": &types.AttributeValueMemberS{Value: n.actorID},
		":gid":   &types.AttributeValueMemberS{Value: n.groupID},
		":pid":   &types.AttributeValueMemberS{Value: n.postID},
		":cmt":   &types.AttributeValueMemberS{Value: n.cmtPath},
		":false": &types.AttributeValueMemberBOOL{Value: false},
	}
	expr := "SET #type = :type, #kind = :kind, #actor = :actor, #gid = :gid, #pid = :pid, #cmt = :cmt, #read = if_not_exists(#read, :false)"
	if n.ttl != 0 {
		names["#ttl"] = "TTL"
		values[":ttl"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(n.ttl, 10)}
		expr += ", #ttl = :ttl"
	}
	return types.TransactWriteItem{Update: &types.Update{
		TableName:                 aws.String(table),
		Key:                       reactionNotificationKey(n.recipientID, n.postID, n.cmtPath, n.actorID),
		UpdateExpression:          aws.String(expr),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
	}}
}

// deleteReplyNotifications removes the notification a reply sent to recipientID: the recipient's
// NOTIF# rows of kind reply for this post and comment path. Random keys cannot be computed, so
// this reads the recipient's notifications with a filter; a comment is deleted rarely enough that
// the read is acceptable. Nothing to delete is not an error, so a repeated delete is harmless.
func (c *Client) deleteReplyNotifications(ctx context.Context, recipientID, postID, path string) error {
	var start map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:                aws.String(c.table),
			KeyConditionExpression:   aws.String("PK = :pk AND begins_with(SK, :sk)"),
			FilterExpression:         aws.String("#kind = :kind AND PostID = :pid AND CmtPath = :cmt"),
			ExpressionAttributeNames: map[string]string{"#kind": "Kind"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk":   &types.AttributeValueMemberS{Value: "USER#" + recipientID},
				":sk":   &types.AttributeValueMemberS{Value: "NOTIF#"},
				":kind": &types.AttributeValueMemberS{Value: NotificationReply},
				":pid":  &types.AttributeValueMemberS{Value: postID},
				":cmt":  &types.AttributeValueMemberS{Value: path},
			},
			ProjectionExpression: aws.String("PK, SK"),
			ConsistentRead:       aws.Bool(true),
			ExclusiveStartKey:    start,
		})
		if err != nil {
			return fmt.Errorf("db: find reply notifications: %w", err)
		}
		keys := make([]map[string]types.AttributeValue, 0, len(out.Items))
		for _, it := range out.Items {
			keys = append(keys, map[string]types.AttributeValue{"PK": it["PK"], "SK": it["SK"]})
		}
		if err := c.batchDelete(ctx, keys); err != nil {
			return fmt.Errorf("db: delete reply notifications: %w", err)
		}
		if len(out.LastEvaluatedKey) == 0 {
			return nil
		}
		start = out.LastEvaluatedKey
	}
}
