package db

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
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

// put is the transaction item that writes it. The sort key is random, so it never collides and
// needs no condition; what stops a retry writing a second one is that the item that causes it
// rides in the same transaction (a repeated comment fails its own write, so none of it lands).
func (n notification) put(table string) (types.TransactWriteItem, error) {
	sk, err := idgen.NotificationSortKey(n.now)
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
