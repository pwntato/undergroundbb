package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

// This lives in the command, not in internal/db, on purpose: it needs dynamodb:Scan, which neither
// the API Lambda's role nor the purge role has, and an operator tool run once from a shell with the
// operator's own credentials is the only thing that should.

type rekeyOptions struct {
	// dryRun counts what would move and writes nothing.
	dryRun bool
	// onlyUsers restricts a run to these recipients. Tests share one DynamoDB Local with other
	// packages, so they must not rewrite each other's rows.
	onlyUsers map[string]bool
}

// rekeyReport says what a run did, or with dryRun what it would do.
type rekeyReport struct {
	DryRun bool `json:"dryRun"`
	// Moved rows were rewritten under the new key.
	Moved int `json:"moved"`
	// Superseded old rows were deleted because the new key already existed: the reaction was given
	// again after the deploy, and that row (and its Read flag) wins.
	Superseded int `json:"superseded"`
	// Orphaned old rows were deleted, not moved, because the reaction they announce is gone: it was
	// taken back (or its comment or post deleted) after the deploy, when the delete computed the new
	// key and missed the old row. Moving one would strand it, since a reaction row is the only
	// pointer to its notification.
	Orphaned int `json:"orphaned"`
	// Retry rows were not moved because their transaction was cancelled for any reason but the old
	// row already being gone: the new row or a conflicting transaction appeared, the reaction was
	// taken back mid-move, or throttling. They are still on the old key: run the command again until
	// a dry run reports moved, superseded, orphaned and retry all 0 (retry itself is always 0 in a dry
	// run, which sends no transaction; the other three are what show a row left to handle).
	Retry int `json:"retry"`
	// Skipped rows could not be moved: no readable PostID. They are left alone and listed so an
	// operator can look.
	Skipped []string `json:"skipped,omitempty"`
}

const oldPrefix = "NOTIF#" + idgen.UndatedNotificationDay + "#"

// oldHash returns the hash of an old-shape reaction notification key
// ("NOTIF#0000-00-00#<32 hex>"), and false for anything else: the new shape has a day and a second
// "#" after the prefix.
func oldHash(sk string) (string, bool) {
	h, ok := strings.CutPrefix(sk, oldPrefix)
	if !ok || strings.Contains(h, "#") || len(h) != 32 {
		return "", false
	}
	return h, true
}

func str(item map[string]types.AttributeValue, k string) string {
	if v, ok := item[k].(*types.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}

// rekeyReactionNotifications moves each old-shape row to its new key. A row's new key is the same
// hash behind the day of the post its PostID names, so nothing about it is recomputed. Each move is
// one transaction (put the new row, delete the old one, condition that the old one is still there),
// so a repeat or a concurrent delete cannot duplicate or resurrect a row.
func rekeyReactionNotifications(ctx context.Context, ddb *dynamodb.Client, table string, opts rekeyOptions) (rekeyReport, error) {
	report := rekeyReport{DryRun: opts.dryRun}
	in := &dynamodb.ScanInput{
		TableName:        aws.String(table),
		FilterExpression: aws.String("begins_with(SK, :p) AND #kind = :k"),
		ExpressionAttributeNames: map[string]string{
			"#kind": "Kind",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":p": &types.AttributeValueMemberS{Value: oldPrefix},
			":k": &types.AttributeValueMemberS{Value: db.NotificationReaction},
		},
		ConsistentRead: aws.Bool(true),
	}
	for {
		out, err := ddb.Scan(ctx, in)
		if err != nil {
			return report, fmt.Errorf("scan reaction notifications: %w", err)
		}
		for _, item := range out.Items {
			pk, sk := str(item, "PK"), str(item, "SK")
			if opts.onlyUsers != nil && !opts.onlyUsers[strings.TrimPrefix(pk, "USER#")] {
				continue
			}
			hash, old := oldHash(sk)
			if !old {
				continue
			}
			postID := str(item, "PostID")
			if _, _, ok := idgen.ParsePostID(postID); !ok {
				report.Skipped = append(report.Skipped, pk+" "+sk)
				continue
			}
			newSK := db.ReactionNotificationSortKey(postID, hash)
			key := func(sk string) map[string]types.AttributeValue {
				return map[string]types.AttributeValue{"PK": item["PK"], "SK": &types.AttributeValueMemberS{Value: sk}}
			}
			// The reaction this row announces must still exist: its row is RXN#<target>#<reactor> in
			// the post's partition, and the notification names all three.
			rxnKey := map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: db.PostPartition(postID)},
				"SK": &types.AttributeValueMemberS{Value: db.ReactionSortKeyPrefix + str(item, "CmtPath") + "#" + str(item, "ActorUserID")},
			}
			rxn, err := ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(table), ConsistentRead: aws.Bool(true), Key: rxnKey})
			if err != nil {
				return report, fmt.Errorf("read reaction for %s: %w", sk, err)
			}
			if rxn.Item == nil {
				report.Orphaned++
				if opts.dryRun {
					continue
				}
				if _, err := ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(table), Key: key(sk)}); err != nil {
					return report, fmt.Errorf("delete orphaned %s: %w", sk, err)
				}
				continue
			}
			existing, err := ddb.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(table), Key: key(newSK), ConsistentRead: aws.Bool(true)})
			if err != nil {
				return report, fmt.Errorf("read %s: %w", newSK, err)
			}
			if existing.Item != nil {
				report.Superseded++
				if opts.dryRun {
					continue
				}
				if _, err := ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(table), Key: key(sk)}); err != nil {
					return report, fmt.Errorf("delete superseded %s: %w", sk, err)
				}
				continue
			}
			report.Moved++
			if opts.dryRun {
				continue
			}
			moved := make(map[string]types.AttributeValue, len(item))
			for k, v := range item {
				moved[k] = v
			}
			moved["SK"] = &types.AttributeValueMemberS{Value: newSK}
			// The reaction is checked again inside the transaction: the read above is a separate
			// request, and a reaction taken back in between would otherwise be moved and stranded.
			// The order matters: nothingLeftToMove reads the Delete's reason by its position.
			_, err = ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
				{Put: &types.Put{TableName: aws.String(table), Item: moved, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
				{Delete: &types.Delete{TableName: aws.String(table), Key: key(sk), ConditionExpression: aws.String("attribute_exists(PK)")}},
				{ConditionCheck: &types.ConditionCheck{TableName: aws.String(table), Key: rxnKey, ConditionExpression: aws.String("attribute_exists(PK)")}},
			}})
			var cancelled *types.TransactionCanceledException
			if errors.As(err, &cancelled) {
				report.recordCancelled(cancelled)
				continue
			}
			if err != nil {
				return report, fmt.Errorf("move %s: %w", sk, err)
			}
		}
		if out.LastEvaluatedKey == nil {
			return report, nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}

// deleteItem is the position of the old row's Delete in a move's transaction.
const deleteItem = 1

// nothingLeftToMove is true only when the move's Delete failed its own condition: the old row is
// gone, so there is nothing to move. Every other cancellation leaves the old row in place and needing
// another run: the Put's condition failing (the new row appeared, so the next run deletes the old
// one as superseded), the reaction check failing (the reaction was taken back mid-move, so the next
// run deletes the old one as orphaned), a conflicting transaction, or throttling.
func nothingLeftToMove(c *types.TransactionCanceledException) bool {
	if len(c.CancellationReasons) <= deleteItem {
		return false
	}
	return aws.ToString(c.CancellationReasons[deleteItem].Code) == "ConditionalCheckFailed"
}

// recordCancelled undoes the optimistic Moved count for a move whose transaction was cancelled, and
// counts it as Retry unless the old row is gone.
func (r *rekeyReport) recordCancelled(c *types.TransactionCanceledException) {
	r.Moved--
	if !nothingLeftToMove(c) {
		r.Retry++
	}
}
