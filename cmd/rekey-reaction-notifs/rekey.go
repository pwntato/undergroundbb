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
			_, err = ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
				{Put: &types.Put{TableName: aws.String(table), Item: moved, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
				{Delete: &types.Delete{TableName: aws.String(table), Key: key(sk), ConditionExpression: aws.String("attribute_exists(PK)")}},
			}})
			var cancelled *types.TransactionCanceledException
			if errors.As(err, &cancelled) {
				// The old row was deleted (the reaction taken back) or the new one appeared since the
				// read: either way there is nothing left to move. Count it as not moved.
				report.Moved--
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
