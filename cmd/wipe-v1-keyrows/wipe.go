package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// This lives in the command, not in internal/db, on purpose: it needs
// dynamodb:Scan, which neither the API Lambda's role nor the purge role has
// (internal/db's IAM tests pin both), and an operator tool run once from a
// shell with the operator's own credentials is the only thing that should.

// wipeOptions tunes wipeV1KeyRows.
type wipeOptions struct {
	// dryRun counts what would be deleted and deletes nothing.
	dryRun bool
	// onlyUsers restricts a run to these user ids. Tests share one DynamoDB
	// Local with other packages, so they must not wipe each other's rows.
	onlyUsers map[string]bool
}

// wipeReport says what a run did, or with dryRun what it would do.
type wipeReport struct {
	DryRun   bool `json:"dryRun"`
	Pins     int  `json:"pins"`
	Verified int  `json:"verifications"`
}

// wipeV1KeyRows deletes every v1 PIN# and VERIFIED# row, for every user: the
// one-time migration of the key-rotation work (#62, docs/DESIGN.md "What a key
// change looks like to others"). v1 rows carry no signed day, so under the v2
// payloads they could only read as bad-signature; nothing is deployed with real
// users, and the accounts that exist are test accounts and the maintainer's, so
// they are wiped rather than left to fail.
//
// A v2 row always has SignedDay (the handlers refuse a write without one), so
// the filter is "has no SignedDay", which makes the run idempotent and safe to
// repeat after v2 rows exist: it can only ever delete a row a v2 verifier would
// have rejected.
func wipeV1KeyRows(ctx context.Context, ddb *dynamodb.Client, table string, opts wipeOptions) (wipeReport, error) {
	report := wipeReport{DryRun: opts.dryRun}
	in := &dynamodb.ScanInput{
		TableName:        aws.String(table),
		FilterExpression: aws.String("(begins_with(SK, :pin) OR begins_with(SK, :ver)) AND attribute_not_exists(SignedDay)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pin": &types.AttributeValueMemberS{Value: "PIN#"},
			":ver": &types.AttributeValueMemberS{Value: "VERIFIED#"},
		},
		ProjectionExpression: aws.String("PK, SK"),
		ConsistentRead:       aws.Bool(true),
	}
	for {
		out, err := ddb.Scan(ctx, in)
		if err != nil {
			return report, fmt.Errorf("scan v1 key rows: %w", err)
		}
		var keys []map[string]types.AttributeValue
		for _, item := range out.Items {
			pk := item["PK"].(*types.AttributeValueMemberS).Value
			sk := item["SK"].(*types.AttributeValueMemberS).Value
			if opts.onlyUsers != nil && !opts.onlyUsers[strings.TrimPrefix(pk, "USER#")] {
				continue
			}
			if strings.HasPrefix(sk, "PIN#") {
				report.Pins++
			} else {
				report.Verified++
			}
			if !opts.dryRun {
				keys = append(keys, map[string]types.AttributeValue{"PK": item["PK"], "SK": item["SK"]})
			}
		}
		if err := batchDelete(ctx, ddb, table, keys); err != nil {
			return report, fmt.Errorf("delete v1 key rows: %w", err)
		}
		if out.LastEvaluatedKey == nil {
			return report, nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}

// batchDelete deletes the given keys, 25 per BatchWriteItem, retrying
// unprocessed items a bounded number of times.
func batchDelete(ctx context.Context, ddb *dynamodb.Client, table string, keys []map[string]types.AttributeValue) error {
	for i := 0; i < len(keys); i += 25 {
		end := min(i+25, len(keys))
		reqs := make([]types.WriteRequest, 0, end-i)
		for _, k := range keys[i:end] {
			reqs = append(reqs, types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: k}})
		}
		for attempt := 0; len(reqs) > 0; attempt++ {
			if attempt == 5 {
				return errors.New("unprocessed deletes after retries")
			}
			res, err := ddb.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
				RequestItems: map[string][]types.WriteRequest{table: reqs},
			})
			if err != nil {
				return err
			}
			reqs = res.UnprocessedItems[table]
		}
	}
	return nil
}
