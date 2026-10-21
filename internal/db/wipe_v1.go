package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// WipeV1Options tunes WipeV1KeyRows.
type WipeV1Options struct {
	// DryRun counts what would be deleted and deletes nothing.
	DryRun bool

	// onlyUsers restricts a run to these user ids. Tests share one DynamoDB
	// Local with other packages, so they must not wipe each other's rows.
	onlyUsers map[string]bool
}

// WipeV1Report says what a WipeV1KeyRows run did, or with DryRun what it would do.
type WipeV1Report struct {
	DryRun   bool `json:"dryRun"`
	Pins     int  `json:"pins"`
	Verified int  `json:"verifications"`
}

// WipeV1KeyRows deletes every v1 PIN# and VERIFIED# row, for every user: the
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
func (c *Client) WipeV1KeyRows(ctx context.Context, opts WipeV1Options) (WipeV1Report, error) {
	report := WipeV1Report{DryRun: opts.DryRun}
	in := &dynamodb.ScanInput{
		TableName:        aws.String(c.table),
		FilterExpression: aws.String("(begins_with(SK, :pin) OR begins_with(SK, :ver)) AND attribute_not_exists(SignedDay)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pin": &types.AttributeValueMemberS{Value: "PIN#"},
			":ver": &types.AttributeValueMemberS{Value: "VERIFIED#"},
		},
		ProjectionExpression: aws.String("PK, SK"),
		ConsistentRead:       aws.Bool(true),
	}
	for {
		out, err := c.ddb.Scan(ctx, in)
		if err != nil {
			return report, fmt.Errorf("db: scan v1 key rows: %w", err)
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
			if !opts.DryRun {
				keys = append(keys, map[string]types.AttributeValue{"PK": item["PK"], "SK": item["SK"]})
			}
		}
		if err := c.batchDelete(ctx, keys); err != nil {
			return report, fmt.Errorf("db: delete v1 key rows: %w", err)
		}
		if out.LastEvaluatedKey == nil {
			return report, nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}
