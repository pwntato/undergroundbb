// Package backfill coarsens the full-resolution Record.CreatedAt that rows
// written before #147 still carry, and before #259 for Admission,
// GenerationKey and Rotation rows. It lives outside internal/db because it
// needs a table Scan, which no request-serving code may use: the web
// Lambda's IAM test (db/lambda_iam_test.go) scans package db's source, and
// cmd/backfill has its own role (terraform/backfill.tf).
package backfill

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
)

// API is the slice of *dynamodb.Client the backfill uses.
type API interface {
	Scan(ctx context.Context, in *dynamodb.ScanInput, opts ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
	UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

// Options tunes Run.
type Options struct {
	// DryRun scans and reports but writes nothing.
	DryRun bool
}

// Report says what a run did, or with DryRun what it would do.
type Report struct {
	DryRun  bool `json:"dryRun"`
	Scanned int  `json:"scanned"`
	// Removed counts rows whose CreatedAt was (or would be) removed, by Type.
	Removed map[string]int `json:"removed"`
	// Truncated counts MEMBER# rows set (or that would be set) to their UTC day.
	Truncated int `json:"truncated"`
	// Kept counts rows with a CreatedAt that is deliberately left alone: test
	// accounts' PROFILE (the purge needs it), MEMBER# rows already at midnight
	// UTC, and rows of any other Type.
	Kept int `json:"kept"`
	// KeptByType breaks Kept down by Type, so a dry run shows any type that
	// still carries a CreatedAt this backfill does not know about.
	KeptByType map[string]int `json:"keptByType"`
	// Unparsed counts MEMBER# rows whose CreatedAt is not RFC 3339. They are
	// left alone, but the successor claim already refuses such a row
	// (designation_before_join), so each is logged by key to be looked at.
	Unparsed int `json:"unparsed"`
	// Raced counts rows that changed between the scan and the write; the
	// conditional update refused them and a rerun picks them up.
	Raced int `json:"raced"`
}

// Types whose CreatedAt is removed outright: nothing reads it (#147's reader
// audit), and the rows are written without it now.
var removeTypes = map[string]bool{
	"User":          true, // real accounts only; see decide
	"Recovery":      true,
	"UsernameClaim": true,
	"Group":         true,
	"RoleGrant":     true,
	// Written without it since #259 (#258); nothing reads it. A Rotation's
	// functional StartedAt is a separate attribute and is not touched.
	"Admission":     true,
	"GenerationKey": true,
	"Rotation":      true,
}

// action is what to do to one scanned row.
type action int

const (
	keep action = iota
	remove
	truncate
	unparsed
)

// decide classifies a scanned row. day is the UTC-midnight form of its
// CreatedAt (only meaningful for truncate).
func decide(item map[string]types.AttributeValue) (act action, typ, day string) {
	typ = strAttr(item, "Type")
	created := strAttr(item, "CreatedAt")
	switch {
	case created == "":
		return keep, typ, ""
	case typ == "Membership":
		// The successor claim reads this as the join date and compares by
		// day, so it keeps the day and loses the time.
		t, err := time.Parse(time.RFC3339, created)
		if err != nil {
			return unparsed, typ, ""
		}
		d := t.UTC().Truncate(24 * time.Hour).Format(time.RFC3339)
		if d == created {
			return keep, typ, ""
		}
		return truncate, typ, d
	case typ == "User":
		// A test account's PROFILE keeps it: the purge compares it to a
		// cutoff and sorts GSI1SK by it.
		if b, ok := item["TestAccount"].(*types.AttributeValueMemberBOOL); ok && b.Value {
			return keep, typ, ""
		}
		return remove, typ, ""
	case removeTypes[typ]:
		return remove, typ, ""
	}
	return keep, typ, ""
}

func strAttr(item map[string]types.AttributeValue, k string) string {
	if v, ok := item[k].(*types.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}

// Run backfills every row in table. It is idempotent: a removed CreatedAt is
// never seen again, and a truncated one is recognised and kept. Each write is
// conditional on the CreatedAt the scan saw, so a row changed in between is
// counted as raced rather than overwritten. A dry run reports what a real run
// would do.
func Run(ctx context.Context, api API, table string, opts Options) (Report, error) {
	rep := Report{DryRun: opts.DryRun, Removed: map[string]int{}, KeptByType: map[string]int{}}
	var start map[string]types.AttributeValue
	for {
		out, err := api.Scan(ctx, &dynamodb.ScanInput{
			TableName:         aws.String(table),
			ExclusiveStartKey: start,
			ConsistentRead:    aws.Bool(true),
			FilterExpression:  aws.String("attribute_exists(CreatedAt)"),
		})
		if err != nil {
			return rep, fmt.Errorf("backfill: scan: %w", err)
		}
		for _, item := range out.Items {
			rep.Scanned++
			act, typ, day := decide(item)
			if act == unparsed {
				rep.Unparsed++
				log.Printf("backfill: %s/%s has a CreatedAt that is not RFC 3339: %q", strAttr(item, "PK"), strAttr(item, "SK"), strAttr(item, "CreatedAt"))
				continue
			}
			if act == keep {
				rep.Kept++
				rep.KeptByType[typ]++
				continue
			}
			if !opts.DryRun {
				raced, err := write(ctx, api, table, item, act, day)
				if err != nil {
					return rep, err
				}
				if raced {
					rep.Raced++
					continue
				}
			}
			if act == remove {
				rep.Removed[typ]++
			} else {
				rep.Truncated++
			}
		}
		if out.LastEvaluatedKey == nil {
			return rep, nil
		}
		start = out.LastEvaluatedKey
	}
}

// write applies one decision. Every write requires CreatedAt to still be the
// value the scan saw; a User also requires that it is still not a test
// account. It reports raced when that condition fails.
func write(ctx context.Context, api API, table string, item map[string]types.AttributeValue, act action, day string) (raced bool, err error) {
	in := &dynamodb.UpdateItemInput{
		TableName: aws.String(table),
		Key:       map[string]types.AttributeValue{"PK": item["PK"], "SK": item["SK"]},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":seen": item["CreatedAt"],
		},
		ConditionExpression: aws.String("CreatedAt = :seen"),
	}
	if act == remove {
		in.UpdateExpression = aws.String("REMOVE CreatedAt")
	} else {
		in.UpdateExpression = aws.String("SET CreatedAt = :day")
		in.ExpressionAttributeValues[":day"] = &types.AttributeValueMemberS{Value: day}
	}
	if strAttr(item, "Type") == "User" {
		in.ConditionExpression = aws.String("CreatedAt = :seen AND attribute_not_exists(TestAccount)")
	}
	if _, err := api.UpdateItem(ctx, in); err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			return true, nil
		}
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ConditionalCheckFailedException" {
			return true, nil
		}
		return false, fmt.Errorf("backfill: update %s/%s: %w", strAttr(item, "PK"), strAttr(item, "SK"), err)
	}
	return false, nil
}
