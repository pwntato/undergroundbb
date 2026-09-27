// Package db is the DynamoDB access layer.
//
// Every record lives in one table (single-table design), addressed by PK/SK
// with GSI1 for secondary access patterns. Query construction is confined to
// this package so the key schema stays in one place.
//
// The client is created at cold start and reused across Lambda invocations.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// Client wraps a DynamoDB client bound to a single table.
type Client struct {
	ddb   *dynamodb.Client
	table string
}

// New builds a Client for the given table. endpoint overrides the AWS endpoint
// for local development against DynamoDB Local; pass "" to use the real
// service.
func New(ctx context.Context, table, endpoint string) (*Client, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	var opts []func(*dynamodb.Options)
	if endpoint != "" {
		opts = append(opts, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}

	return &Client{ddb: dynamodb.NewFromConfig(cfg, opts...), table: table}, nil
}

// Table returns the name of the table this client is bound to.
func (c *Client) Table() string { return c.table }

// Ping verifies the client can actually reach and use its table: right
// region, right table name, and IAM permission to describe it. New cannot
// catch any of this -- awsconfig.LoadDefaultConfig resolves configuration
// lazily and never contacts AWS, so New returns a working-looking Client for
// a table that does not exist or that the caller has no access to. Call this
// once at cold start so a misconfigured deployment fails there instead of on
// the first request that actually queries DynamoDB. See #86.
func (c *Client) Ping(ctx context.Context) error {
	if _, err := c.ddb.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(c.table),
	}); err != nil {
		return fmt.Errorf("db: describe table %q: %w", c.table, err)
	}
	return nil
}

// RoundUpToEndOfUTCDay rounds t up to 23:59:59 UTC on its own UTC calendar
// day -- the global TTL-storage rule from issue #5's round-27 review
// comment: "round every stored TTL value up to the end of its UTC day," so a
// plaintext epoch-seconds TTL attribute never discloses a second-resolution
// timestamp sitting next to a sort key this schema deliberately built to
// disclose only a day. Applies to every item that carries a TTL at all --
// POST#, CMT#, RXN#, NOTIF#, and the invite pair (INVITE#/SENT#) -- except
// CHALLENGE, whose short (~2 minute) TTL is deliberately NOT rounded: it is
// not derived from a day-resolution sort key or signed payload the way the
// others are, and rounding a 2-minute lifetime up to the end of the day
// would defeat its entire purpose (see login.go's own challengeTTL).
//
// Exported from this package (not idgen) because rounding a TTL is a
// storage-attribute concern specific to how this package persists items,
// not an id-generation concern -- unlike idgen.DaySuffix, callers never need
// this value to be part of anything signed or otherwise agreed with a
// client.
func RoundUpToEndOfUTCDay(t time.Time) time.Time {
	u := t.UTC()
	endOfDay := time.Date(u.Year(), u.Month(), u.Day(), 23, 59, 59, 0, time.UTC)
	if u.After(endOfDay) {
		// t was already past 23:59:59 on its own calendar day, which cannot
		// happen for a well-formed time.Time -- defensive only.
		return u
	}
	return endOfDay
}
