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
