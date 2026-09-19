package db

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// UsernameAvailable reports whether usernameLower has no USERNAME#<lower>
// claim yet. usernameLower must already be lowercased by the caller -- this
// package has no case-folding policy of its own, per RegisterInput's own
// convention.
//
// This is a plain (not strongly consistent) GetItem: DynamoDB's default read
// is eventually consistent, so a claim written a moment ago by a concurrent
// signup could still read as available here. That's fine for this endpoint
// -- it is advisory, not authoritative. The authoritative check is
// Register's own conditional write, which is what actually decides
// ownership; this method exists only to save a client the round trip of
// discovering a taken name via a failed signup. See docs/DESIGN.md, "The
// claim is only a claim because the write is conditional."
func (c *Client) UsernameAvailable(ctx context.Context, usernameLower string) (bool, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USERNAME#" + usernameLower},
			"SK": &types.AttributeValueMemberS{Value: "CLAIM"},
		},
	})
	if err != nil {
		return false, fmt.Errorf("db: check username availability: %w", err)
	}
	return out.Item == nil, nil
}
