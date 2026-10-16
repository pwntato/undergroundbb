package db

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// PutVerification writes or replaces the verifier's record for verifiedUserID.
// Replacing is deliberate: after the other user's keys change and the verifier
// compares again, the new record supersedes the stale one. Only the verifier
// can write their own partition.
func (c *Client) PutVerification(ctx context.Context, verifierID, verifiedUserID, fingerprint string, verifierSigningKey, signature []byte) error {
	item, err := attributevalue.MarshalMap(models.Verification{
		Record: models.Record{
			PK:   "USER#" + verifierID,
			SK:   "VERIFIED#" + verifiedUserID,
			Type: "Verification",
		},
		Fingerprint:              fingerprint,
		VerifierSigningPublicKey: verifierSigningKey,
		Signature:                signature,
	})
	if err != nil {
		return fmt.Errorf("db: marshal verification: %w", err)
	}
	if _, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(c.table),
		Item:      item,
	}); err != nil {
		return fmt.Errorf("db: put verification: %w", err)
	}
	return nil
}

// DeleteVerification removes the verifier's record for verifiedUserID. Deleting
// one that does not exist is not an error.
func (c *Client) DeleteVerification(ctx context.Context, verifierID, verifiedUserID string) error {
	if _, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + verifierID},
			"SK": &types.AttributeValueMemberS{Value: "VERIFIED#" + verifiedUserID},
		},
	}); err != nil {
		return fmt.Errorf("db: delete verification: %w", err)
	}
	return nil
}

// ListVerifications returns one page of the verifier's own records in
// verified-uuid order, starting strictly after afterVerifiedUserID (empty for
// the first page), plus the last verified uuid returned when more may follow.
// The cursor is a uuid, so a caller-supplied one can only move within the
// caller's own partition.
func (c *Client) ListVerifications(ctx context.Context, verifierID, afterVerifiedUserID string, limit int) ([]models.Verification, string, error) {
	in := &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "USER#" + verifierID},
			":sk": &types.AttributeValueMemberS{Value: "VERIFIED#"},
		},
		ConsistentRead: aws.Bool(true),
		Limit:          aws.Int32(int32(limit + 1)),
	}
	if afterVerifiedUserID != "" {
		in.ExclusiveStartKey = map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + verifierID},
			"SK": &types.AttributeValueMemberS{Value: "VERIFIED#" + afterVerifiedUserID},
		}
	}
	out, err := c.ddb.Query(ctx, in)
	if err != nil {
		return nil, "", fmt.Errorf("db: list verifications: %w", err)
	}
	var vs []models.Verification
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &vs); err != nil {
		return nil, "", fmt.Errorf("db: unmarshal verifications: %w", err)
	}
	next := ""
	if len(vs) > limit {
		vs = vs[:limit]
		next = vs[limit-1].SK[len("VERIFIED#"):]
	}
	return vs, next, nil
}
