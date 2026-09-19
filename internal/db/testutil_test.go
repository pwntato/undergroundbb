package db

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// getItemInput builds a GetItemInput for the given table/PK/SK -- a small
// helper so each test doesn't repeat the attributevalue boilerplate.
func getItemInput(table, pk, sk string) *dynamodb.GetItemInput {
	return &dynamodb.GetItemInput{
		TableName: aws.String(table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: pk},
			"SK": &types.AttributeValueMemberS{Value: sk},
		},
		ConsistentRead: aws.Bool(true),
	}
}

// unmarshalItem is attributevalue.UnmarshalMap under a name that reads at
// the call site without an extra import in every test file.
func unmarshalItem(item map[string]types.AttributeValue, out any) error {
	return attributevalue.UnmarshalMap(item, out)
}

// randomSuffix returns a short random hex string so tests sharing one
// DynamoDB Local instance (in-memory, not reset between runs within a
// session) don't collide on a fixed username across repeated `go test`
// invocations.
func randomSuffix(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("randomSuffix: %v", err)
	}
	return hex.EncodeToString(b[:])
}
