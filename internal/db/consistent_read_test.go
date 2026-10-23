package db

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/smithy-go/middleware"
)

// TestGetUserByIDConsistentRead pins the consistency of the two readers: the
// plain one stays eventually consistent (cheaper, what every other caller
// wants), the Consistent one must ask DynamoDB for a strongly consistent read.
func TestGetUserByIDConsistentRead(t *testing.T) {
	c := testClient(t)
	var seen []bool
	capture := func(o *dynamodb.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("capture-consistent-read",
				func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
					if g, ok := in.Parameters.(*dynamodb.GetItemInput); ok {
						seen = append(seen, g.ConsistentRead != nil && *g.ConsistentRead)
					}
					return next.HandleInitialize(ctx, in)
				}), middleware.After)
		})
	}
	c.ddb = dynamodb.New(c.ddb.Options(), capture)

	// The user does not need to exist: the read is what is being checked.
	_, _ = c.GetUserByID(t.Context(), "no-such-user")
	_, _ = c.GetUserByIDConsistent(t.Context(), "no-such-user")
	if len(seen) != 2 || seen[0] || !seen[1] {
		t.Fatalf("ConsistentRead per call = %v, want [false true]", seen)
	}
}
