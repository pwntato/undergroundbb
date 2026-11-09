package db

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// When the pair marker changed under a refused create (it was there for the transaction and gone
// for the read), the answer is the retryable ErrDMRaced, not the cool-off error.
func TestDMCreateFailureWhenTheMarkerVanishedIsRetryable(t *testing.T) {
	c := testClient(t)
	in := CreateGroupInput{GroupID: "g-raced", CreatorUserID: "raced-sender-" + t.Name(), DM: &CreateDMInput{RecipientUserID: "raced-recipient-" + t.Name()}}
	cancelled := &types.TransactionCanceledException{CancellationReasons: []types.CancellationReason{
		{Code: aws.String("None")}, {Code: aws.String("None")}, {Code: aws.String("None")}, {Code: aws.String("None")},
		{Code: aws.String("ConditionalCheckFailed")},
	}}
	err := c.dmCreateFailure(t.Context(), in, cancelled, 4)
	if !errors.Is(err, ErrDMRaced) {
		t.Errorf("err = %v, want ErrDMRaced", err)
	}
}
