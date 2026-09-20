package db

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// ErrCredentialVersionStale is returned when RewrapCredentials' condition
// on CredentialVersion fails -- another re-wrap (a second tab, or a race
// between a password change and a recovery reset) already landed first.
// See docs/DESIGN.md, "the fourth [contested write] is the credential
// re-wrap": the loser must be told, not left holding a recovery code that
// silently no longer works.
var ErrCredentialVersionStale = errors.New("db: credential version is stale; the credentials were changed by another request")

// RewrapCredentialsInput is everything RewrapCredentials needs to re-wrap
// both PROFILE and RECOVERY under a new password and a new recovery code.
// Shared by #30 (password change, which re-derives Salt/WrappedPrivateKeys
// but not the caller's identity) and #31 (recovery reset, which
// additionally authenticates via the code rather than a session) -- see
// docs/DESIGN.md, "Both copies are therefore rewritten together... that is
// one TransactWriteItems," which applies identically to both flows.
//
// Every credential field here is client-generated and opaque to this
// package, matching RegisterInput -- this function's only policy is the
// CredentialVersion condition and which two items it writes.
type RewrapCredentialsInput struct {
	UserID string

	// ExpectedCredentialVersion is read back by the caller (from the
	// PROFILE item, e.g. via LookupUserByUsername or a fresh GetItem) before
	// the client began deriving new wraps, and is what the transaction
	// conditions on. NewCredentialVersion is ExpectedCredentialVersion+1,
	// computed by the caller rather than here so this function has no
	// arithmetic to get wrong at the one place a stale write would be worst.
	ExpectedCredentialVersion int64
	NewCredentialVersion      int64

	Salt               []byte
	Argon2Params       models.Argon2Params
	WrappedPrivateKeys models.WrappedBlob

	RecoverySalt               []byte
	RecoveryArgon2Params       models.Argon2Params
	RecoveryWrappedPrivateKeys models.WrappedBlob

	RecoveryVerifierSalt   []byte
	RecoveryVerifierParams models.Argon2Params
	RecoveryVerifier       []byte
}

// RewrapCredentials re-wraps PROFILE and RECOVERY together as one
// TransactWriteItems, each conditional on CredentialVersion still equalling
// ExpectedCredentialVersion -- see docs/DESIGN.md's contested-write
// paragraph this implements. A concurrent re-wrap that already bumped the
// version fails this condition on both items simultaneously (both live in
// the same partition and both are being rewritten, so there is exactly one
// failure mode to distinguish, unlike Register's claim-vs-profile split);
// ErrCredentialVersionStale covers it uniformly.
//
// This does not touch Username, the public keys, or anything else on
// PROFILE -- see docs/DESIGN.md, "Changing a password does not change
// keys," which applies equally to a recovery reset.
func (c *Client) RewrapCredentials(ctx context.Context, in RewrapCredentialsInput) error {
	userKey := "USER#" + in.UserID

	profileUpdate := &types.Update{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: userKey},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		UpdateExpression: aws.String(
			"SET Salt = :salt, Argon2Params = :argon2Params, WrappedPrivateKeys = :wrappedPrivateKeys, CredentialVersion = :newVersion",
		),
		ConditionExpression: aws.String("CredentialVersion = :expectedVersion"),
	}
	recoveryUpdate := &types.Update{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: userKey},
			"SK": &types.AttributeValueMemberS{Value: "RECOVERY"},
		},
		UpdateExpression: aws.String(
			"SET Salt = :recoverySalt, Argon2Params = :recoveryArgon2Params, WrappedPrivateKeys = :recoveryWrappedPrivateKeys, " +
				"VerifierSalt = :verifierSalt, VerifierArgon2Params = :verifierArgon2Params, #V = :verifier, " +
				"CredentialVersion = :newVersion",
		),
		// Verifier collides with a DynamoDB reserved word, so it needs an
		// expression attribute name like every other reserved-word field
		// this codebase writes via an UpdateExpression.
		ExpressionAttributeNames: map[string]string{"#V": "Verifier"},
		ConditionExpression:      aws.String("CredentialVersion = :expectedVersion"),
	}

	values, err := attributevalue.MarshalMap(map[string]any{
		":salt":               in.Salt,
		":argon2Params":       in.Argon2Params,
		":wrappedPrivateKeys": in.WrappedPrivateKeys,

		":recoverySalt":               in.RecoverySalt,
		":recoveryArgon2Params":       in.RecoveryArgon2Params,
		":recoveryWrappedPrivateKeys": in.RecoveryWrappedPrivateKeys,

		":verifierSalt":         in.RecoveryVerifierSalt,
		":verifierArgon2Params": in.RecoveryVerifierParams,
		":verifier":             in.RecoveryVerifier,

		":expectedVersion": in.ExpectedCredentialVersion,
		":newVersion":      in.NewCredentialVersion,
	})
	if err != nil {
		return err
	}
	// PROFILE's update only needs the subset of values its own expression
	// references -- ExpressionAttributeValues on a TransactWriteItems Update
	// rejects unused names, unlike a plain UpdateItem, so the two items
	// cannot share one map the way a single-item call could.
	profileValues := map[string]types.AttributeValue{
		":salt":               values[":salt"],
		":argon2Params":       values[":argon2Params"],
		":wrappedPrivateKeys": values[":wrappedPrivateKeys"],
		":newVersion":         values[":newVersion"],
		":expectedVersion":    values[":expectedVersion"],
	}
	recoveryValues := map[string]types.AttributeValue{
		":recoverySalt":               values[":recoverySalt"],
		":recoveryArgon2Params":       values[":recoveryArgon2Params"],
		":recoveryWrappedPrivateKeys": values[":recoveryWrappedPrivateKeys"],
		":verifierSalt":               values[":verifierSalt"],
		":verifierArgon2Params":       values[":verifierArgon2Params"],
		":verifier":                   values[":verifier"],
		":newVersion":                 values[":newVersion"],
		":expectedVersion":            values[":expectedVersion"],
	}
	profileUpdate.ExpressionAttributeValues = profileValues
	recoveryUpdate.ExpressionAttributeValues = recoveryValues

	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Update: profileUpdate},
			{Update: recoveryUpdate},
		},
	})
	if err != nil {
		var txErr *types.TransactionCanceledException
		if errors.As(err, &txErr) {
			for _, reason := range txErr.CancellationReasons {
				if reason.Code != nil && *reason.Code == "ConditionalCheckFailed" {
					return ErrCredentialVersionStale
				}
			}
		}
		return err
	}
	return nil
}
