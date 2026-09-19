package db

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// ErrUsernameTaken is returned when the USERNAME#<lower> claim already
// exists -- the concurrency guard described in docs/DESIGN.md, "The claim is
// only a claim because the write is conditional on
// attribute_not_exists(PK)."
var ErrUsernameTaken = errors.New("db: username taken")

// RegisterInput is everything Register needs to create an account. UserID
// and UsernameLower are derived by the caller (handlers) rather than here,
// so this package stays a pure data-access layer with no id-generation or
// case-folding policy of its own.
type RegisterInput struct {
	UserID            string
	Username          string
	UsernameLower     string
	SigningPublicKey  []byte
	WrappingPublicKey []byte

	Salt               []byte
	Argon2Params       models.Argon2Params
	WrappedPrivateKeys models.WrappedBlob

	RecoverySalt               []byte
	RecoveryArgon2Params       models.Argon2Params
	RecoveryWrappedPrivateKeys models.WrappedBlob
}

// Register creates a new account: the USER#<uuid>/PROFILE item, the
// USER#<uuid>/RECOVERY item, and the USERNAME#<lower>/CLAIM item, as one
// TransactWriteItems. See docs/DESIGN.md, "signup writes three items across
// two partitions, so it is one TransactWriteItems" -- a transaction is what
// closes both partial-write routes (claim without profile burns the
// username permanently; profile without claim makes the account
// unreachable) that separate writes would leave open to nothing more than
// an ordinary timeout or retry, with no concurrency required to reach them.
//
// The claim write is additionally conditional on attribute_not_exists(PK),
// which is what makes it a claim rather than an unconditional overwrite --
// see ErrUsernameTaken.
func (c *Client) Register(ctx context.Context, in RegisterInput) error {
	now := time.Now().UTC().Format(time.RFC3339)

	user := models.User{
		Record: models.Record{
			PK:        "USER#" + in.UserID,
			SK:        "PROFILE",
			Type:      "User",
			CreatedAt: now,
		},
		Username:           in.Username,
		SigningPublicKey:   in.SigningPublicKey,
		WrappingPublicKey:  in.WrappingPublicKey,
		Salt:               in.Salt,
		Argon2Params:       in.Argon2Params,
		WrappedPrivateKeys: in.WrappedPrivateKeys,
		CredentialVersion:  1,
	}
	recovery := models.Recovery{
		Record: models.Record{
			PK:        "USER#" + in.UserID,
			SK:        "RECOVERY",
			Type:      "Recovery",
			CreatedAt: now,
		},
		Salt:               in.RecoverySalt,
		Argon2Params:       in.RecoveryArgon2Params,
		WrappedPrivateKeys: in.RecoveryWrappedPrivateKeys,
		CredentialVersion:  1,
	}
	claim := models.UsernameClaim{
		Record: models.Record{
			PK:        "USERNAME#" + in.UsernameLower,
			SK:        "CLAIM",
			Type:      "UsernameClaim",
			CreatedAt: now,
		},
		UserID: in.UserID,
	}

	userItem, err := attributevalue.MarshalMap(user)
	if err != nil {
		return err
	}
	recoveryItem, err := attributevalue.MarshalMap(recovery)
	if err != nil {
		return err
	}
	claimItem, err := attributevalue.MarshalMap(claim)
	if err != nil {
		return err
	}

	// claimItemIndex is the claim Put's position in TransactItems below --
	// named so isConditionalCheckFailure checks the cancellation reason at
	// this specific index rather than scanning all of them. Scanning would
	// stay correct today (this transaction has exactly one conditional
	// item) but would silently start mapping the wrong failure to
	// ErrUsernameTaken if a second conditional item were ever added here --
	// e.g. the credential-version condition docs/DESIGN.md describes for
	// the re-wrap path, should that ever be folded into this function. This
	// way the mapping stays correct by construction instead of depending on
	// this comment being re-read before such a change.
	const claimItemIndex = 2

	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{TableName: aws.String(c.table), Item: userItem}},
			{Put: &types.Put{TableName: aws.String(c.table), Item: recoveryItem}},
			{
				Put: &types.Put{
					TableName:           aws.String(c.table),
					Item:                claimItem,
					ConditionExpression: aws.String("attribute_not_exists(PK)"),
					// ReturnValuesOnConditionCheckFailure isn't needed here --
					// the only condition in this transaction is the claim's,
					// so a ConditionalCheckFailed at claimItemIndex always
					// means the username was taken and there is nothing else
					// to distinguish it from.
				},
			},
		},
	})
	if err != nil {
		if isConditionalCheckFailure(err, claimItemIndex) {
			return ErrUsernameTaken
		}
		return err
	}
	return nil
}

// isConditionalCheckFailure reports whether err is a TransactWriteItems
// failure caused by the condition check on the item at itemIndex, as
// opposed to any other transaction cancellation reason (throttling,
// validation, a capacity error, or a condition failure on a *different*
// item). Checking a specific index rather than scanning every reason keeps
// this correct even if a second conditional item is later added to the same
// transaction.
func isConditionalCheckFailure(err error, itemIndex int) bool {
	var txErr *types.TransactionCanceledException
	if !errors.As(err, &txErr) {
		return false
	}
	if itemIndex < 0 || itemIndex >= len(txErr.CancellationReasons) {
		return false
	}
	reason := txErr.CancellationReasons[itemIndex]
	return reason.Code != nil && *reason.Code == "ConditionalCheckFailed"
}
