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

// ErrUserIDTaken is returned when the USER#<uuid> PROFILE item already
// exists. UserID is now client-supplied (see RegisterInput's own doc
// comment) rather than server-generated, so unlike a UUID idgen.UUID()
// itself picks, this is a value the caller does not fully control the
// randomness of -- a client could submit any well-formed UUID, including
// one that collides with an existing account, whether by the astronomical
// accident a random 128-bit value implies or by deliberately choosing one.
// The PROFILE Put's own attribute_not_exists(PK) condition is what turns
// that into a rejected transaction instead of a silent overwrite of
// someone else's credentials.
var ErrUserIDTaken = errors.New("db: user id taken")

// RegisterInput is everything Register needs to create an account.
// UsernameLower is derived by the caller (handlers) rather than here, so
// this package stays a pure data-access layer with no case-folding policy of
// its own. UserID is likewise supplied by the caller -- client-chosen, not
// server-generated (see internal/handlers/register.go's own doc comment on
// why: the credential-wrap AAD binds "user uuid + which copy" and the
// client must know the real uuid before it wraps, which is before the
// server would otherwise assign one) -- which is exactly why Register's own
// PROFILE Put is conditional: this package cannot assume UserID is as
// trustworthy as a value it generated itself.
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

	RecoveryVerifierSalt   []byte
	RecoveryVerifierParams models.Argon2Params
	RecoveryVerifier       []byte
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
// The claim write and the PROFILE write are each additionally conditional on
// attribute_not_exists(PK) -- the claim's condition is what makes it a claim
// rather than an unconditional overwrite (see ErrUsernameTaken); the
// PROFILE write's condition guards against a colliding client-supplied
// UserID (see ErrUserIDTaken). The RECOVERY write has no condition of its
// own: it shares PROFILE's PK, so PROFILE's condition already covers it --
// a transaction either writes both or neither.
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
		Salt:                 in.RecoverySalt,
		Argon2Params:         in.RecoveryArgon2Params,
		WrappedPrivateKeys:   in.RecoveryWrappedPrivateKeys,
		VerifierSalt:         in.RecoveryVerifierSalt,
		VerifierArgon2Params: in.RecoveryVerifierParams,
		Verifier:             in.RecoveryVerifier,
		CredentialVersion:    1,
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

	// userItemIndex and claimItemIndex are the two conditional Puts'
	// positions in TransactItems below -- named so isConditionalCheckFailure
	// checks the cancellation reason at a specific index rather than
	// scanning all of them, so the mapping to ErrUserIDTaken/ErrUsernameTaken
	// stays correct by construction (tied to position, which the literal
	// slice below makes obvious) rather than depending on a comment being
	// re-read before a future item is added or reordered.
	const (
		userItemIndex  = 0
		claimItemIndex = 2
	)

	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{
				Put: &types.Put{
					TableName:           aws.String(c.table),
					Item:                userItem,
					ConditionExpression: aws.String("attribute_not_exists(PK)"),
					// See ErrUserIDTaken's own doc comment: UserID is now
					// client-supplied, so this condition is load-bearing in a
					// way it would not be against a server-generated UUID.
				},
			},
			{Put: &types.Put{TableName: aws.String(c.table), Item: recoveryItem}},
			{
				Put: &types.Put{
					TableName:           aws.String(c.table),
					Item:                claimItem,
					ConditionExpression: aws.String("attribute_not_exists(PK)"),
				},
			},
		},
	})
	if err != nil {
		if isConditionalCheckFailure(err, claimItemIndex) {
			return ErrUsernameTaken
		}
		if isConditionalCheckFailure(err, userItemIndex) {
			return ErrUserIDTaken
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
