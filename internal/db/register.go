package db

import (
	"bytes"
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
// own. The condition is item-scoped (PK+SK), so it only checks PROFILE, but
// RECOVERY is only ever created in this same transaction and never deleted,
// so a missing PROFILE implies a missing RECOVERY.
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
		claimFailed := isConditionalCheckFailure(err, claimItemIndex)
		userFailed := isConditionalCheckFailure(err, userItemIndex)
		if claimFailed && userFailed {
			// Both conditions failing together is exactly the shape a lost
			// response produces: the first call committed, the response
			// never reached the client, and the client's retry resends the
			// identical registerRequest -- same UserID, same username. See
			// issue #124: before this check, that retry was told "username
			// is taken" for the account it just created, because the claim
			// index was always checked first regardless of what else failed.
			//
			// A consistent read (not the eventually-consistent default) is
			// required here -- this runs microseconds after the losing
			// transaction, and a stale read could still see the claim as
			// absent or, worse, see a prior winner's UserID from a version
			// before this one, whichever committed most recently but hasn't
			// propagated.
			//
			// Matching UserID alone is NOT enough (PR #133 round 1 review):
			// it only proves this caller registered *a* PROFILE at this
			// UserID before, not that it was created with THIS request's key
			// material. A client that regenerated its keys between attempts
			// (a real client bug, but this package can't assume it never
			// happens) would otherwise get back a silent "success" for a
			// write that never actually happened, while the OLD, different
			// keys stay live server-side -- worse than the 409 this issue
			// set out to fix, since the caller has no way to know its new
			// keys were never stored. isOwnRegistration additionally checks
			// the stored PROFILE's own key material against in, so a
			// non-identical resend fails loudly with ErrUsernameTaken
			// instead of succeeding silently.
			isRetry, checkErr := c.isOwnRegistration(ctx, in)
			if checkErr != nil {
				return checkErr
			}
			if isRetry {
				return nil
			}
			return ErrUsernameTaken
		}
		if claimFailed {
			return ErrUsernameTaken
		}
		if userFailed {
			return ErrUserIDTaken
		}
		return err
	}
	return nil
}

// isOwnRegistration reports whether a registration attempt that lost both
// the PROFILE and CLAIM conditions is actually in.UserID's own earlier,
// successful call being resent -- not a genuine conflict with a different
// account, and not a resend whose key material has since diverged from what
// was actually stored (see this function's own two checks below, and
// Register's call site for why both are needed: PR #133 round 1 review
// found that matching UserID alone is not a safe basis for returning
// success, since it doesn't prove this request's material is what the
// server actually has). See Register's own call site (issue #124) for why
// this is only ever consulted when both the claim and the profile writes
// fail together.
func (c *Client) isOwnRegistration(ctx context.Context, in RegisterInput) (bool, error) {
	claimOut, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USERNAME#" + in.UsernameLower},
			"SK": &types.AttributeValueMemberS{Value: "CLAIM"},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return false, err
	}
	if claimOut.Item == nil {
		// The condition check just reported this claim exists; a strongly
		// consistent read finding it gone a moment later would mean
		// something this package's model doesn't support (claims are never
		// deleted) -- treat it as "not a match" rather than assume retry.
		return false, nil
	}
	var claim models.UsernameClaim
	if err := attributevalue.UnmarshalMap(claimOut.Item, &claim); err != nil {
		return false, err
	}
	if claim.UserID != in.UserID {
		// The claimed username belongs to a different account entirely --
		// a genuine conflict, not this caller's own write.
		return false, nil
	}

	// The claim's UserID matches, but that alone only proves this caller
	// registered *a* PROFILE at this UserID before -- not that it was
	// created with the key material this specific request carries. Read the
	// stored PROFILE and compare: only an exact match on the fields that
	// differ between two otherwise-identical-looking registerRequests (a
	// resend that regenerated its keys, whether by a client bug or by
	// design, would fail this) is treated as the same request being
	// resent.
	profileOut, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + in.UserID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return false, err
	}
	if profileOut.Item == nil {
		// The PROFILE condition just reported this item exists; missing a
		// moment later on a consistent read would mean something this
		// package's model doesn't support (PROFILE is never deleted).
		return false, nil
	}
	var profile models.User
	if err := attributevalue.UnmarshalMap(profileOut.Item, &profile); err != nil {
		return false, err
	}
	return bytes.Equal(profile.SigningPublicKey, in.SigningPublicKey) &&
		bytes.Equal(profile.WrappingPublicKey, in.WrappingPublicKey) &&
		bytes.Equal(profile.WrappedPrivateKeys.Nonce, in.WrappedPrivateKeys.Nonce) &&
		bytes.Equal(profile.WrappedPrivateKeys.Ciphertext, in.WrappedPrivateKeys.Ciphertext), nil
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
