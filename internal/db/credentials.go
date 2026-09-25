package db

import (
	"bytes"
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

// GetUserByID reads a single user's PROFILE directly by uuid, unlike
// LookupUserByUsername's two-step claim-then-profile lookup -- issue #131's
// GET /api/account/credentials calls this from behind requireSession, which
// has already turned a verified session cookie into a userID with no
// username involved, so there is no claim to resolve first. Returns
// ErrUserNotFound if the PROFILE item is missing, the same sentinel
// LookupUserByUsername uses, since a caller with a valid session pointing at
// a nonexistent profile is exactly as anomalous as that function's own
// claim-without-profile case.
func (c *Client) GetUserByID(ctx context.Context, userID string) (*models.User, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, ErrUserNotFound
	}
	var user models.User
	if err := attributevalue.UnmarshalMap(out.Item, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

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

	// IdempotencyToken, if set, is written to RECOVERY's LastRewrapToken
	// alongside this write -- opaque to this package, just another field to
	// persist. See models.Recovery.LastRewrapToken's own doc comment for
	// what reads it back and why (issue #130). changePassword (#30) leaves
	// this unset; RewrapCredentials then leaves LastRewrapToken untouched
	// rather than overwriting it with an empty value (see this function's
	// own comment on why an empty binary AttributeValue is avoided), so a
	// password change following a recovery reset does not itself clear the
	// token -- recoveryCodeReset's own fallback additionally requires the
	// stored CredentialVersion to match what the retry expects, which a
	// later, unrelated password change already bumped past, so a stale
	// leftover token from a much earlier reset cannot be replayed against a
	// newer write it was never for.
	IdempotencyToken []byte

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

	// RECOVERY's SET clause and value map are built incrementally so
	// LastRewrapToken is only ever written when in.IdempotencyToken is set --
	// an empty/nil binary AttributeValue is best avoided rather than relied
	// on to behave like "no value" (unlike every other field re-wrapped
	// here, this one has a real "caller didn't provide one" case:
	// changePassword, #30, never sets it). See
	// RewrapCredentialsInput.IdempotencyToken and
	// models.Recovery.LastRewrapToken's own doc comments; issue #130.
	recoverySet := "SET Salt = :recoverySalt, Argon2Params = :recoveryArgon2Params, WrappedPrivateKeys = :recoveryWrappedPrivateKeys, " +
		"VerifierSalt = :verifierSalt, VerifierArgon2Params = :verifierArgon2Params, #V = :verifier, " +
		"CredentialVersion = :newVersion"
	recoveryValues := map[string]types.AttributeValue{}
	if len(in.IdempotencyToken) > 0 {
		recoverySet += ", LastRewrapToken = :idempotencyToken"
		tokenValue, err := attributevalue.Marshal(in.IdempotencyToken)
		if err != nil {
			return err
		}
		recoveryValues[":idempotencyToken"] = tokenValue
	}

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
		UpdateExpression: aws.String(recoverySet),
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
	recoveryValues[":recoverySalt"] = values[":recoverySalt"]
	recoveryValues[":recoveryArgon2Params"] = values[":recoveryArgon2Params"]
	recoveryValues[":recoveryWrappedPrivateKeys"] = values[":recoveryWrappedPrivateKeys"]
	recoveryValues[":verifierSalt"] = values[":verifierSalt"]
	recoveryValues[":verifierArgon2Params"] = values[":verifierArgon2Params"]
	recoveryValues[":verifier"] = values[":verifier"]
	recoveryValues[":newVersion"] = values[":newVersion"]
	recoveryValues[":expectedVersion"] = values[":expectedVersion"]
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

// IsOwnRewrap reports whether a RewrapCredentials call this package cannot
// re-attempt -- because it never even got there, see below -- was actually
// userID's own earlier, successful call, identified by an idempotency token
// rather than any property of a stale-version conflict.
//
// This is NOT called from inside RewrapCredentials, unlike Register's
// analogous isOwnRegistration (issue #124): a recovery reset's own retry
// never reaches RewrapCredentials's stale-version condition at all.
// resolveRecovery (internal/handlers/recovery.go) re-checks the presented
// code against RECOVERY's *current* Verifier on every call, and a
// successful reset rotates that verifier in the same transaction that bumps
// CredentialVersion -- so a retry presenting the same, now-stale code fails
// the *code* check first, with a plain 401, before RewrapCredentials, its
// version condition, or any token comparison ever run. This function exists
// for that caller to invoke directly, once its own code check has already
// failed, as the fallback issue #130 needs. See recoveryCodeReset's call
// site for the full sequence.
//
// wantVersion is the CredentialVersion the caller's original request would
// have produced (ExpectedCredentialVersion+1, mirroring
// RewrapCredentialsInput.NewCredentialVersion) -- required to match exactly,
// not just be greater than what the caller last knew, so a stale token left
// over from a much earlier reset cannot be replayed to falsely confirm a
// request it was never for (see RewrapCredentialsInput.IdempotencyToken's
// own comment on why a later write does not clear a prior token outright).
//
// Matching token and version alone are NOT enough -- the same lesson PR
// #133 round 1 review applied to isOwnRegistration: a token match only
// proves SOME call from a holder of this token landed at this version, not
// that it was created with THIS request's own credential material. Without
// also comparing material, a caller that resent the same token but
// different Salt/WrappedPrivateKeys/RecoveryVerifier (a client bug, or a
// second, different write mistakenly reusing a token) would get back a
// silent "success" for a write that never actually happened, while
// whatever the FIRST call under that token actually wrote stays live --
// worse than the 401 this fallback exists to avoid, since the caller has no
// way to know its own fields were never stored. want carries this request's
// own decoded fields -- recoveryCodeReset decodes credentialRewrapFields
// once, up front, before either branch, specifically so the fallback path
// has real bytes to compare here rather than trusting the token match
// alone.
//
// A zero-length token never matches -- ConsistentRead: true, since this is
// meant to observe a write that may have landed microseconds earlier, the
// same reasoning isOwnRegistration's own comment gives.
func (c *Client) IsOwnRewrap(ctx context.Context, userID string, token []byte, wantVersion int64, want RewrapMaterial) (bool, error) {
	if len(token) == 0 {
		return false, nil
	}

	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "RECOVERY"},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return false, err
	}
	if out.Item == nil {
		return false, nil
	}
	var recovery models.Recovery
	if err := attributevalue.UnmarshalMap(out.Item, &recovery); err != nil {
		return false, err
	}
	if recovery.CredentialVersion != wantVersion {
		return false, nil
	}
	if !bytes.Equal(recovery.LastRewrapToken, token) {
		return false, nil
	}
	return bytes.Equal(recovery.Salt, want.RecoverySalt) &&
		recovery.Argon2Params == want.RecoveryArgon2Params &&
		bytes.Equal(recovery.WrappedPrivateKeys.Nonce, want.RecoveryWrappedPrivateKeys.Nonce) &&
		bytes.Equal(recovery.WrappedPrivateKeys.Ciphertext, want.RecoveryWrappedPrivateKeys.Ciphertext) &&
		bytes.Equal(recovery.VerifierSalt, want.RecoveryVerifierSalt) &&
		recovery.VerifierArgon2Params == want.RecoveryVerifierParams &&
		bytes.Equal(recovery.Verifier, want.RecoveryVerifier), nil
}

// RewrapMaterial is the subset of RewrapCredentialsInput's RECOVERY-item
// fields IsOwnRewrap compares against what's actually stored -- not the
// PROFILE-item fields (Salt/Argon2Params/WrappedPrivateKeys for the
// password copy), since RECOVERY's own version+token match already proves
// this exact call's whole transaction landed (PROFILE and RECOVERY are
// always written together by the same RewrapCredentials call, under the
// same version condition -- see that function's own doc comment), so a
// second, independent comparison of PROFILE's fields would be redundant
// with this one, not an additional guarantee.
type RewrapMaterial struct {
	RecoverySalt               []byte
	RecoveryArgon2Params       models.Argon2Params
	RecoveryWrappedPrivateKeys models.WrappedBlob

	RecoveryVerifierSalt   []byte
	RecoveryVerifierParams models.Argon2Params
	RecoveryVerifier       []byte
}
