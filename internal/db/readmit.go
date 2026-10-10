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

// ReadmitMemberInput is an admin's or ambassador's fresh signed admission of a
// current member whose earlier one no longer verifies (#178).
type ReadmitMemberInput struct {
	GroupID       string
	SubjectUserID string
	// SubjectEd25519, SubjectX25519 are the member's keys as the caller signed
	// them (the handler read them from the member's PROFILE).
	SubjectEd25519 []byte
	SubjectX25519  []byte
	CallerUserID   string
	// CallerGeneration is the caller's own entry-point generation, which the
	// admission signs; CallerGrantRef is their current grant.
	CallerGeneration int64
	CallerGrantRef   string
	// CallerHasStoredGrant is false for a creator on a group whose creator
	// membership carries no GrantSortKey (their grant is the root one).
	CallerHasStoredGrant bool
	InviteID             string
	Day                  string
	Signature            []byte
}

// ErrReadmitCallerChanged means the caller is no longer an admin or
// ambassador at the generation and grant they signed under.
var ErrReadmitCallerChanged = errors.New("db: caller's role, generation or grant changed")

// ReadmitMember replaces a member's ADMISSION# row with the caller's fresh
// signed record (#178, docs/DESIGN.md "Re-admitting a member"). There is no
// invite to complete, so the record carries a client-chosen id in the invite
// slot; the verifier never looks it up.
//
// One transaction: the caller must still be an admin or ambassador at the
// generation and grant they signed, the subject must still be a member whose
// account is not deleted, and the group must exist. The Put is unconditional
// like a rejoin's: a re-admission exists to replace a record that stopped
// verifying. A running rotation does NOT block it, because a rotation paused
// on an unadmitted member is exactly when it is needed.
func (c *Client) ReadmitMember(ctx context.Context, in ReadmitMemberInput) error {
	const (
		callerIndex  = 0
		subjectIndex = 1
		profileIndex = 2
		groupIndex   = 3
	)
	now := time.Now().UTC().Format(time.RFC3339)
	admission, err := attributevalue.MarshalMap(models.Admission{
		Record: models.Record{
			PK:        "GROUP#" + in.GroupID,
			SK:        "ADMISSION#" + in.SubjectUserID,
			Type:      "Admission",
			CreatedAt: now,
		},
		InviteeUserID:           in.SubjectUserID,
		InviterUserID:           in.CallerUserID,
		InviteID:                in.InviteID,
		InviteeEd25519PublicKey: in.SubjectEd25519,
		InviteeX25519PublicKey:  in.SubjectX25519,
		InviterGrantRef:         in.CallerGrantRef,
		Day:                     in.Day,
		Generation:              in.CallerGeneration,
		Signature:               in.Signature,
	})
	if err != nil {
		return err
	}
	// The caller must still hold the role, generation and grant they signed. A
	// creator whose membership stores no grant signed the root grant, and must
	// still have none stored.
	callerNames := map[string]string{"#role": "Role", "#gen": "Generation", "#grant": "GrantSortKey"}
	callerValues := map[string]types.AttributeValue{
		":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin},
		":amb":   &types.AttributeValueMemberS{Value: models.RoleAmbassador},
		":gen":   genAttr(in.CallerGeneration),
	}
	callerCond := "#role IN (:admin, :amb) AND #gen = :gen AND "
	if in.CallerHasStoredGrant {
		callerCond += "#grant = :ref"
		callerValues[":ref"] = &types.AttributeValueMemberS{Value: in.CallerGrantRef}
	} else {
		callerCond += "attribute_not_exists(#grant)"
	}
	items := []types.TransactWriteItem{
		{ConditionCheck: &types.ConditionCheck{
			TableName:                 aws.String(c.table),
			Key:                       memberKey(in.GroupID, in.CallerUserID),
			ConditionExpression:       aws.String(callerCond),
			ExpressionAttributeNames:  callerNames,
			ExpressionAttributeValues: callerValues,
		}},
		{ConditionCheck: &types.ConditionCheck{
			TableName:           aws.String(c.table),
			Key:                 memberKey(in.GroupID, in.SubjectUserID),
			ConditionExpression: aws.String("attribute_exists(PK)"),
		}},
		{ConditionCheck: &types.ConditionCheck{
			TableName: aws.String(c.table),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "USER#" + in.SubjectUserID},
				"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
			},
			ConditionExpression: aws.String("attribute_not_exists(DeletedAt)"),
		}},
		{ConditionCheck: &types.ConditionCheck{
			TableName: aws.String(c.table),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "GROUP#" + in.GroupID},
				"SK": &types.AttributeValueMemberS{Value: "META"},
			},
			ConditionExpression: aws.String("attribute_exists(PK)"),
		}},
		{Put: &types.Put{TableName: aws.String(c.table), Item: admission}},
	}
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		switch {
		case isConditionalCheckFailure(err, callerIndex):
			return ErrReadmitCallerChanged
		case isConditionalCheckFailure(err, subjectIndex):
			return ErrNotMember
		case isConditionalCheckFailure(err, profileIndex):
			return ErrSubjectDeleted
		case isConditionalCheckFailure(err, groupIndex):
			return ErrGroupGone
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		}
		return err
	}
	return nil
}
