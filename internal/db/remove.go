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

// RemoveMemberInput is one admin removing another member -- issue #58.
type RemoveMemberInput struct {
	GroupID       string
	SubjectUserID string
	// SubjectRole is the role the caller saw the subject hold; the delete is
	// conditioned on it so a role change in between is a conflict, not a
	// removal that signs the wrong demotion (or none).
	SubjectRole string

	RemoverUserID string
	// RemoverHasStoredGrant says whether the remover's MEMBER# row records
	// RemoverGrantRef (Membership.GrantSortKey); when false the ref came from
	// the Group.RootGrantSortKey fallback and the row must still lack it.
	RemoverHasStoredGrant bool
	RemoverGrantRef       string

	// Demotion is the remover's signed grant of "member" to the subject,
	// appended in the same transaction. Required exactly when SubjectRole is
	// admin or ambassador (nil otherwise): a removed admin's last grant would
	// otherwise still say admin, and a later rejoin (baseline member) would
	// read as a forged demotion. Because the REMOVER signs it, nothing here
	// needs the removed admin's cooperation, which is what an involuntary
	// removal cannot have.
	Demotion *RemoveDemotion
}

// RemoveDemotion is the signed grant a removal appends for an elevated subject.
type RemoveDemotion struct {
	GrantSortKey     string
	SigningPublicKey []byte // the remover's key, as served at write time
	Signature        []byte
}

// RemoveMember deletes the subject's membership in one transaction:
// (0) the remover is still Admin and still on the grant they signed against,
// (1) the subject still holds SubjectRole and is deleted, (2) for an elevated
// subject, the demotion grant is new. Grants the subject signed or received
// stay; history is append-only. The subject's own outstanding invites are
// removed afterwards, as on leaving.
//
// This does NOT rotate keys. For an Open group that is the whole definition
// of removal (docs/DESIGN.md, "Revocation mode"); the handler refuses a
// Rotating group until rotation exists, because removing without rotating
// there would leave the removed member reading every new post while nothing
// said so.
func (c *Client) RemoveMember(ctx context.Context, in RemoveMemberInput) error {
	elevated := in.SubjectRole != models.RoleMember
	if elevated != (in.Demotion != nil) {
		return ErrRoleChangeConflict
	}

	removerCond := "#role = :admin AND attribute_not_exists(#gsk)"
	removerValues := map[string]types.AttributeValue{
		":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin},
	}
	if in.RemoverHasStoredGrant {
		removerCond = "#role = :admin AND #gsk = :ref"
		removerValues[":ref"] = &types.AttributeValueMemberS{Value: in.RemoverGrantRef}
	}

	const (
		removerIndex = 0
		deleteIndex  = 1
		grantIndex   = 2
	)
	items := []types.TransactWriteItem{
		{ConditionCheck: &types.ConditionCheck{
			TableName:                 aws.String(c.table),
			Key:                       memberKey(in.GroupID, in.RemoverUserID),
			ConditionExpression:       aws.String(removerCond),
			ExpressionAttributeNames:  map[string]string{"#role": "Role", "#gsk": "GrantSortKey"},
			ExpressionAttributeValues: removerValues,
		}},
		{Delete: &types.Delete{
			TableName:                aws.String(c.table),
			Key:                      memberKey(in.GroupID, in.SubjectUserID),
			ConditionExpression:      aws.String("#role = :old"),
			ExpressionAttributeNames: map[string]string{"#role": "Role"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":old": &types.AttributeValueMemberS{Value: in.SubjectRole},
			},
		}},
	}
	if elevated {
		grantItem, err := attributevalue.MarshalMap(models.RoleGrant{
			Record: models.Record{
				PK:   "GROUP#" + in.GroupID,
				SK:   in.Demotion.GrantSortKey,
				Type: "RoleGrant",
			},
			SubjectUserID:           in.SubjectUserID,
			GrantedRole:             models.RoleMember,
			GrantorUserID:           in.RemoverUserID,
			GrantorSigningPublicKey: in.Demotion.SigningPublicKey,
			GrantorGrantRef:         in.RemoverGrantRef,
			Signature:               in.Demotion.Signature,
		})
		if err != nil {
			return err
		}
		items = append(items, types.TransactWriteItem{Put: &types.Put{
			TableName:           aws.String(c.table),
			Item:                grantItem,
			ConditionExpression: aws.String("attribute_not_exists(PK)"),
		}})
	}

	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		switch {
		case isConditionalCheckFailure(err, removerIndex):
			return ErrGrantorChanged
		case isConditionalCheckFailure(err, deleteIndex):
			return ErrSubjectRoleChanged
		case elevated && isConditionalCheckFailure(err, grantIndex):
			return ErrGrantKeyTaken
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		}
		return err
	}
	if err := c.deleteOwnInvites(ctx, in.GroupID, in.SubjectUserID); err != nil {
		return fmt.Errorf("%w: %v", ErrInviteCleanupIncomplete, err)
	}
	return nil
}
