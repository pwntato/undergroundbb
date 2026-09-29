package db

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// ListMembers returns one page of a group's MEMBER# rows in user-id order,
// starting strictly after afterUserID (empty for the first page), plus the
// last user id returned when more may follow (empty when the group is
// exhausted). The cursor is a bare user id rather than a DynamoDB key, so a
// caller-supplied cursor can only ever move within this group's partition.
func (c *Client) ListMembers(ctx context.Context, groupID, afterUserID string, limit int) ([]models.Membership, string, error) {
	in := &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			":sk": &types.AttributeValueMemberS{Value: "MEMBER#"},
		},
		// One extra row tells us whether another page exists, so the last page
		// never carries a cursor that leads to an empty one.
		Limit: aws.Int32(int32(limit + 1)),
	}
	if afterUserID != "" {
		in.ExclusiveStartKey = map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + afterUserID},
		}
	}
	out, err := c.ddb.Query(ctx, in)
	if err != nil {
		return nil, "", fmt.Errorf("db: list members: %w", err)
	}
	var members []models.Membership
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &members); err != nil {
		return nil, "", fmt.Errorf("db: unmarshal members: %w", err)
	}
	next := ""
	if len(members) > limit {
		members = members[:limit]
		next = strings.TrimPrefix(members[limit-1].SK, "MEMBER#")
	}
	return members, next, nil
}

// Errors returned by ChangeMemberRole. Each maps to a distinct, retryable
// 409 -- the caller reloads and re-signs.
var (
	// ErrGrantorChanged: the grantor's own role or current grant is no
	// longer what the signed grantorGrantRef assumed.
	ErrGrantorChanged = errors.New("db: grantor's role or current grant changed")
	// ErrSubjectRoleChanged: the subject's role is no longer the one the
	// caller saw (another admin changed it first), or they left.
	ErrSubjectRoleChanged = errors.New("db: subject's role changed")
	// ErrGrantKeyTaken: a GRANT# row already exists at the chosen sort key.
	ErrGrantKeyTaken = errors.New("db: grant sort key taken")
	// ErrRoleChangeConflict: a concurrent transaction touched one of the
	// rows (DynamoDB's TransactionConflict). Nothing was written; retry.
	ErrRoleChangeConflict = errors.New("db: concurrent role change, retry")
)

// ChangeMemberRoleInput is one signed role change. The handler has already
// verified Signature against the grantor's current signing key; like every
// other signature this package stores, db does not check it.
type ChangeMemberRoleInput struct {
	GroupID       string
	SubjectUserID string
	OldRole       string
	NewRole       string

	GrantorUserID           string
	GrantorSigningPublicKey []byte
	// GrantorGrantRef is the sort key of the grantor's own current grant, as
	// signed. GrantorHasStoredGrant says whether their MEMBER# row records
	// it (Membership.GrantSortKey); when false it came from the
	// Group.RootGrantSortKey fallback and the row must still lack the
	// attribute.
	GrantorGrantRef       string
	GrantorHasStoredGrant bool

	GrantSortKey string
	Signature    []byte
}

// ChangeMemberRole appends the signed grant and applies the new role in one
// transaction: (0) the grantor is still Admin and still on the grant they
// signed against, (1) the subject still holds OldRole, (2) the grant row is
// new. Grants are append-only, so a demotion is also just a grant; nothing
// is overwritten or deleted. CreatedAt is deliberately unset on the grant
// row -- see issue #147; the sort key already carries the day and no more.
func (c *Client) ChangeMemberRole(ctx context.Context, in ChangeMemberRoleInput) error {
	grant := models.RoleGrant{
		Record: models.Record{
			PK:   "GROUP#" + in.GroupID,
			SK:   in.GrantSortKey,
			Type: "RoleGrant",
		},
		SubjectUserID:           in.SubjectUserID,
		GrantedRole:             in.NewRole,
		GrantorUserID:           in.GrantorUserID,
		GrantorSigningPublicKey: in.GrantorSigningPublicKey,
		GrantorGrantRef:         in.GrantorGrantRef,
		Signature:               in.Signature,
	}
	grantItem, err := attributevalue.MarshalMap(grant)
	if err != nil {
		return err
	}

	grantorCond := "#role = :admin AND attribute_not_exists(#gsk)"
	grantorNames := map[string]string{"#role": "Role", "#gsk": "GrantSortKey"}
	grantorValues := map[string]types.AttributeValue{
		":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin},
	}
	if in.GrantorHasStoredGrant {
		grantorCond = "#role = :admin AND #gsk = :ref"
		grantorValues[":ref"] = &types.AttributeValueMemberS{Value: in.GrantorGrantRef}
	}

	const (
		grantorIndex = 0
		subjectIndex = 1
		grantIndex   = 2
	)
	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{ConditionCheck: &types.ConditionCheck{
				TableName: aws.String(c.table),
				Key: map[string]types.AttributeValue{
					"PK": &types.AttributeValueMemberS{Value: "GROUP#" + in.GroupID},
					"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + in.GrantorUserID},
				},
				ConditionExpression:       aws.String(grantorCond),
				ExpressionAttributeNames:  grantorNames,
				ExpressionAttributeValues: grantorValues,
			}},
			{Update: &types.Update{
				TableName: aws.String(c.table),
				Key: map[string]types.AttributeValue{
					"PK": &types.AttributeValueMemberS{Value: "GROUP#" + in.GroupID},
					"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + in.SubjectUserID},
				},
				UpdateExpression:         aws.String("SET #role = :new, #gsk = :gsk"),
				ConditionExpression:      aws.String("#role = :old"),
				ExpressionAttributeNames: map[string]string{"#role": "Role", "#gsk": "GrantSortKey"},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":new": &types.AttributeValueMemberS{Value: in.NewRole},
					":old": &types.AttributeValueMemberS{Value: in.OldRole},
					":gsk": &types.AttributeValueMemberS{Value: in.GrantSortKey},
				},
			}},
			{Put: &types.Put{
				TableName:           aws.String(c.table),
				Item:                grantItem,
				ConditionExpression: aws.String("attribute_not_exists(PK)"),
			}},
		},
	})
	if err != nil {
		switch {
		case isConditionalCheckFailure(err, grantorIndex):
			return ErrGrantorChanged
		case isConditionalCheckFailure(err, subjectIndex):
			return ErrSubjectRoleChanged
		case isConditionalCheckFailure(err, grantIndex):
			return ErrGrantKeyTaken
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		}
		return err
	}
	return nil
}
