package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// Errors returned by ClaimDesignation.
var (
	// ErrClaimAdminChanged: the designating admin is no longer an admin, or no
	// longer on the grant the designation was signed against.
	ErrClaimAdminChanged = errors.New("db: designating admin's role or current grant changed")
	// ErrClaimRoleChanged: the successor's own role is no longer the one the
	// claim was checked against (someone changed it first, or they left).
	ErrClaimRoleChanged = errors.New("db: successor's role changed")
	// ErrClaimSuccessorDeleted: the successor's account was deleted (#77).
	ErrClaimSuccessorDeleted = errors.New("db: successor's account was deleted")
	// ErrClaimKeyTaken: a GRANT# row already exists at the claim's sort key.
	ErrClaimKeyTaken = errors.New("db: claim sort key taken")
	// ErrClaimConflict: a concurrent transaction touched one of the rows;
	// nothing was written, retry.
	ErrClaimConflict = errors.New("db: concurrent claim, retry")
)

// ClaimDesignationInput is one signed successor claim. The handler has
// already verified Signature against the successor's current signing key and
// run every eligibility check; like every other signature this package
// stores, db does not check it.
type ClaimDesignationInput struct {
	GroupID     string
	AdminUserID string
	// AdminGrantRef is the admin's grant as the designation signed it.
	// AdminHasStoredGrant says whether their MEMBER# row records it
	// (Membership.GrantSortKey); when false it came from the
	// Group.RootGrantSortKey fallback and the row must still lack the attribute.
	AdminGrantRef       string
	AdminHasStoredGrant bool

	SuccessorUserID string
	// SuccessorOldRole is the role the successor held when the claim was
	// checked: ambassador or member.
	SuccessorOldRole string

	DesignationSortKey string
	ClaimSortKey       string
	Signature          []byte
}

// ClaimDesignation appends the successor's claim as a GRANT# row and makes the
// successor an admin, in one transaction: (0) the designating admin is still an
// admin on the grant the designation signed against, (1) the successor still
// holds the role the claim was checked against, and is set to admin on the new
// grant, (2) the row is new, and (3) the successor's account is not deleted.
// The conditions on (1) are also what makes two concurrent claims safe: the
// second finds the role already changed. Nothing is overwritten or deleted.
// CreatedAt is unset on the row, like every grant's (issue #147).
func (c *Client) ClaimDesignation(ctx context.Context, in ClaimDesignationInput) error {
	row := models.RoleGrant{
		Record: models.Record{
			PK:   "GROUP#" + in.GroupID,
			SK:   in.ClaimSortKey,
			Type: "RoleGrant",
		},
		SubjectUserID:   in.SuccessorUserID,
		GrantedRole:     models.RoleAdmin,
		GrantorUserID:   in.AdminUserID,
		GrantorGrantRef: in.AdminGrantRef,
		ViaDesignation:  in.DesignationSortKey,
		Signature:       in.Signature,
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return err
	}

	adminCond := "#role = :admin AND attribute_not_exists(#gsk)"
	adminNames := map[string]string{"#role": "Role", "#gsk": "GrantSortKey"}
	adminValues := map[string]types.AttributeValue{
		":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin},
	}
	if in.AdminHasStoredGrant {
		adminCond = "#role = :admin AND #gsk = :ref"
		adminValues[":ref"] = &types.AttributeValueMemberS{Value: in.AdminGrantRef}
	}

	const (
		adminIndex     = 0
		successorIndex = 1
		rowIndex       = 2
		profileIndex   = 3
	)
	items := []types.TransactWriteItem{
		{ConditionCheck: &types.ConditionCheck{
			TableName:                 aws.String(c.table),
			Key:                       memberKey(in.GroupID, in.AdminUserID),
			ConditionExpression:       aws.String(adminCond),
			ExpressionAttributeNames:  adminNames,
			ExpressionAttributeValues: adminValues,
		}},
		{Update: &types.Update{
			TableName:                aws.String(c.table),
			Key:                      memberKey(in.GroupID, in.SuccessorUserID),
			UpdateExpression:         aws.String("SET #role = :new, #gsk = :gsk"),
			ConditionExpression:      aws.String("#role = :old"),
			ExpressionAttributeNames: map[string]string{"#role": "Role", "#gsk": "GrantSortKey"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":new": &types.AttributeValueMemberS{Value: models.RoleAdmin},
				":old": &types.AttributeValueMemberS{Value: in.SuccessorOldRole},
				":gsk": &types.AttributeValueMemberS{Value: in.ClaimSortKey},
			},
		}},
		{Put: &types.Put{
			TableName:           aws.String(c.table),
			Item:                item,
			ConditionExpression: aws.String("attribute_not_exists(PK)"),
		}},
		{ConditionCheck: &types.ConditionCheck{
			TableName: aws.String(c.table),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "USER#" + in.SuccessorUserID},
				"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
			},
			ConditionExpression: aws.String("attribute_not_exists(DeletedAt)"),
		}},
	}
	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if err != nil {
		switch {
		case isConditionalCheckFailure(err, adminIndex):
			return ErrClaimAdminChanged
		case isConditionalCheckFailure(err, successorIndex):
			return ErrClaimRoleChanged
		case isConditionalCheckFailure(err, rowIndex):
			return ErrClaimKeyTaken
		case isConditionalCheckFailure(err, profileIndex):
			return ErrClaimSuccessorDeleted
		case isTransactionConflict(err):
			return ErrClaimConflict
		}
		return fmt.Errorf("db: claim designation: %w", err)
	}
	return nil
}

// GetDesignation returns the DESIGNATION# row at sortKey, or nil if there is
// none.
func (c *Client) GetDesignation(ctx context.Context, groupID, sortKey string) (*models.SuccessorDesignation, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			"SK": &types.AttributeValueMemberS{Value: sortKey},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("db: get designation: %w", err)
	}
	if out.Item == nil {
		return nil, nil
	}
	var d models.SuccessorDesignation
	if err := attributevalue.UnmarshalMap(out.Item, &d); err != nil {
		return nil, fmt.Errorf("db: unmarshal designation: %w", err)
	}
	return &d, nil
}

// queryAllPrefix reads every row of a group under an SK prefix, strongly
// consistent, following LastEvaluatedKey. filter, when non-empty, is a
// DynamoDB FilterExpression over values.
func (c *Client) queryAllPrefix(ctx context.Context, groupID, prefix, filter string, names map[string]string, values map[string]types.AttributeValue) ([]map[string]types.AttributeValue, error) {
	vals := map[string]types.AttributeValue{
		":pk": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
		":sk": &types.AttributeValueMemberS{Value: prefix},
	}
	for k, v := range values {
		vals[k] = v
	}
	in := &dynamodb.QueryInput{
		TableName:                 aws.String(c.table),
		KeyConditionExpression:    aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: vals,
		ConsistentRead:            aws.Bool(true),
	}
	if filter != "" {
		in.FilterExpression = aws.String(filter)
		in.ExpressionAttributeNames = names
	}
	var all []map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		all = append(all, out.Items...)
		if out.LastEvaluatedKey == nil {
			return all, nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}

// ListAdminDesignations returns every DESIGNATION# row the admin has signed in
// the group, in day order.
func (c *Client) ListAdminDesignations(ctx context.Context, groupID, adminUserID string) ([]models.SuccessorDesignation, error) {
	items, err := c.queryAllPrefix(ctx, groupID, "DESIGNATION#"+adminUserID+"#", "", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("db: list admin designations: %w", err)
	}
	var rows []models.SuccessorDesignation
	if err := attributevalue.UnmarshalListOfMaps(items, &rows); err != nil {
		return nil, fmt.Errorf("db: unmarshal designations: %w", err)
	}
	return rows, nil
}

// ListGrantsTo returns every GRANT# row whose subject is subjectUserID, in day
// order: the role changes that happened to them.
func (c *Client) ListGrantsTo(ctx context.Context, groupID, subjectUserID string) ([]models.RoleGrant, error) {
	items, err := c.queryAllPrefix(ctx, groupID, "GRANT#"+subjectUserID+"#", "", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("db: list grants to subject: %w", err)
	}
	var rows []models.RoleGrant
	if err := attributevalue.UnmarshalListOfMaps(items, &rows); err != nil {
		return nil, fmt.Errorf("db: unmarshal grants: %w", err)
	}
	return rows, nil
}

// ListGrantsCiting returns every GRANT# row in the group that relies on the
// designation (ViaDesignation == designationSortKey): its earlier activations.
func (c *Client) ListGrantsCiting(ctx context.Context, groupID, designationSortKey string) ([]models.RoleGrant, error) {
	items, err := c.queryAllPrefix(ctx, groupID, "GRANT#", "ViaDesignation = :d", nil,
		map[string]types.AttributeValue{":d": &types.AttributeValueMemberS{Value: designationSortKey}})
	if err != nil {
		return nil, fmt.Errorf("db: list grants citing designation: %w", err)
	}
	var rows []models.RoleGrant
	if err := attributevalue.UnmarshalListOfMaps(items, &rows); err != nil {
		return nil, fmt.Errorf("db: unmarshal grants: %w", err)
	}
	return rows, nil
}

// ListAdminMembers returns every member of the group whose role is admin, read
// strongly consistent so an admin promoted a moment ago is not missed.
func (c *Client) ListAdminMembers(ctx context.Context, groupID string) ([]models.Membership, error) {
	var admins []models.Membership
	after := ""
	for {
		page, next, err := c.listMembers(ctx, groupID, after, 200, true)
		if err != nil {
			return nil, err
		}
		for _, m := range page {
			if m.Role == models.RoleAdmin {
				admins = append(admins, m)
			}
		}
		if next == "" {
			return admins, nil
		}
		after = next
	}
}
