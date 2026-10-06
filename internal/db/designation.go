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

// Errors returned by PutDesignation.
var (
	// ErrDesignationAdminChanged: the admin is no longer an admin, or no longer
	// on the grant they signed against.
	ErrDesignationAdminChanged = errors.New("db: designating admin's role or current grant changed")
	// ErrDesignationSuccessorGone: the named successor is not a member.
	ErrDesignationSuccessorGone = errors.New("db: successor is not a member")
	// ErrDesignationSuccessorDeleted: the named successor's account was deleted (#77).
	ErrDesignationSuccessorDeleted = errors.New("db: successor's account was deleted")
	// ErrDesignationKeyTaken: a DESIGNATION# row already exists at the sort key.
	ErrDesignationKeyTaken = errors.New("db: designation sort key taken")
	// ErrDesignationConflict: a concurrent transaction touched one of the rows;
	// nothing was written, retry.
	ErrDesignationConflict = errors.New("db: concurrent designation change, retry")
)

// PutDesignationInput is one signed designation. The handler has already
// verified Signature against the admin's current signing key; like every other
// signature this package stores, db does not check it.
type PutDesignationInput struct {
	GroupID     string
	AdminUserID string
	SortKey     string
	// SuccessorUserID is empty to revoke.
	SuccessorUserID string
	PeriodDays      int
	// AdminGrantRef is the admin's own current grant, as signed.
	// AdminHasStoredGrant says whether their MEMBER# row records it
	// (Membership.GrantSortKey); when false it came from the
	// Group.RootGrantSortKey fallback and the row must still lack the attribute.
	AdminGrantRef       string
	AdminHasStoredGrant bool
	Signature           []byte
}

// PutDesignation appends the signed designation in one transaction: (0) the
// admin is still an admin on the grant they signed against, (1) for a named
// successor, they are still a member and (2) their account is not deleted,
// and (last) the row is new. Nothing is overwritten or deleted. CreatedAt is
// unset on the row, like a grant's (issue #147): the sort key carries the day.
func (c *Client) PutDesignation(ctx context.Context, in PutDesignationInput) error {
	row := models.SuccessorDesignation{
		Record: models.Record{
			PK:   "GROUP#" + in.GroupID,
			SK:   in.SortKey,
			Type: "SuccessorDesignation",
		},
		AdminUserID:     in.AdminUserID,
		SuccessorUserID: in.SuccessorUserID,
		PeriodDays:      in.PeriodDays,
		AdminGrantRef:   in.AdminGrantRef,
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

	items := []types.TransactWriteItem{
		{ConditionCheck: &types.ConditionCheck{
			TableName:                 aws.String(c.table),
			Key:                       memberKey(in.GroupID, in.AdminUserID),
			ConditionExpression:       aws.String(adminCond),
			ExpressionAttributeNames:  adminNames,
			ExpressionAttributeValues: adminValues,
		}},
	}
	const adminIndex = 0
	successorIndex, profileIndex := -1, -1
	if in.SuccessorUserID != "" {
		successorIndex = len(items)
		items = append(items, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName:           aws.String(c.table),
			Key:                 memberKey(in.GroupID, in.SuccessorUserID),
			ConditionExpression: aws.String("attribute_exists(PK)"),
		}})
		profileIndex = len(items)
		items = append(items, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName: aws.String(c.table),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "USER#" + in.SuccessorUserID},
				"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
			},
			ConditionExpression: aws.String("attribute_not_exists(DeletedAt)"),
		}})
	}
	putIndex := len(items)
	items = append(items, types.TransactWriteItem{Put: &types.Put{
		TableName:           aws.String(c.table),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(PK)"),
	}})

	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if err != nil {
		switch {
		case isConditionalCheckFailure(err, adminIndex):
			return ErrDesignationAdminChanged
		case successorIndex >= 0 && isConditionalCheckFailure(err, successorIndex):
			return ErrDesignationSuccessorGone
		case profileIndex >= 0 && isConditionalCheckFailure(err, profileIndex):
			return ErrDesignationSuccessorDeleted
		case isConditionalCheckFailure(err, putIndex):
			return ErrDesignationKeyTaken
		case isTransactionConflict(err):
			return ErrDesignationConflict
		}
		return fmt.Errorf("db: put designation: %w", err)
	}
	return nil
}

// ListDesignations returns one page of a group's DESIGNATION# rows in sort-key
// order (admin uuid, then day), starting strictly after afterSortKey (empty for
// the first page), plus the last sort key returned when more may follow. The
// cursor is a sort key rather than a DynamoDB key, so a caller-supplied one can
// only ever move within this group's partition.
func (c *Client) ListDesignations(ctx context.Context, groupID, afterSortKey string, limit int) ([]models.SuccessorDesignation, string, error) {
	in := &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			":sk": &types.AttributeValueMemberS{Value: "DESIGNATION#"},
		},
		ConsistentRead: aws.Bool(true),
		Limit:          aws.Int32(int32(limit + 1)),
	}
	if afterSortKey != "" {
		in.ExclusiveStartKey = map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			"SK": &types.AttributeValueMemberS{Value: afterSortKey},
		}
	}
	out, err := c.ddb.Query(ctx, in)
	if err != nil {
		return nil, "", fmt.Errorf("db: list designations: %w", err)
	}
	var rows []models.SuccessorDesignation
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &rows); err != nil {
		return nil, "", fmt.Errorf("db: unmarshal designations: %w", err)
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		next = rows[limit-1].SK
	}
	return rows, next, nil
}

// HasDesignationOnDay reports whether the admin already has a designation
// dated day ("2006-01-02", UTC). Order within a day is unknowable, so a second
// one is refused. This is a read before the write, so two concurrent requests
// can both pass; that is harmless, because the verifier cancels two
// same-day designations by one admin (docs/DESIGN.md).
func (c *Client) HasDesignationOnDay(ctx context.Context, groupID, adminUserID, day string) (bool, error) {
	out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			":sk": &types.AttributeValueMemberS{Value: "DESIGNATION#" + adminUserID + "#" + day + "#"},
		},
		ProjectionExpression: aws.String("SK"),
		ConsistentRead:       aws.Bool(true),
		Limit:                aws.Int32(1),
	})
	if err != nil {
		return false, fmt.Errorf("db: check designation day: %w", err)
	}
	return len(out.Items) > 0, nil
}

// RecordLogin stamps PROFILE.LastLoginDay with day ("2006-01-02", UTC) after a
// successful login (#161). One conditional write at most per day: a repeat on
// the same day, or a stale day, fails the condition and is not an error.
func (c *Client) RecordLogin(ctx context.Context, userID, day string) error {
	_, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		UpdateExpression:          aws.String("SET LastLoginDay = :day"),
		ConditionExpression:       aws.String("attribute_exists(PK) AND (attribute_not_exists(LastLoginDay) OR LastLoginDay < :day)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":day": &types.AttributeValueMemberS{Value: day}},
	})
	if err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) {
			return nil
		}
		return fmt.Errorf("db: record login: %w", err)
	}
	return nil
}
