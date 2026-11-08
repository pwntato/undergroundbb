package db

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/pwntato/undergroundbb/internal/models"
)

// Join requests (#72). One row per user per public group at GROUP#<gid> /
// REQ#<requester uuid>, with a GSI1 entry on the requester. See models.JoinRequest
// for the shape and docs/DESIGN.md, "Visibility -- private and public groups".

const (
	// JoinRequestPendingTTL is how long an unanswered request lives. It is the
	// only bound on a pending request, so a request nobody answers does not sit
	// in the requester's partition for ever as a record of who they asked to join.
	JoinRequestPendingTTL = 90 * 24 * time.Hour
	// JoinRequestCoolOff is how long a denied request keeps its slot. A denial
	// is not a ban: the requester sees "declined" for this long and may ask
	// again afterwards. No role in the design grants a ban, and a slot that never
	// freed itself would be one.
	JoinRequestCoolOff = 7 * 24 * time.Hour

	joinRequestPrefix = "REQ#"
)

// A filtered read of one group's queue examines at most joinRequestPageRows rows per pass
// (DynamoDB's Limit counts rows examined, before the filter) and keeps only the pending
// ones, so the work of one pass is fixed however many denied rows are cooling off. It makes
// at most maxJoinRequestPasses passes, then hands back a cursor. Variables so a test can
// lower them.
var (
	joinRequestPageRows  int32 = 500
	maxJoinRequestPasses       = 10
)

var (
	// ErrJoinRequestPending means the requester already has a pending request in
	// this group.
	ErrJoinRequestPending = errors.New("db: a join request is already pending")
	// ErrJoinRequestCoolingOff means the requester's last request was denied and
	// its cool-off has not ended.
	ErrJoinRequestCoolingOff = errors.New("db: the last join request was denied; it is cooling off")
	// ErrJoinRequestNotFound means no live request to act on: it never existed,
	// has expired, was withdrawn, was decided already, or carries a different
	// request id than the caller expected.
	ErrJoinRequestNotFound = errors.New("db: no such join request")
	// ErrNotPublicGroup means the group is gone or is not a public group.
	ErrNotPublicGroup = errors.New("db: no such public group")
	// ErrApproverNotEligible means the approver is no longer an admin or
	// ambassador at the generation they signed under.
	ErrApproverNotEligible = errors.New("db: approver is no longer an admin or ambassador")
)

func joinRequestKey(groupID, requesterID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
		"SK": &types.AttributeValueMemberS{Value: joinRequestPrefix + requesterID},
	}
}

func unixAttr(t time.Time) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(t.Unix(), 10)}
}

// CreateJoinRequestInput is one new request. The keys are the requester's current
// keys, read by the handler from their PROFILE; RequesterKeyEpoch is the epoch they
// were read at, checked again in the transaction so a request is never written for
// keys the requester has just rotated away from.
type CreateJoinRequestInput struct {
	GroupID           string
	RequesterUserID   string
	RequestID         string
	Ed25519PublicKey  []byte
	X25519PublicKey   []byte
	Signature         []byte
	RequesterKeyEpoch uint64
}

// CreateJoinRequest writes the request. It succeeds only when the group exists and
// is public, the requester is not already a member, their account is live and still
// at the epoch the keys were read at, and their slot is empty or its TTL has passed
// (an expired row is not yet swept, and must not block a new request).
func (c *Client) CreateJoinRequest(ctx context.Context, in CreateJoinRequestInput) error {
	now := time.Now()
	row := models.JoinRequest{
		Record: models.Record{
			PK:     "GROUP#" + in.GroupID,
			SK:     joinRequestPrefix + in.RequesterUserID,
			Type:   "JoinRequest",
			GSI1PK: "USER#" + in.RequesterUserID,
			GSI1SK: joinRequestPrefix + inviteDaySuffix(now),
		},
		TTL:              RoundUpToEndOfUTCDay(now.Add(JoinRequestPendingTTL)).Unix(),
		RequestID:        in.RequestID,
		GroupID:          in.GroupID,
		RequesterUserID:  in.RequesterUserID,
		Status:           models.JoinRequestPending,
		Ed25519PublicKey: in.Ed25519PublicKey,
		X25519PublicKey:  in.X25519PublicKey,
		Signature:        in.Signature,
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return err
	}
	const (
		slotIndex   = 0
		groupIndex  = 1
		memberIndex = 2
		profileIdx  = 3
	)
	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName:                aws.String(c.table),
				Item:                     item,
				ConditionExpression:      aws.String("attribute_not_exists(PK) OR #ttl < :now"),
				ExpressionAttributeNames: map[string]string{"#ttl": "TTL"},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":now": unixAttr(now),
				},
			}},
			{ConditionCheck: &types.ConditionCheck{
				TableName:                aws.String(c.table),
				Key:                      map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: "GROUP#" + in.GroupID}, "SK": &types.AttributeValueMemberS{Value: "META"}},
				ConditionExpression:      aws.String("attribute_exists(PK) AND #vis = :public"),
				ExpressionAttributeNames: map[string]string{"#vis": "Visibility"},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":public": &types.AttributeValueMemberS{Value: models.VisibilityPublic},
				},
			}},
			{ConditionCheck: &types.ConditionCheck{
				TableName:           aws.String(c.table),
				Key:                 map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: "GROUP#" + in.GroupID}, "SK": &types.AttributeValueMemberS{Value: "MEMBER#" + in.RequesterUserID}},
				ConditionExpression: aws.String("attribute_not_exists(PK)"),
			}},
			c.keyEpochCheck(in.RequesterUserID, in.RequesterKeyEpoch),
		},
	})
	if err == nil {
		return nil
	}
	if isConditionalCheckFailure(err, profileIdx) {
		deleted, whyErr := c.whyProfileCheckFailed(ctx, in.RequesterUserID)
		if whyErr != nil {
			return whyErr
		}
		if deleted {
			return ErrUserNotFound
		}
		return ErrWrapEpochStale
	}
	if isConditionalCheckFailure(err, groupIndex) {
		return ErrNotPublicGroup
	}
	if isConditionalCheckFailure(err, memberIndex) {
		return ErrAlreadyMember
	}
	if isConditionalCheckFailure(err, slotIndex) {
		existing, getErr := c.GetJoinRequest(ctx, in.GroupID, in.RequesterUserID, now)
		if getErr != nil {
			return getErr
		}
		if existing != nil && existing.Status == models.JoinRequestDenied {
			return ErrJoinRequestCoolingOff
		}
		return ErrJoinRequestPending
	}
	return err
}

// GetJoinRequest reads one request with a consistent read, or nil when there is none
// or its TTL has passed (the row may still be there: DynamoDB's deletion lags).
func (c *Client) GetJoinRequest(ctx context.Context, groupID, requesterID string, now time.Time) (*models.JoinRequest, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(c.table),
		Key:            joinRequestKey(groupID, requesterID),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("db: get join request: %w", err)
	}
	if out.Item == nil {
		return nil, nil
	}
	var jr models.JoinRequest
	if err := attributevalue.UnmarshalMap(out.Item, &jr); err != nil {
		return nil, fmt.Errorf("db: unmarshal join request: %w", err)
	}
	if jr.TTL != 0 && jr.TTL < now.Unix() {
		return nil, nil
	}
	return &jr, nil
}

// ListPendingJoinRequests returns up to limit pending requests for one group, in
// requester-uuid order, and a cursor for the next page ("" when there is none). It is
// a filtered Query over the group's REQ# range, so its cost is bounded by the pending
// requests plus denied rows still cooling off, not by history; it keeps reading until
// it has limit rows or has passed through the range, and gives up after
// maxJoinRequestPasses passes with a cursor rather than reading for ever.
func (c *Client) ListPendingJoinRequests(ctx context.Context, groupID string, now time.Time, limit int, cursor string) ([]models.JoinRequest, string, error) {
	var start map[string]types.AttributeValue
	if cursor != "" {
		start = joinRequestKey(groupID, strings.TrimPrefix(cursor, joinRequestPrefix))
	}
	var found []models.JoinRequest
	for pass := 0; pass < maxJoinRequestPasses; pass++ {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:                aws.String(c.table),
			KeyConditionExpression:   aws.String("PK = :pk AND begins_with(SK, :sk)"),
			FilterExpression:         aws.String("#st = :pending AND #ttl >= :now"),
			ExpressionAttributeNames: map[string]string{"#st": "Status", "#ttl": "TTL"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk":      &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
				":sk":      &types.AttributeValueMemberS{Value: joinRequestPrefix},
				":pending": &types.AttributeValueMemberS{Value: models.JoinRequestPending},
				":now":     unixAttr(now),
			},
			ExclusiveStartKey: start,
			ConsistentRead:    aws.Bool(true),
			Limit:             aws.Int32(joinRequestPageRows),
		})
		if err != nil {
			return nil, "", fmt.Errorf("db: list join requests: %w", err)
		}
		for _, it := range out.Items {
			var jr models.JoinRequest
			if err := attributevalue.UnmarshalMap(it, &jr); err != nil {
				return nil, "", fmt.Errorf("db: unmarshal join request: %w", err)
			}
			found = append(found, jr)
		}
		if len(found) > limit {
			// More than a page: cut at limit and resume after the last one returned.
			found = found[:limit]
			return found, found[len(found)-1].SK, nil
		}
		if out.LastEvaluatedKey == nil {
			return found, "", nil
		}
		start = out.LastEvaluatedKey
		if len(found) == limit {
			// Exactly a page and the range is not exhausted: a following page may be empty,
			// which the client learns by asking.
			return found, lastKeySK(out.LastEvaluatedKey), nil
		}
	}
	return found, lastKeySK(start), nil
}

func lastKeySK(key map[string]types.AttributeValue) string {
	if sk, ok := key["SK"].(*types.AttributeValueMemberS); ok {
		return sk.Value
	}
	return ""
}

// ListJoinRequestsByUser returns up to limit of the requester's own live requests across groups
// (pending and denied) from GSI1, oldest first, and a cursor for the next page ("" when there is
// none), so they can see what they asked for and what was declined. A user can have one request per
// public group, so the read is paged like the admin queue: expired rows are skipped in memory, a call
// makes at most maxJoinRequestPasses passes, and the cursor names the last row read.
func (c *Client) ListJoinRequestsByUser(ctx context.Context, requesterID string, now time.Time, limit int, cursor string) ([]models.JoinRequest, string, error) {
	var start map[string]types.AttributeValue
	if cursor != "" {
		groupID, gsi1SK, ok := splitOwnRequestCursor(cursor)
		if !ok {
			return nil, "", fmt.Errorf("db: list own join requests: malformed cursor")
		}
		start = map[string]types.AttributeValue{
			"PK":     &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			"SK":     &types.AttributeValueMemberS{Value: joinRequestPrefix + requesterID},
			"GSI1PK": &types.AttributeValueMemberS{Value: "USER#" + requesterID},
			"GSI1SK": &types.AttributeValueMemberS{Value: gsi1SK},
		}
	}
	var found []models.JoinRequest
	for pass := 0; pass < maxJoinRequestPasses; pass++ {
		page, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			IndexName:              aws.String("GSI1"),
			KeyConditionExpression: aws.String("GSI1PK = :pk AND begins_with(GSI1SK, :sk)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "USER#" + requesterID},
				":sk": &types.AttributeValueMemberS{Value: joinRequestPrefix},
			},
			ExclusiveStartKey: start,
			Limit:             aws.Int32(int32(limit)),
		})
		if err != nil {
			return nil, "", fmt.Errorf("db: list own join requests: %w", err)
		}
		for _, it := range page.Items {
			var jr models.JoinRequest
			if err := attributevalue.UnmarshalMap(it, &jr); err != nil {
				return nil, "", fmt.Errorf("db: unmarshal join request: %w", err)
			}
			if jr.TTL != 0 && jr.TTL < now.Unix() {
				continue
			}
			found = append(found, jr)
			if len(found) == limit {
				// Resume after this row, whether or not the page had more.
				return found, ownRequestCursor(jr.GroupID, jr.GSI1SK), nil
			}
		}
		if page.LastEvaluatedKey == nil {
			return found, "", nil
		}
		start = page.LastEvaluatedKey
	}
	return found, ownRequestCursorFromKey(start), nil
}

// ownRequestCursor names a row of the requester's own list: the group it is in and its GSI1 sort key
// (the requester's uuid is the caller's, so it is not part of the cursor).
func ownRequestCursor(groupID, gsi1SK string) string { return groupID + "/" + gsi1SK }

func ownRequestCursorFromKey(key map[string]types.AttributeValue) string {
	pk, _ := key["PK"].(*types.AttributeValueMemberS)
	sk, _ := key["GSI1SK"].(*types.AttributeValueMemberS)
	if pk == nil || sk == nil {
		return ""
	}
	return ownRequestCursor(strings.TrimPrefix(pk.Value, "GROUP#"), sk.Value)
}

func splitOwnRequestCursor(cursor string) (groupID, gsi1SK string, ok bool) {
	groupID, gsi1SK, ok = strings.Cut(cursor, "/")
	return groupID, gsi1SK, ok && groupID != "" && strings.HasPrefix(gsi1SK, joinRequestPrefix)
}

// PublicGroupNames returns the plaintext names of the public groups among groupIDs, keyed by id, in
// batched reads. A private or missing group is left out.
func (c *Client) PublicGroupNames(ctx context.Context, groupIDs []string) (map[string]string, error) {
	if len(groupIDs) == 0 {
		return map[string]string{}, nil
	}
	metas, err := c.batchGetGroupMetas(ctx, groupIDs)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(metas))
	for id, g := range metas {
		if g.Visibility == models.VisibilityPublic {
			out[id] = g.NamePlaintext
		}
	}
	return out, nil
}

// WithdrawJoinRequest deletes the requester's own pending request. A denied one is
// refused (ErrJoinRequestCoolingOff): withdrawing it would end the cool-off early.
func (c *Client) WithdrawJoinRequest(ctx context.Context, groupID, requesterID string, now time.Time) error {
	_, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                aws.String(c.table),
		Key:                      joinRequestKey(groupID, requesterID),
		ConditionExpression:      aws.String("#st = :pending AND #ttl >= :now"),
		ExpressionAttributeNames: map[string]string{"#st": "Status", "#ttl": "TTL"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pending": &types.AttributeValueMemberS{Value: models.JoinRequestPending},
			":now":     unixAttr(now),
		},
	})
	if err == nil {
		return nil
	}
	var ccf *types.ConditionalCheckFailedException
	if !errors.As(err, &ccf) {
		return err
	}
	existing, getErr := c.GetJoinRequest(ctx, groupID, requesterID, now)
	if getErr != nil {
		return getErr
	}
	if existing != nil && existing.Status == models.JoinRequestDenied {
		return ErrJoinRequestCoolingOff
	}
	return ErrJoinRequestNotFound
}

// approverCheck is the condition both decisions share: the decider is still an admin
// or ambassador, at the generation they signed under when one is given.
func approverCheck(c *Client, groupID, approverID string, generation *int64) types.TransactWriteItem {
	cond := "#role IN (:admin, :amb)"
	vals := map[string]types.AttributeValue{
		":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin},
		":amb":   &types.AttributeValueMemberS{Value: models.RoleAmbassador},
	}
	names := map[string]string{"#role": "Role"}
	if generation != nil {
		cond += " AND #gen = :gen"
		names["#gen"] = "Generation"
		vals[":gen"] = genAttr(*generation)
	}
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + approverID},
		},
		ConditionExpression:       aws.String(cond),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: vals,
	}}
}

// DenyJoinRequest marks a pending request denied and gives the row its cool-off TTL.
// The decider must still be an admin or ambassador, checked in the same transaction.
func (c *Client) DenyJoinRequest(ctx context.Context, groupID, requesterID, approverID string, now time.Time) error {
	const (
		requestIndex  = 0
		approverIndex = 1
	)
	_, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Update: &types.Update{
				TableName:                aws.String(c.table),
				Key:                      joinRequestKey(groupID, requesterID),
				UpdateExpression:         aws.String("SET #st = :denied, #ttl = :cool"),
				ConditionExpression:      aws.String("#st = :pending AND #ttl >= :now"),
				ExpressionAttributeNames: map[string]string{"#st": "Status", "#ttl": "TTL"},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":denied":  &types.AttributeValueMemberS{Value: models.JoinRequestDenied},
					":pending": &types.AttributeValueMemberS{Value: models.JoinRequestPending},
					":cool":    unixAttr(RoundUpToEndOfUTCDay(now.Add(JoinRequestCoolOff))),
					":now":     unixAttr(now),
				},
			}},
			approverCheck(c, groupID, approverID, nil),
		},
	})
	if err == nil {
		return nil
	}
	if isConditionalCheckFailure(err, approverIndex) {
		return ErrApproverNotEligible
	}
	if isConditionalCheckFailure(err, requestIndex) {
		return ErrJoinRequestNotFound
	}
	return err
}

// ApproveJoinRequestInput is the approver's decision. Everything about the requester
// (their keys, their uuid) comes from the request row, never from the caller.
type ApproveJoinRequestInput struct {
	GroupID         string
	RequesterUserID string
	// RequestID is the id on the row the caller verified; the delete is conditional on it
	// so a request replaced in between (withdrawn and made again) is not approved by
	// mistake.
	RequestID      string
	ApproverUserID string
	// RequesterKeyEpoch is the requester's KeyEpoch as the handler read it after checking
	// their current keys are the ones they signed.
	RequesterKeyEpoch uint64
	Generation        int64
	WrappedGroupKey   models.WrappedKey
	Role              string
	// Admission is the approver's signed record, with the request id in the invite slot.
	Admission models.Admission
	// MaxMembers, when positive, is the member cap of a Rotating group (#60): approval refuses with
	// ErrGroupFull once the group already has this many members. Zero means no cap. It is the same cap
	// an invite is held to; see withJoinCap.
	MaxMembers int
}

// ApproveJoinRequest writes the membership and the admission record and deletes the
// request, in one transaction. The request must still be live and unchanged, the
// approver still an admin or ambassador at the generation they wrapped under, the
// group still there, the requester not already a member and still at the epoch their
// keys were read at. A Rotating group is held to its member cap (ErrGroupFull), exactly as an
// invite's completion is, and the request stays pending when it is refused.
func (c *Client) ApproveJoinRequest(ctx context.Context, in ApproveJoinRequestInput) error {
	return c.withJoinCap(ctx, in.GroupID, in.RequesterUserID, in.MaxMembers, func(seenSeq *int64) error {
		return c.approveJoinRequestOnce(ctx, in, seenSeq)
	})
}

func (c *Client) approveJoinRequestOnce(ctx context.Context, in ApproveJoinRequestInput, seenSeq *int64) error {
	now := time.Now()
	membership := models.Membership{
		Record: models.Record{
			PK:        "GROUP#" + in.GroupID,
			SK:        "MEMBER#" + in.RequesterUserID,
			Type:      "Membership",
			CreatedAt: utcDay(now),
			GSI1PK:    "USER#" + in.RequesterUserID,
			GSI1SK:    "GROUP#" + in.GroupID,
		},
		Role:            in.Role,
		Generation:      in.Generation,
		WrappedGroupKey: in.WrappedGroupKey,
		WrapEpoch:       in.RequesterKeyEpoch,
	}
	membershipItem, err := attributevalue.MarshalMap(membership)
	if err != nil {
		return err
	}
	admission := in.Admission
	admission.Record = models.Record{
		PK:   "GROUP#" + in.GroupID,
		SK:   "ADMISSION#" + in.RequesterUserID,
		Type: "Admission",
	}
	admission.InviteeUserID = in.RequesterUserID
	admissionItem, err := attributevalue.MarshalMap(admission)
	if err != nil {
		return err
	}
	const (
		membershipIndex = 0
		requestIndex    = 1
		groupIndex      = 2
		approverIndex   = 3
		requesterIndex  = 4
	)
	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName:           aws.String(c.table),
				Item:                membershipItem,
				ConditionExpression: aws.String("attribute_not_exists(PK)"),
			}},
			{Delete: &types.Delete{
				TableName:                aws.String(c.table),
				Key:                      joinRequestKey(in.GroupID, in.RequesterUserID),
				ConditionExpression:      aws.String("#st = :pending AND RequestID = :rid AND #ttl >= :now"),
				ExpressionAttributeNames: map[string]string{"#st": "Status", "#ttl": "TTL"},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":pending": &types.AttributeValueMemberS{Value: models.JoinRequestPending},
					":rid":     &types.AttributeValueMemberS{Value: in.RequestID},
					":now":     unixAttr(now),
				},
			}},
			// The group must still exist and, for a capped join, JoinSeq must still be the value counted.
			c.joinMetaItem(in.GroupID, seenSeq),
			approverCheck(c, in.GroupID, in.ApproverUserID, &in.Generation),
			c.keyEpochCheck(in.RequesterUserID, in.RequesterKeyEpoch),
			{Put: &types.Put{TableName: aws.String(c.table), Item: admissionItem}},
		},
	})
	if err == nil {
		return nil
	}
	if seenSeq != nil && isTransactionConflict(err) {
		return errJoinRaced
	}
	if isConditionalCheckFailure(err, requesterIndex) {
		deleted, whyErr := c.whyProfileCheckFailed(ctx, in.RequesterUserID)
		if whyErr != nil {
			return whyErr
		}
		if deleted {
			return ErrInviteeDeleted
		}
		return ErrWrapEpochStale
	}
	if isConditionalCheckFailure(err, approverIndex) {
		return ErrApproverNotEligible
	}
	if isConditionalCheckFailure(err, groupIndex) {
		return c.joinMetaFailure(ctx, in.GroupID, seenSeq)
	}
	if isConditionalCheckFailure(err, membershipIndex) {
		return ErrAlreadyMember
	}
	if isConditionalCheckFailure(err, requestIndex) {
		return ErrJoinRequestNotFound
	}
	return err
}

// RemoveJoinRequest deletes a request that can never be approved (its requester's keys
// changed, or they are already a member), only if it is still pending and still carries
// requestID: a newer request in the same slot is left alone, and so is a denied one, whose
// cool-off must run its course (another approver may have denied it in the meantime). Not
// finding it is not an error.
func (c *Client) RemoveJoinRequest(ctx context.Context, groupID, requesterID, requestID string) error {
	_, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                aws.String(c.table),
		Key:                      joinRequestKey(groupID, requesterID),
		ConditionExpression:      aws.String("RequestID = :rid AND #st = :pending"),
		ExpressionAttributeNames: map[string]string{"#st": "Status"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":rid":     &types.AttributeValueMemberS{Value: requestID},
			":pending": &types.AttributeValueMemberS{Value: models.JoinRequestPending},
		},
	})
	var ccf *types.ConditionalCheckFailedException
	if err != nil && !errors.As(err, &ccf) {
		return err
	}
	return nil
}
