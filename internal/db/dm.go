package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/pwntato/undergroundbb/internal/models"
)

// Direct messages (#73, docs/DESIGN.md, "Direct messages"). A DM is an ordinary group row set
// (META with GroupType "dm", the sender's MEMBER# and root GRANT#) plus four DM-only rows, all
// written with the group in one transaction:
//
//	DMPAIR#<lo>#<hi> / PAIR      one per unordered pair of users (models.DMPair)
//	GROUP#<gid> / DMREQ#<recip>  the recipient's key wrap and admission, until they open it
//	  (GSI1 USER#<recip> / DMREQ#<gid> is how the recipient finds it)
//	USER#<sender> / DMOUT#<gid>  the sender's own pointer, counted against the pending cap
//
// The recipient's MEMBER# row is written only when they accept.

const (
	// DMDeclineCoolOff is how long a declined DM keeps the sender out: the same 7 days as a declined
	// join request, and for the same reason (a decline is not a ban).
	DMDeclineCoolOff = 7 * 24 * time.Hour
	// MaxPendingDMsPerSender bounds how many unanswered DMs one account may have out at once.
	MaxPendingDMsPerSender = 20

	dmRequestPrefix = "DMREQ#"
	dmOutPrefix     = "DMOUT#"
)

var (
	// ErrDMExists means the pair already has a DM (pending or active). Carries the group id in
	// DMExistsError.
	ErrDMExists = errors.New("db: a direct message between these two users already exists")
	// ErrDMCoolingOff means the recipient declined this sender's DM and the cool-off has not ended.
	ErrDMCoolingOff = errors.New("db: the recipient declined; the cool-off has not ended")
	// ErrDMRecipientGone means the recipient's account was deleted.
	ErrDMRecipientGone = errors.New("db: the recipient no longer exists")
	// ErrDMNotFound means there is no pending DM slot to act on (never existed, answered, withdrawn,
	// or a different request id than the caller expected).
	ErrDMNotFound = errors.New("db: no such pending direct message")
	// ErrDMTooManyPending means the sender is at MaxPendingDMsPerSender.
	ErrDMTooManyPending = errors.New("db: too many direct messages awaiting an answer")
)

// DMExistsError wraps ErrDMExists with the id of the existing group.
type DMExistsError struct{ GroupID string }

func (e *DMExistsError) Error() string { return ErrDMExists.Error() }
func (e *DMExistsError) Unwrap() error { return ErrDMExists }

// DMCoolingOffError wraps ErrDMCoolingOff with the UTC day it ends.
type DMCoolingOffError struct{ Until time.Time }

func (e *DMCoolingOffError) Error() string { return ErrDMCoolingOff.Error() }
func (e *DMCoolingOffError) Unwrap() error { return ErrDMCoolingOff }

// DMPairPK is the pair marker's partition key: the two ids in byte order, so both directions
// name the same row.
func DMPairPK(a, b string) string {
	if b < a {
		a, b = b, a
	}
	return "DMPAIR#" + a + "#" + b
}

func dmPairKey(pairPK string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: pairPK},
		"SK": &types.AttributeValueMemberS{Value: "PAIR"},
	}
}

func dmRequestKey(groupID, recipientID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
		"SK": &types.AttributeValueMemberS{Value: dmRequestPrefix + recipientID},
	}
}

func dmOutKey(senderID, groupID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "USER#" + senderID},
		"SK": &types.AttributeValueMemberS{Value: dmOutPrefix + groupID},
	}
}

// CreateDMInput is the DM part of CreateGroupInput. The recipient's keys and epoch are the
// handler's read of their PROFILE; the epoch is checked again in the transaction.
type CreateDMInput struct {
	RecipientUserID   string
	RequestID         string
	RecipientEd25519  []byte
	RecipientX25519   []byte
	RecipientKeyEpoch uint64
	WrappedGroupKey   models.WrappedKey
	// AdmissionDay and AdmissionSig are the sender's admission of the recipient. Its grant ref is
	// the sender's root grant (CreateGroupInput.RootGrantSortKey) and its generation 0.
	AdmissionDay string
	AdmissionSig []byte
}

// dmCreateItems builds the transaction items CreateGroup appends for a DM, in the order
// dmCreateFailure expects (the first is at index dmPairIndex).
func (c *Client) dmCreateItems(in CreateGroupInput) ([]types.TransactWriteItem, error) {
	dm := in.DM
	pairPK := DMPairPK(in.CreatorUserID, dm.RecipientUserID)
	pair := models.DMPair{
		Record:       models.Record{PK: pairPK, SK: "PAIR", Type: "DMPair"},
		GroupID:      in.GroupID,
		SenderUserID: in.CreatorUserID,
		Status:       models.DMPairPending,
	}
	pairItem, err := attributevalue.MarshalMap(pair)
	if err != nil {
		return nil, err
	}
	req := models.DMRequest{
		Record: models.Record{
			PK: "GROUP#" + in.GroupID, SK: dmRequestPrefix + dm.RecipientUserID, Type: "DMRequest",
			GSI1PK: "USER#" + dm.RecipientUserID, GSI1SK: dmRequestPrefix + in.GroupID,
		},
		GroupID:           in.GroupID,
		SenderUserID:      in.CreatorUserID,
		RecipientUserID:   dm.RecipientUserID,
		RequestID:         dm.RequestID,
		RecipientEd25519:  dm.RecipientEd25519,
		RecipientX25519:   dm.RecipientX25519,
		RecipientKeyEpoch: dm.RecipientKeyEpoch,
		WrappedGroupKey:   dm.WrappedGroupKey,
		AdmissionDay:      dm.AdmissionDay,
		AdmissionGrantRef: in.RootGrantSortKey,
		AdmissionSig:      dm.AdmissionSig,
	}
	reqItem, err := attributevalue.MarshalMap(req)
	if err != nil {
		return nil, err
	}
	out := map[string]types.AttributeValue{
		"PK":      &types.AttributeValueMemberS{Value: "USER#" + in.CreatorUserID},
		"SK":      &types.AttributeValueMemberS{Value: dmOutPrefix + in.GroupID},
		"Type":    &types.AttributeValueMemberS{Value: "DMOut"},
		"GroupID": &types.AttributeValueMemberS{Value: in.GroupID},
	}
	return []types.TransactWriteItem{
		{Put: &types.Put{
			TableName: aws.String(c.table),
			Item:      pairItem,
			// A marker that is absent, or declined with its cool-off over, or declined BY the creator
			// (the person who refused may start the conversation themselves), is replaced.
			ConditionExpression: aws.String("attribute_not_exists(PK) OR (#st = :declined AND (#ttl < :now OR DeclinedBy = :me))"),
			ExpressionAttributeNames: map[string]string{
				"#st": "Status", "#ttl": "TTL",
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":declined": &types.AttributeValueMemberS{Value: models.DMPairDeclined},
				":now":      unixAttr(time.Now()),
				":me":       &types.AttributeValueMemberS{Value: in.CreatorUserID},
			},
		}},
		c.keyEpochCheck(dm.RecipientUserID, dm.RecipientKeyEpoch),
		{Put: &types.Put{TableName: aws.String(c.table), Item: reqItem}},
		{Put: &types.Put{TableName: aws.String(c.table), Item: out}},
	}, nil
}

// dmCreateFailure turns a failed CreateGroup transaction into a DM error when the failing item
// was one of the DM's. It returns nil when the failure is not the DM's, so the caller's own
// handling continues.
func (c *Client) dmCreateFailure(ctx context.Context, in CreateGroupInput, err error, pairIndex int) error {
	if isConditionalCheckFailure(err, pairIndex) {
		out, getErr := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
			TableName: aws.String(c.table), Key: dmPairKey(DMPairPK(in.CreatorUserID, in.DM.RecipientUserID)), ConsistentRead: aws.Bool(true),
		})
		if getErr != nil {
			return getErr
		}
		var pair models.DMPair
		if out.Item == nil || attributevalue.UnmarshalMap(out.Item, &pair) != nil {
			return ErrDMCoolingOff // raced with a delete: have the caller retry
		}
		if pair.Status == models.DMPairDeclined {
			return &DMCoolingOffError{Until: time.Unix(pair.TTL, 0).UTC()}
		}
		return &DMExistsError{GroupID: pair.GroupID}
	}
	if isConditionalCheckFailure(err, pairIndex+1) {
		deleted, whyErr := c.whyProfileCheckFailed(ctx, in.DM.RecipientUserID)
		if whyErr != nil {
			return whyErr
		}
		if deleted {
			return ErrDMRecipientGone
		}
		return ErrWrapEpochStale
	}
	return nil
}

// CountPendingDMs counts the sender's unanswered DMs, stopping once it passes the cap.
func (c *Client) CountPendingDMs(ctx context.Context, senderID string) (int, error) {
	out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :p)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "USER#" + senderID},
			":p":  &types.AttributeValueMemberS{Value: dmOutPrefix},
		},
		Select:         types.SelectCount,
		Limit:          aws.Int32(MaxPendingDMsPerSender + 1),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return 0, fmt.Errorf("db: count pending DMs: %w", err)
	}
	return int(out.Count), nil
}

// GetDMRequest returns the pending slot for (group, recipient), or nil.
func (c *Client) GetDMRequest(ctx context.Context, groupID, recipientID string) (*models.DMRequest, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table), Key: dmRequestKey(groupID, recipientID), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("db: get DM request: %w", err)
	}
	if out.Item == nil {
		return nil, nil
	}
	var r models.DMRequest
	if err := attributevalue.UnmarshalMap(out.Item, &r); err != nil {
		return nil, fmt.Errorf("db: unmarshal DM request: %w", err)
	}
	return &r, nil
}

// ListIncomingDMs returns the recipient's pending DMs (at most limit; the sender cap and the
// decline remedy bound the list, so it has no cursor).
func (c *Client) ListIncomingDMs(ctx context.Context, recipientID string, limit int32) ([]models.DMRequest, error) {
	out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		IndexName:              aws.String("GSI1"),
		KeyConditionExpression: aws.String("GSI1PK = :pk AND begins_with(GSI1SK, :p)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "USER#" + recipientID},
			":p":  &types.AttributeValueMemberS{Value: dmRequestPrefix},
		},
		Limit: aws.Int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("db: list incoming DMs: %w", err)
	}
	reqs := make([]models.DMRequest, 0, len(out.Items))
	for _, it := range out.Items {
		var r models.DMRequest
		if err := attributevalue.UnmarshalMap(it, &r); err != nil {
			return nil, fmt.Errorf("db: unmarshal DM request: %w", err)
		}
		reqs = append(reqs, r)
	}
	return reqs, nil
}

// AcceptDM is the recipient opening the conversation: their MEMBER# row (and the sender's
// signed admission of them) is written for the first time, and the slot, the sender's pointer
// and the pending marker are retired, in one transaction. req is the slot the caller read and
// verified.
func (c *Client) AcceptDM(ctx context.Context, req *models.DMRequest, pairPK string) error {
	now := time.Now()
	membership := models.Membership{
		Record: models.Record{
			PK: "GROUP#" + req.GroupID, SK: "MEMBER#" + req.RecipientUserID, Type: "Membership",
			CreatedAt: utcDay(now),
			GSI1PK:    "USER#" + req.RecipientUserID, GSI1SK: "GROUP#" + req.GroupID,
		},
		Role:            models.RoleMember,
		Generation:      0,
		WrappedGroupKey: req.WrappedGroupKey,
		WrapEpoch:       req.RecipientKeyEpoch,
	}
	membershipItem, err := attributevalue.MarshalMap(membership)
	if err != nil {
		return err
	}
	admission := models.Admission{
		Record:                  models.Record{PK: "GROUP#" + req.GroupID, SK: "ADMISSION#" + req.RecipientUserID, Type: "Admission"},
		InviteeUserID:           req.RecipientUserID,
		InviterUserID:           req.SenderUserID,
		InviteID:                req.RequestID,
		InviteeEd25519PublicKey: req.RecipientEd25519,
		InviteeX25519PublicKey:  req.RecipientX25519,
		InviterGrantRef:         req.AdmissionGrantRef,
		Day:                     req.AdmissionDay,
		Generation:              0,
		Signature:               req.AdmissionSig,
	}
	admissionItem, err := attributevalue.MarshalMap(admission)
	if err != nil {
		return err
	}
	const (
		membershipIndex = 0
		slotIndex       = 1
		epochIndex      = 3
		groupIndex      = 4
		pairIndex       = 6
	)
	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(c.table), Item: membershipItem, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Delete: &types.Delete{
			TableName: aws.String(c.table), Key: dmRequestKey(req.GroupID, req.RecipientUserID),
			ConditionExpression:       aws.String("RequestID = :rid"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":rid": &types.AttributeValueMemberS{Value: req.RequestID}},
		}},
		{Put: &types.Put{TableName: aws.String(c.table), Item: admissionItem}},
		c.keyEpochCheck(req.RecipientUserID, req.RecipientKeyEpoch),
		{ConditionCheck: &types.ConditionCheck{
			TableName: aws.String(c.table),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "GROUP#" + req.GroupID},
				"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + req.SenderUserID},
			},
			ConditionExpression: aws.String("attribute_exists(PK)"),
		}},
		{Delete: &types.Delete{TableName: aws.String(c.table), Key: dmOutKey(req.SenderUserID, req.GroupID)}},
		{Update: &types.Update{
			TableName: aws.String(c.table), Key: dmPairKey(pairPK),
			UpdateExpression:         aws.String("SET #st = :active"),
			ConditionExpression:      aws.String("GroupID = :gid AND #st = :pending"),
			ExpressionAttributeNames: map[string]string{"#st": "Status"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":active":  &types.AttributeValueMemberS{Value: models.DMPairActive},
				":pending": &types.AttributeValueMemberS{Value: models.DMPairPending},
				":gid":     &types.AttributeValueMemberS{Value: req.GroupID},
			},
		}},
	}})
	if err == nil {
		return nil
	}
	switch {
	case isConditionalCheckFailure(err, epochIndex):
		deleted, whyErr := c.whyProfileCheckFailed(ctx, req.RecipientUserID)
		if whyErr != nil {
			return whyErr
		}
		if deleted {
			return ErrInviteeDeleted
		}
		return ErrWrapEpochStale
	case isConditionalCheckFailure(err, slotIndex), isConditionalCheckFailure(err, groupIndex), isConditionalCheckFailure(err, pairIndex):
		return ErrDMNotFound
	case isConditionalCheckFailure(err, membershipIndex):
		return ErrAlreadyMember
	}
	return err
}

// DeclineDM is the recipient refusing: the slot, the sender's pointer and the pending marker go
// (the marker becomes "declined" for DMDeclineCoolOff, keeping the sender out), then the group
// the sender made is deleted.
func (c *Client) DeclineDM(ctx context.Context, req *models.DMRequest, pairPK string) error {
	until := time.Now().Add(DMDeclineCoolOff)
	_, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Delete: &types.Delete{
			TableName: aws.String(c.table), Key: dmRequestKey(req.GroupID, req.RecipientUserID),
			ConditionExpression:       aws.String("RequestID = :rid"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":rid": &types.AttributeValueMemberS{Value: req.RequestID}},
		}},
		{Delete: &types.Delete{TableName: aws.String(c.table), Key: dmOutKey(req.SenderUserID, req.GroupID)}},
		{Update: &types.Update{
			TableName: aws.String(c.table), Key: dmPairKey(pairPK),
			UpdateExpression:         aws.String("SET #st = :declined, DeclinedBy = :me, #ttl = :until"),
			ConditionExpression:      aws.String("GroupID = :gid AND #st = :pending"),
			ExpressionAttributeNames: map[string]string{"#st": "Status", "#ttl": "TTL"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":declined": &types.AttributeValueMemberS{Value: models.DMPairDeclined},
				":pending":  &types.AttributeValueMemberS{Value: models.DMPairPending},
				":me":       &types.AttributeValueMemberS{Value: req.RecipientUserID},
				":until":    unixAttr(until),
				":gid":      &types.AttributeValueMemberS{Value: req.GroupID},
			},
		}},
	}})
	if err != nil {
		if isConditionalCheckFailure(err, 0) || isConditionalCheckFailure(err, 2) {
			return ErrDMNotFound
		}
		return err
	}
	if _, err := c.deleteGroup(ctx, req.GroupID, req.SenderUserID); err != nil && !errors.Is(err, ErrNotMember) {
		return err
	}
	return nil
}

// leaveDM is LeaveGroup for a DM. A DM has no roles and no re-key, so leaving is just removing
// your own row. The last person out deletes the group, along with the pair marker, a pending
// slot and the sender's pointer; the first person out of an active DM frees the pair marker so
// a new DM can be started, and leaves the other person a read-only conversation.
func (c *Client) leaveDM(ctx context.Context, g *models.Group, groupID, userID string) (bool, error) {
	roles, err := c.memberRoles(ctx, groupID)
	if err != nil {
		return false, err
	}
	if _, ok := roles[userID]; !ok {
		return false, ErrNotMember
	}
	if len(roles) == 1 {
		// Best effort first (both are keyed off the group, and a stale one is harmless): the
		// marker only if it still names this group.
		c.deleteDMMarkers(ctx, g, groupID)
		return c.deleteGroup(ctx, groupID, userID)
	}
	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Delete: &types.Delete{TableName: aws.String(c.table), Key: memberKey(groupID, userID), ConditionExpression: aws.String("attribute_exists(PK)")}},
		admissionDelete(c.table, groupID, userID),
	}})
	if err != nil {
		if isConditionalCheckFailure(err, 0) {
			return false, ErrNotMember
		}
		if isTransactionConflict(err) {
			return false, ErrLeaveConflict
		}
		return false, err
	}
	c.deleteDMMarkers(ctx, g, groupID)
	return false, nil
}

// deleteDMMarkers removes the pair marker if it still names groupID, and the sender's pointer.
// Failures are ignored: a leftover marker for a group that no longer exists is refused at the
// next create as "exists" with a dead id, which the handler detects and clears.
func (c *Client) deleteDMMarkers(ctx context.Context, g *models.Group, groupID string) {
	if g.DMPairPK != "" {
		_, _ = c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: aws.String(c.table), Key: dmPairKey(g.DMPairPK),
			ConditionExpression:       aws.String("GroupID = :gid AND #st <> :declined"),
			ExpressionAttributeNames:  map[string]string{"#st": "Status"},
			ExpressionAttributeValues: map[string]types.AttributeValue{":gid": &types.AttributeValueMemberS{Value: groupID}, ":declined": &types.AttributeValueMemberS{Value: models.DMPairDeclined}},
		})
	}
	_, _ = c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(c.table), Key: dmOutKey(g.CreatorUserID, groupID)})
}

// DMMemberCount is the number of members a DM has now (1 until the recipient accepts, and again
// once either has left). A DM with fewer than two members is read-only.
func (c *Client) DMMemberCount(ctx context.Context, groupID string) (int, error) {
	roles, err := c.memberRoles(ctx, groupID)
	if err != nil {
		return 0, err
	}
	return len(roles), nil
}

// DMWritable reports whether new content may be added to a DM: it needs two members, or the
// recipient's pending slot (the sender may write before the recipient has opened it). A DM
// whose other person has left is read-only.
func (c *Client) DMWritable(ctx context.Context, groupID string) (bool, error) {
	n, err := c.DMMemberCount(ctx, groupID)
	if err != nil {
		return false, err
	}
	if n >= 2 {
		return true, nil
	}
	out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :p)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			":p":  &types.AttributeValueMemberS{Value: dmRequestPrefix},
		},
		Select:         types.SelectCount,
		Limit:          aws.Int32(1),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return false, fmt.Errorf("db: check DM slot: %w", err)
	}
	return out.Count > 0, nil
}

// ClearStaleDMPair removes a pair marker whose group no longer exists, so a failed cleanup
// cannot block the pair for ever. It only deletes a marker that still names groupID.
func (c *Client) ClearStaleDMPair(ctx context.Context, pairPK, groupID string) error {
	_, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(c.table), Key: dmPairKey(pairPK),
		ConditionExpression:       aws.String("GroupID = :gid"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":gid": &types.AttributeValueMemberS{Value: groupID}},
	})
	var ccf *types.ConditionalCheckFailedException
	if err != nil && !errors.As(err, &ccf) {
		return err
	}
	return nil
}
