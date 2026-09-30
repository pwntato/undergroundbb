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

var (
	// ErrNotMember: the caller has no MEMBER# row in the group.
	ErrNotMember = errors.New("db: not a member of this group")
	// ErrLastAdmin: the caller is the group's only Admin and other members
	// remain. They must promote a successor first (issue #66).
	ErrLastAdmin = errors.New("db: last admin cannot leave while other members remain")
	// ErrLeaveConflict: the roster changed between the read and the write
	// (a role change, another admin leaving), or the caller's role no longer
	// matches whether a demotion was supplied. Nothing was written; retry.
	ErrLeaveConflict = errors.New("db: roster changed during leave, retry")
	// ErrDemotionRequired: the caller holds a role above member and leaves a
	// group that survives, so the leave must carry their signed demotion.
	ErrDemotionRequired = errors.New("db: an admin or ambassador must sign a demotion to leave")
	// ErrLeaveGrantKeyTaken: a GRANT# row already exists at the demotion's
	// sort key. Nothing was written; re-sign with a new one.
	ErrLeaveGrantKeyTaken = errors.New("db: demotion grant sort key taken")
	// ErrGroupSweepIncomplete accompanies groupDeleted=true when the group's
	// remaining rows could not all be removed. The group is already gone
	// (its META and the caller's membership are deleted); what is left is
	// unreachable garbage.
	ErrGroupSweepIncomplete = errors.New("db: group deleted but leftover rows remain")
	// ErrInviteCleanupIncomplete accompanies a successful leave when the
	// leaver's outstanding invites to the group could not all be removed.
	// They are unusable either way (the inviter is gone) and expire by TTL.
	ErrInviteCleanupIncomplete = errors.New("db: left the group but some of the caller's invites remain")
)

// memberRoles reads every MEMBER# row's user id and role in the group. Only
// SK and Role are projected: a roster of 1,000 members must not drag 1,000
// wrapped keys through this read.
func (c *Client) memberRoles(ctx context.Context, groupID string) (map[string]string, error) {
	roles := map[string]string{}
	var start map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:                aws.String(c.table),
			KeyConditionExpression:   aws.String("PK = :pk AND begins_with(SK, :sk)"),
			ProjectionExpression:     aws.String("SK, #role"),
			ExpressionAttributeNames: map[string]string{"#role": "Role"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
				":sk": &types.AttributeValueMemberS{Value: "MEMBER#"},
			},
			ExclusiveStartKey: start,
			ConsistentRead:    aws.Bool(true),
		})
		if err != nil {
			return nil, fmt.Errorf("db: read roster: %w", err)
		}
		var rows []models.Membership
		if err := attributevalue.UnmarshalListOfMaps(out.Items, &rows); err != nil {
			return nil, fmt.Errorf("db: unmarshal roster: %w", err)
		}
		for _, r := range rows {
			roles[strings.TrimPrefix(r.SK, "MEMBER#")] = r.Role
		}
		if out.LastEvaluatedKey == nil {
			return roles, nil
		}
		start = out.LastEvaluatedKey
	}
}

// otherAdmin returns some admin other than userID, or "" if there is none.
func otherAdmin(roles map[string]string, userID string) string {
	for id, r := range roles {
		if id != userID && r == models.RoleAdmin {
			return id
		}
	}
	return ""
}

func otherAdminExists(roles map[string]string, userID string) bool {
	return otherAdmin(roles, userID) != ""
}

func memberKey(groupID, userID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
		"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + userID},
	}
}

// LeaveDemotion is the signed self-demotion an admin or ambassador attaches
// to leaving: a role grant to "member" whose grantor and subject are both the
// leaver. It is appended in the same transaction that deletes their
// membership, so a departed admin's last grant no longer says admin and a
// later rejoin (baseline member) matches the chain.
type LeaveDemotion struct {
	GrantSortKey    string
	GrantorGrantRef string
	// HasStoredGrant says whether the caller's MEMBER# row records
	// GrantorGrantRef (Membership.GrantSortKey); when false it came from the
	// Group.RootGrantSortKey fallback and the row must still lack the field.
	HasStoredGrant   bool
	SigningPublicKey []byte
	Signature        []byte
}

// LeaveGroup removes userID from the group -- issues #66 and #55.
//
//   - Anyone but the last Admin: their MEMBER# row is deleted, and so are
//     their own outstanding invites to the group (see deleteOwnInvites).
//     Grants they signed or received stay; history is append-only. An Admin
//     or Ambassador also appends their signed demotion (LeaveDemotion) in
//     the same transaction; without one, ErrDemotionRequired.
//   - The last Admin while others remain: ErrLastAdmin, nothing written.
//   - The only member: the group is deleted (groupDeleted true) rather than
//     trapping the user in it.
//
// The last-admin rule is enforced by the transaction, not just the read: an
// admin's delete carries a ConditionCheck that another admin still holds the
// role, so two admins leaving at once cannot both succeed (one sees the
// other's row deleted or in conflict).
//
// Leaving does not rotate keys. A member of a Rotating group keeps the
// generation keys they already hold until #58 exists.
func (c *Client) LeaveGroup(ctx context.Context, groupID, userID string, demotion *LeaveDemotion) (groupDeleted bool, err error) {
	roles, err := c.memberRoles(ctx, groupID)
	if err != nil {
		return false, err
	}
	role, ok := roles[userID]
	if !ok {
		return false, ErrNotMember
	}
	if len(roles) == 1 {
		return c.deleteGroup(ctx, groupID, userID)
	}

	if role == models.RoleAdmin {
		if !otherAdminExists(roles, userID) {
			return false, ErrLastAdmin
		}
	}
	elevated := role != models.RoleMember
	if elevated && demotion == nil {
		return false, ErrDemotionRequired
	}
	if !elevated && demotion != nil {
		// The caller's role changed since the request was built.
		return false, ErrLeaveConflict
	}

	deleteCond := "#role = :role"
	deleteNames := map[string]string{"#role": "Role"}
	deleteValues := map[string]types.AttributeValue{
		":role": &types.AttributeValueMemberS{Value: role},
	}
	if elevated {
		// The demotion was signed against a specific current grant.
		deleteNames["#gsk"] = "GrantSortKey"
		if demotion.HasStoredGrant {
			deleteCond += " AND #gsk = :ref"
			deleteValues[":ref"] = &types.AttributeValueMemberS{Value: demotion.GrantorGrantRef}
		} else {
			deleteCond += " AND attribute_not_exists(#gsk)"
		}
	}
	const (
		deleteIndex = 0
		grantIndex  = 1 // only when elevated
	)
	items := []types.TransactWriteItem{{Delete: &types.Delete{
		TableName:                 aws.String(c.table),
		Key:                       memberKey(groupID, userID),
		ConditionExpression:       aws.String(deleteCond),
		ExpressionAttributeNames:  deleteNames,
		ExpressionAttributeValues: deleteValues,
	}}}
	adminCheckIndex := -1
	if elevated {
		grantItem, err := attributevalue.MarshalMap(models.RoleGrant{
			Record: models.Record{
				PK:   "GROUP#" + groupID,
				SK:   demotion.GrantSortKey,
				Type: "RoleGrant",
			},
			SubjectUserID:           userID,
			GrantedRole:             models.RoleMember,
			GrantorUserID:           userID,
			GrantorSigningPublicKey: demotion.SigningPublicKey,
			GrantorGrantRef:         demotion.GrantorGrantRef,
			Signature:               demotion.Signature,
		})
		if err != nil {
			return false, err
		}
		items = append(items, types.TransactWriteItem{Put: &types.Put{
			TableName:           aws.String(c.table),
			Item:                grantItem,
			ConditionExpression: aws.String("attribute_not_exists(PK)"),
		}})
	}
	if role == models.RoleAdmin {
		adminCheckIndex = len(items)
		items = append(items, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName:                aws.String(c.table),
			Key:                      memberKey(groupID, otherAdmin(roles, userID)),
			ConditionExpression:      aws.String("#role = :admin"),
			ExpressionAttributeNames: map[string]string{"#role": "Role"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin},
			},
		}})
	}
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		switch {
		case elevated && isConditionalCheckFailure(err, grantIndex):
			return false, ErrLeaveGrantKeyTaken
		case isConditionalCheckFailure(err, deleteIndex),
			adminCheckIndex >= 0 && isConditionalCheckFailure(err, adminCheckIndex),
			isTransactionConflict(err):
			return false, ErrLeaveConflict
		}
		return false, err
	}
	if err := c.deleteOwnInvites(ctx, groupID, userID); err != nil {
		return false, fmt.Errorf("%w: %v", ErrInviteCleanupIncomplete, err)
	}
	return false, nil
}

// deleteGroup removes the last member and the group's META in one
// transaction, then sweeps everything else under the partition. META going
// first is what stops a late invite completion (CompleteInvite conditions on
// META existing); the sweep also removes any membership that slipped in
// between the roster read and the transaction, since that member's group no
// longer exists.
func (c *Client) deleteGroup(ctx context.Context, groupID, userID string) (bool, error) {
	_, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Delete: &types.Delete{
				TableName:           aws.String(c.table),
				Key:                 memberKey(groupID, userID),
				ConditionExpression: aws.String("attribute_exists(PK)"),
			}},
			{Delete: &types.Delete{
				TableName: aws.String(c.table),
				Key: map[string]types.AttributeValue{
					"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
					"SK": &types.AttributeValueMemberS{Value: "META"},
				},
				ConditionExpression: aws.String("attribute_exists(PK)"),
			}},
		},
	})
	if err != nil {
		if isConditionalCheckFailure(err, 0) {
			return false, ErrNotMember
		}
		if isConditionalCheckFailure(err, 1) || isTransactionConflict(err) {
			return false, ErrLeaveConflict
		}
		return false, err
	}
	// The sweep is the more important cleanup (GROUP# rows have no TTL and
	// nothing will retry once META is gone), so it runs whatever the invite
	// cleanup did.
	inviteErr := c.deleteOwnInvites(ctx, groupID, userID)
	if err := c.sweepPartition(ctx, "GROUP#"+groupID); err != nil {
		return true, fmt.Errorf("%w: %v", ErrGroupSweepIncomplete, err)
	}
	if inviteErr != nil {
		return true, fmt.Errorf("%w: %v", ErrInviteCleanupIncomplete, inviteErr)
	}
	return true, nil
}

// sweepPartition deletes every item under pk, 25 at a time.
func (c *Client) sweepPartition(ctx context.Context, pk string) error {
	var start map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(c.table),
			KeyConditionExpression:    aws.String("PK = :pk"),
			ProjectionExpression:      aws.String("PK, SK"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":pk": &types.AttributeValueMemberS{Value: pk}},
			ExclusiveStartKey:         start,
			ConsistentRead:            aws.Bool(true),
		})
		if err != nil {
			return err
		}
		keys := make([]map[string]types.AttributeValue, 0, len(out.Items))
		for _, it := range out.Items {
			keys = append(keys, map[string]types.AttributeValue{"PK": it["PK"], "SK": it["SK"]})
		}
		if err := c.batchDelete(ctx, keys); err != nil {
			return err
		}
		if out.LastEvaluatedKey == nil {
			return nil
		}
		start = out.LastEvaluatedKey
	}
}

// batchDelete deletes the given keys, 25 per BatchWriteItem, retrying
// unprocessed items a bounded number of times.
func (c *Client) batchDelete(ctx context.Context, keys []map[string]types.AttributeValue) error {
	for i := 0; i < len(keys); i += 25 {
		end := min(i+25, len(keys))
		reqs := make([]types.WriteRequest, 0, end-i)
		for _, k := range keys[i:end] {
			reqs = append(reqs, types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: k}})
		}
		for attempt := 0; len(reqs) > 0; attempt++ {
			if attempt == 5 {
				return errors.New("unprocessed deletes after retries")
			}
			res, err := c.ddb.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
				RequestItems: map[string][]types.WriteRequest{c.table: reqs},
			})
			if err != nil {
				return err
			}
			reqs = res.UnprocessedItems[c.table]
		}
	}
	return nil
}

// deleteOwnInvites removes userID's outstanding invites to groupID: each
// USER#<user>/SENT#<iid> row and its INVITE#<iid>/META. Once the inviter is
// no longer a member those invites can never complete, and left in place they
// would still be acceptable (AcceptInvite checks neither the group nor the
// inviter's membership), so an invitee would accept and then wait forever.
// Only the leaver's own partition is read, so only their own invite ids can
// be named here. Other members' invites to the group are untouched.
func (c *Client) deleteOwnInvites(ctx context.Context, groupID, userID string) error {
	var keys []map[string]types.AttributeValue
	var start map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
			FilterExpression:       aws.String("GroupID = :g"),
			ProjectionExpression:   aws.String("PK, SK, InviteID"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "USER#" + userID},
				":sk": &types.AttributeValueMemberS{Value: "SENT#"},
				":g":  &types.AttributeValueMemberS{Value: groupID},
			},
			ExclusiveStartKey: start,
			ConsistentRead:    aws.Bool(true),
		})
		if err != nil {
			return err
		}
		for _, it := range out.Items {
			keys = append(keys, map[string]types.AttributeValue{"PK": it["PK"], "SK": it["SK"]})
			if iid, ok := it["InviteID"].(*types.AttributeValueMemberS); ok && iid.Value != "" {
				keys = append(keys, map[string]types.AttributeValue{
					"PK": &types.AttributeValueMemberS{Value: "INVITE#" + iid.Value},
					"SK": &types.AttributeValueMemberS{Value: "META"},
				})
			}
		}
		if out.LastEvaluatedKey == nil {
			break
		}
		start = out.LastEvaluatedKey
	}
	return c.batchDelete(ctx, keys)
}
