package db

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

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

// liveOtherAdmin returns an admin other than userID whose account is not
// deleted, or "" if there is none (#77). A deleted account's membership can
// outlive the tombstone for a moment, and nobody can sign in as it, so it
// cannot take over a group: counting it would let the last live admin leave
// with a group nobody can govern.
func (c *Client) liveOtherAdmin(ctx context.Context, roles map[string]string, userID string) (string, error) {
	var admins []string
	for id, r := range roles {
		if id != userID && r == models.RoleAdmin {
			admins = append(admins, id)
		}
	}
	sort.Strings(admins)
	for _, id := range admins {
		user, err := c.GetUserByID(ctx, id)
		// Only a tombstone is dead. PROFILE is never deleted, so a missing row
		// does not happen outside synthetic fixtures; treating it as live
		// matches the transaction's attribute_not_exists(DeletedAt) check.
		if errors.Is(err, ErrUserNotFound) {
			return id, nil
		}
		if err != nil {
			return "", err
		}
		if user.DeletedAt == "" {
			return id, nil
		}
	}
	return "", nil
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

// MaxLeaveHolders caps how many admins one leave re-wraps the new key to. A
// DynamoDB transaction holds at most 100 items and the rest of a leave needs a
// handful; anyone beyond the cap is re-wrapped by the ordinary rotation batch.
const MaxLeaveHolders = 50

// ErrRotationRequired is returned when a member of a Rotating group leaves
// while others remain and sends no rotation: the key they hold would otherwise
// keep working for them (#178).
var ErrRotationRequired = errors.New("db: leaving a Rotating group needs a key rotation")

// ErrRotationNotApplicable is returned when an Open group's leave carries a
// rotation: an Open group has no key to rotate.
var ErrRotationNotApplicable = errors.New("db: an Open group does not rotate keys on leave")

// ErrLeaveHolders is returned when the holders named by a leave's rotation are
// empty, too many, repeated, or include the leaver.
var ErrLeaveHolders = errors.New("db: a leave's rotation needs 1 to MaxLeaveHolders distinct admins other than the leaver")

// ErrLeaveHolderChanged is returned when a holder's entry is no longer an
// admin at the generation the new key was wrapped against (their role or key
// moved since the request was built). Nothing was written.
var ErrLeaveHolderChanged = errors.New("db: a key holder changed during leave, retry")

// LeaveHolder is one admin the leaver's new group key is wrapped to.
type LeaveHolder struct {
	UserID     string
	WrappedKey models.WrappedKey
}

// LeaveRotation is what a Rotating-group leave commits besides the delete
// (#178). The leaver mints the next generation exactly as a remover does, but
// they are departing, so the only copy of the minted key cannot stay with
// them: it goes to Holders, who find it waiting on their entry
// (Membership.PendingWrappedKey).
//
// It is deliberately NOT written over their Generation and WrappedGroupKey.
// The server can only check the shape of what a leaver sends, and a leaver who
// is leaving hostile could send bytes that open to nothing, wiping the only
// copy of the key every admin holds. A holder instead adopts the pending key
// (AdoptPendingKey) after opening Link with it and finding their own key
// inside; if no holder's pending key checks out, an admin replaces the
// rotation (RestartLeaveRotation).
type LeaveRotation struct {
	// CurrentGeneration is the leaver's own entry-point generation; the
	// rotation goes to CurrentGeneration+1 and every conditional hangs on it.
	CurrentGeneration int64
	// Link is generation CurrentGeneration's key under the new one, stored as
	// GENKEY#<CurrentGeneration>.
	Link models.WrappedBlob
	// StartSignature is the leaver's signature over crypto.RotationStartPayload
	// naming themselves as the removed member. Stored on the marker AND the
	// chain link, as for a removal.
	StartSignature []byte
	Holders        []LeaveHolder
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
// In a Rotating group (rotating true) leaving while others remain also starts
// a key rotation in the same transaction (rot, required): the marker, the
// GENKEY# link, and each holder's entry point at the new generation. Otherwise
// the leaver would keep a key that still works for everything posted until the
// next removal, and a server colluding with them could re-list them and have
// the next rotation wrap to them (#178). The only member leaving deletes the
// group and needs no rotation.
func (c *Client) LeaveGroup(ctx context.Context, groupID, userID string, demotion *LeaveDemotion, rot *LeaveRotation, rotating bool) (groupDeleted bool, err error) {
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
	switch {
	case rotating && rot == nil:
		return false, ErrRotationRequired
	case !rotating && rot != nil:
		return false, ErrRotationNotApplicable
	case rot != nil:
		if err := checkLeaveHolders(rot.Holders, userID); err != nil {
			return false, err
		}
	}

	successor := ""
	if role == models.RoleAdmin {
		successor, err = c.liveOtherAdmin(ctx, roles, userID)
		if err != nil {
			return false, err
		}
		if successor == "" {
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
	if rot != nil {
		// The new key was minted from the leaver's entry at this generation.
		deleteNames["#gen"] = "Generation"
		deleteCond += " AND #gen = :cur"
		deleteValues[":cur"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(rot.CurrentGeneration, 10)}
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
	profileCheckIndex := -1
	if role == models.RoleAdmin {
		// A transaction may touch an item once. When the successor is also a
		// key holder, the holder's update already conditions on them being an
		// admin, which is the same check, so the separate one is skipped.
		if !holdsKey(rot, successor) {
			adminCheckIndex = len(items)
			items = append(items, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
				TableName:                aws.String(c.table),
				Key:                      memberKey(groupID, successor),
				ConditionExpression:      aws.String("#role = :admin"),
				ExpressionAttributeNames: map[string]string{"#role": "Role"},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin},
				},
			}})
		}
		// ...and that admin's account must still be live when this commits, so
		// a deletion between the read above and here cannot strand the group.
		profileCheckIndex = len(items)
		items = append(items, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName: aws.String(c.table),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "USER#" + successor},
				"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
			},
			ConditionExpression: aws.String("attribute_not_exists(DeletedAt)"),
		}})
	}
	rotationIndex := -1
	if rot != nil {
		var rotItems []types.TransactWriteItem
		rotItems, err = c.leaveRotationItems(groupID, userID, rot)
		if err != nil {
			return false, err
		}
		rotationIndex = len(items)
		items = append(items, rotItems...)
	}
	// The leaver's admission record goes with their membership (#178). Hygiene
	// for an honest server only: a malicious one can keep it, and the signed
	// removal history (the rotation above) is what the verifier checks. Last,
	// so no condition-check index above shifts.
	items = append(items, admissionDelete(c.table, groupID, userID))
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		switch {
		case rot != nil && isConditionalCheckFailure(err, rotationIndex):
			return false, ErrRotationInProgress
		case rot != nil && isConditionalCheckFailure(err, rotationIndex+1):
			return false, ErrRotationStaleGeneration
		case rot != nil && anyConditionalCheckFailure(err, rotationIndex+2, len(rot.Holders)):
			return false, ErrLeaveHolderChanged
		case elevated && isConditionalCheckFailure(err, grantIndex):
			return false, ErrLeaveGrantKeyTaken
		case isConditionalCheckFailure(err, deleteIndex),
			adminCheckIndex >= 0 && isConditionalCheckFailure(err, adminCheckIndex),
			profileCheckIndex >= 0 && isConditionalCheckFailure(err, profileCheckIndex),
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

// checkLeaveHolders enforces the holder rules the transaction cannot express:
// a bounded, repeat-free set that does not include the leaver.
func checkLeaveHolders(holders []LeaveHolder, leaver string) error {
	if len(holders) == 0 || len(holders) > MaxLeaveHolders {
		return ErrLeaveHolders
	}
	seen := make(map[string]bool, len(holders))
	for _, h := range holders {
		if h.UserID == "" || h.UserID == leaver || seen[h.UserID] {
			return ErrLeaveHolders
		}
		seen[h.UserID] = true
	}
	return nil
}

// leaveRotationItems builds the rotation half of a leave, in the order
// LeaveGroup's error mapping expects: marker, link, then one update per
// holder. The marker's condition is the "one rotation at a time" rule; the
// link's is the guard that a generation is only ever minted once; a holder's
// is that they are still an admin at the generation the key was wrapped for.
// A holder's entry point is NOT moved: the wrap lands beside it as pending.
func (c *Client) leaveRotationItems(groupID, leaver string, rot *LeaveRotation) ([]types.TransactWriteItem, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	link, err := attributevalue.MarshalMap(models.GenerationKey{
		Record: models.Record{
			PK:        "GROUP#" + groupID,
			SK:        GenKeySortKey(rot.CurrentGeneration),
			Type:      "GenerationKey",
			CreatedAt: now,
		},
		Wrapped:        rot.Link,
		RemoverUserID:  leaver,
		RemovedUserID:  leaver,
		StartSignature: rot.StartSignature,
	})
	if err != nil {
		return nil, err
	}
	marker, err := attributevalue.MarshalMap(models.Rotation{
		Record: models.Record{
			PK:        "GROUP#" + groupID,
			SK:        RotationSortKey,
			Type:      "Rotation",
			CreatedAt: now,
		},
		Generation:     rot.CurrentGeneration + 1,
		StartedAt:      now,
		StartedBy:      leaver,
		RemovedUserID:  leaver,
		StartSignature: rot.StartSignature,
	})
	if err != nil {
		return nil, err
	}
	items := []types.TransactWriteItem{
		{Put: &types.Put{
			TableName:           aws.String(c.table),
			Item:                marker,
			ConditionExpression: aws.String("attribute_not_exists(PK)"),
		}},
		{Put: &types.Put{
			TableName:           aws.String(c.table),
			Item:                link,
			ConditionExpression: aws.String("attribute_not_exists(PK)"),
		}},
	}
	for _, h := range rot.Holders {
		wrapped, err := attributevalue.Marshal(h.WrappedKey)
		if err != nil {
			return nil, err
		}
		items = append(items, types.TransactWriteItem{Update: &types.Update{
			TableName:                aws.String(c.table),
			Key:                      memberKey(groupID, h.UserID),
			ConditionExpression:      aws.String("#role = :admin AND #gen = :cur"),
			UpdateExpression:         aws.String("SET #pending = :wrapped"),
			ExpressionAttributeNames: map[string]string{"#role": "Role", "#gen": "Generation", "#pending": "PendingWrappedKey"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":admin":   &types.AttributeValueMemberS{Value: models.RoleAdmin},
				":cur":     &types.AttributeValueMemberN{Value: strconv.FormatInt(rot.CurrentGeneration, 10)},
				":wrapped": wrapped,
			},
		}})
	}
	return items, nil
}

// anyConditionalCheckFailure reports whether the transaction was cancelled by
// a failed condition on any of n consecutive items starting at first.
func anyConditionalCheckFailure(err error, first, n int) bool {
	for i := first; i < first+n; i++ {
		if isConditionalCheckFailure(err, i) {
			return true
		}
	}
	return false
}

// holdsKey reports whether userID is one of rot's key holders.
func holdsKey(rot *LeaveRotation, userID string) bool {
	if rot == nil {
		return false
	}
	for _, h := range rot.Holders {
		if h.UserID == userID {
			return true
		}
	}
	return false
}
