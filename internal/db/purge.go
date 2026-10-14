package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// DefaultPurgeMaxAccounts bounds how many test accounts one run examines.
const DefaultPurgeMaxAccounts = 100

// PurgeOptions tunes PurgeTestAccounts.
type PurgeOptions struct {
	// MinAge is how old an account must be before it is eligible, so a test
	// still running is never deleted under itself.
	MinAge time.Duration
	// MaxAccounts caps accounts examined per run (skipped and waiting ones
	// count); zero means DefaultPurgeMaxAccounts.
	MaxAccounts int
	// DryRun plans and reports but deletes nothing.
	DryRun bool
	// Now is the clock; zero means time.Now().
	Now time.Time

	// onlyUsers restricts a run to these ids. Tests share one DynamoDB Local
	// with other packages' test accounts, so they must not purge each other.
	onlyUsers map[string]bool
	// beforeMemberRow, if set, runs after a group's other rows are deleted and
	// before the account's own MEMBER# row is. Tests use it to stop a run there.
	beforeMemberRow func(groupID string) error
}

// PurgeSkip records an account the purge examined and left alone.
type PurgeSkip struct {
	UserID string `json:"userId"`
	Reason string `json:"reason"`
}

// PurgeReport says what a run did, or with DryRun what it would do.
type PurgeReport struct {
	DryRun bool `json:"dryRun"`
	// Examined counts accounts looked at. Purged are finished: everything they
	// owned is gone except a tombstone PROFILE. Waiting are tombstoned but still
	// members of a group with a real member (KeptGroups counts those groups,
	// which are left alone), so they are looked at again every run until that
	// group goes. Groups counts test-only groups deleted whole and Rows every
	// item deleted. All counts are what would happen under DryRun, with a group
	// or row shared by two accounts counted once, as a real run does.
	Examined   int         `json:"examined"`
	Purged     int         `json:"purged"`
	Waiting    int         `json:"waiting"`
	Groups     int         `json:"groups"`
	KeptGroups int         `json:"keptGroups"`
	Rows       int         `json:"rows"`
	Skipped    []PurgeSkip `json:"skipped,omitempty"`
}

// PurgeTestAccounts deletes automated-test accounts and everything they own.
//
// It deletes by removing items, never through the leave protocol: leaving
// needs the user's own signature and the server holds no user keys. So a group
// is deleted whole only when every member is a test account. A group with any
// real member is never touched: the test account stays a member of it. Either
// way PROFILE is never deleted, only tombstoned as DeleteAccount does: the
// grant chain verifies a grantor's signatures with the key GET /api/users/{id}
// serves from PROFILE, so a grant the account signed in a real group, even one
// it has since left, stops verifying if PROFILE goes; and user ids are
// client-chosen, so a deleted PROFILE would let anyone re-register the id and
// inherit its history (docs/DESIGN.md, the AAD table). A tombstone is one small
// item per test account. A test account left as a member of a real group is the
// documented "member whose profile is deleted" state, which an admin clears
// with the ordinary removal flow (docs/DESIGN.md, "Test accounts are a
// reserved, opt-in namespace").
//
// An account counts as a test account only when its PROFILE carries
// TestAccount (written solely by a registration that also used the reserved
// username prefix) and, while it is still live, its username has that prefix.
// A deleted account's username is gone, so the flag alone identifies it.
// Candidates come from the GSI1 "TESTACCOUNT" partition, so nothing scans.
//
// A tombstoned account keeps its index keys while it is still a member of a
// group with real members, so every run looks at it again and deletes that
// group once the last real member has left. Once nothing is left to wait on,
// the keys are removed and it is never examined again. Waiting accounts count
// against MaxAccounts; a great many of them would crowd out new work.
//
// Order: for each test-only group, its other rows first and the account's own
// MEMBER# row last, because that row is how the next run finds the group; then
// the user's other rows and invites, then the username claim, then PROFILE.
// PROFILE is what the candidate query finds, so a run that dies partway is
// finished by the next.
//
// Group membership is read from GSI1, which is eventually consistent, so a
// membership written moments before the run could be missed. MinAge makes that
// window irrelevant in practice; it is not a guarantee.
func (c *Client) PurgeTestAccounts(ctx context.Context, opts PurgeOptions) (PurgeReport, error) {
	report := PurgeReport{DryRun: opts.DryRun}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	limit := opts.MaxAccounts
	if limit <= 0 {
		limit = DefaultPurgeMaxAccounts
	}
	cutoff := now.UTC().Add(-opts.MinAge).Format(time.RFC3339)

	candidates, err := c.testAccountCandidates(ctx, cutoff, limit, opts.onlyUsers)
	if err != nil {
		return report, fmt.Errorf("db: list test accounts: %w", err)
	}

	isTest := map[string]bool{}
	plannedGroups := map[string]bool{}
	plannedRows := map[string]bool{}
	for _, uid := range candidates {
		report.Examined++
		plan, skip, err := c.planPurge(ctx, uid, isTest)
		if err != nil {
			return report, fmt.Errorf("db: plan purge of %s: %w", uid, err)
		}
		if skip != "" {
			report.Skipped = append(report.Skipped, PurgeSkip{UserID: uid, Reason: skip})
			continue
		}
		// In a dry run nothing is deleted, so a group or row two accounts share
		// would be planned twice; a real run's second account no longer sees it.
		var groups []groupPlan
		for _, g := range plan.groups {
			if !plannedGroups[g.id] {
				plannedGroups[g.id] = true
				groups = append(groups, g)
				report.Groups++
				report.Rows += len(g.rows) + 1 // + the member row
				for _, k := range g.rows {
					plannedRows[keyID(k)] = true
				}
				plannedRows[keyID(g.memberKey)] = true
			}
		}
		plan.groups = groups
		var keys []map[string]types.AttributeValue
		for _, k := range plan.keys {
			if !plannedRows[keyID(k)] {
				plannedRows[keyID(k)] = true
				keys = append(keys, k)
			}
		}
		plan.keys = keys
		report.Rows += len(keys)
		if plan.claimLower != "" {
			report.Rows++
		}
		report.KeptGroups += len(plan.keptGroups)
		if len(plan.keptGroups) > 0 {
			report.Waiting++
		} else {
			report.Purged++
		}
		if !opts.DryRun {
			if err := c.executePurge(ctx, plan, now, opts); err != nil {
				return report, fmt.Errorf("db: purge %s: %w", uid, err)
			}
		}
	}
	return report, nil
}

func keyID(k map[string]types.AttributeValue) string {
	pk, _ := k["PK"].(*types.AttributeValueMemberS)
	sk, _ := k["SK"].(*types.AttributeValueMemberS)
	if pk == nil || sk == nil {
		return ""
	}
	return pk.Value + "\x00" + sk.Value
}

// groupPlan is one test-only group: every row but the account's own MEMBER#
// row, which is deleted last.
type groupPlan struct {
	id        string
	rows      []map[string]types.AttributeValue
	memberKey map[string]types.AttributeValue
}

type purgePlan struct {
	userID     string
	claimLower string
	groups     []groupPlan                       // test-only groups, deleted whole
	keptGroups map[string]bool                   // groups with a real member, left alone
	wasDeleted bool                              // PROFILE is already a tombstone
	keys       []map[string]types.AttributeValue // the user's other rows, never PROFILE
}

func (c *Client) testAccountCandidates(ctx context.Context, cutoff string, limit int, only map[string]bool) ([]string, error) {
	var ids []string
	var start map[string]types.AttributeValue
	for len(ids) < limit {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			IndexName:              aws.String("GSI1"),
			KeyConditionExpression: aws.String("GSI1PK = :pk AND GSI1SK < :cutoff"),
			ProjectionExpression:   aws.String("PK"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk":     &types.AttributeValueMemberS{Value: models.TestAccountGSI1PK},
				":cutoff": &types.AttributeValueMemberS{Value: cutoff},
			},
			ExclusiveStartKey: start,
		})
		if err != nil {
			return nil, err
		}
		for _, it := range out.Items {
			pk, _ := it["PK"].(*types.AttributeValueMemberS)
			if pk == nil || !strings.HasPrefix(pk.Value, "USER#") {
				continue
			}
			uid := strings.TrimPrefix(pk.Value, "USER#")
			if only != nil && !only[uid] {
				continue
			}
			if len(ids) < limit {
				ids = append(ids, uid)
			}
		}
		if out.LastEvaluatedKey == nil {
			break
		}
		start = out.LastEvaluatedKey
	}
	return ids, nil
}

// planPurge reads everything that would be deleted for userID without
// deleting any of it. A non-empty skip means leave the account alone.
func (c *Client) planPurge(ctx context.Context, userID string, isTest map[string]bool) (plan purgePlan, skip string, err error) {
	plan.userID = userID
	if !idgen.ValidUUID(userID) {
		return plan, "not a valid user id", nil
	}
	user, err := c.getProfileConsistent(ctx, userID)
	if err != nil {
		return plan, "", err
	}
	if user == nil || !isTestProfile(user) {
		return plan, "profile is not a test account", nil
	}
	isTest[userID] = true
	plan.wasDeleted = user.DeletedAt != ""
	plan.keptGroups = map[string]bool{}
	if user.DeletedAt == "" {
		plan.claimLower = strings.ToLower(user.Username)
	}

	memberships, err := c.queryMembershipsByUser(ctx, userID)
	if err != nil {
		return plan, "", err
	}
	seen := map[string]bool{}
	for _, m := range memberships {
		gid := groupIDFromMembership(m)
		if gid == "" || seen[gid] {
			continue
		}
		seen[gid] = true
		members, err := c.groupMemberIDs(ctx, gid)
		if err != nil {
			return plan, "", err
		}
		mixed := false
		for _, other := range members {
			ok, known := isTest[other]
			if !known {
				p, err := c.getProfileConsistent(ctx, other)
				if err != nil {
					return plan, "", err
				}
				ok = p != nil && isTestProfile(p)
				isTest[other] = ok
			}
			if !ok {
				mixed = true
				break
			}
		}
		if mixed {
			plan.keptGroups[gid] = true
			continue
		}
		keys, err := c.partitionKeys(ctx, "GROUP#"+gid)
		if err != nil {
			return plan, "", err
		}
		own := "MEMBER#" + userID
		g := groupPlan{id: gid, memberKey: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + gid},
			"SK": &types.AttributeValueMemberS{Value: own},
		}}
		for _, k := range keys {
			if sk, _ := k["SK"].(*types.AttributeValueMemberS); sk != nil && sk.Value == own {
				continue
			}
			g.rows = append(g.rows, k)
		}
		plan.groups = append(plan.groups, g)
	}

	userKeys, err := c.partitionKeys(ctx, "USER#"+userID)
	if err != nil {
		return plan, "", err
	}
	for _, k := range userKeys {
		sk, _ := k["SK"].(*types.AttributeValueMemberS)
		if sk == nil || sk.Value == "PROFILE" {
			continue
		}
		plan.keys = append(plan.keys, k)
		if strings.HasPrefix(sk.Value, "SENT#") {
			plan.keys = append(plan.keys, map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "INVITE#" + strings.TrimPrefix(sk.Value, "SENT#")},
				"SK": &types.AttributeValueMemberS{Value: "META"},
			})
		}
	}
	// Rows other partitions hold about this user: invites addressed to them and
	// join requests they made. Memberships come back too and are skipped below:
	// those in kept groups must stay, and those in planned groups are deleted by
	// the group plan, last.
	var start map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			IndexName:              aws.String("GSI1"),
			KeyConditionExpression: aws.String("GSI1PK = :pk"),
			ProjectionExpression:   aws.String("PK, SK"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "USER#" + userID},
			},
			ExclusiveStartKey: start,
		})
		if err != nil {
			return plan, "", err
		}
		for _, it := range out.Items {
			pk, _ := it["PK"].(*types.AttributeValueMemberS)
			sk, _ := it["SK"].(*types.AttributeValueMemberS)
			if pk == nil || sk == nil {
				continue
			}
			if strings.HasPrefix(sk.Value, "MEMBER#") {
				// Every membership is either in a kept group (must stay) or a
				// planned group (its member row is deleted last, by groupPlan).
				continue
			}
			plan.keys = append(plan.keys, map[string]types.AttributeValue{"PK": it["PK"], "SK": it["SK"]})
		}
		if out.LastEvaluatedKey == nil {
			break
		}
		start = out.LastEvaluatedKey
	}
	plan.keys = dedupeKeys(plan.keys)
	return plan, "", nil
}

func (c *Client) executePurge(ctx context.Context, plan purgePlan, now time.Time, opts PurgeOptions) error {
	for _, g := range plan.groups {
		if err := c.batchDelete(ctx, dedupeKeys(g.rows)); err != nil {
			return err
		}
		if opts.beforeMemberRow != nil {
			if err := opts.beforeMemberRow(g.id); err != nil {
				return err
			}
		}
		if _, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(c.table), Key: g.memberKey}); err != nil {
			return err
		}
	}
	if err := c.batchDelete(ctx, plan.keys); err != nil {
		return err
	}
	if plan.claimLower != "" {
		_, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: aws.String(c.table),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "USERNAME#" + plan.claimLower},
				"SK": &types.AttributeValueMemberS{Value: "CLAIM"},
			},
			ConditionExpression: aws.String("UserID = :uid"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":uid": &types.AttributeValueMemberS{Value: plan.userID},
			},
		})
		var failed *types.ConditionalCheckFailedException
		if err != nil && !errors.As(err, &failed) {
			return err
		}
	}

	// PROFILE becomes (or stays) the same tombstone DeleteAccount leaves: public
	// keys stay so grants it signed still verify and the uuid stays taken. The
	// index keys stay too while it is waiting on a kept group, so later runs
	// revisit it, and go once there is nothing left to wait on.
	waiting := len(plan.keptGroups) > 0
	var sets, removes []string
	values := map[string]types.AttributeValue{}
	if !plan.wasDeleted {
		sets = append(sets, "DeletedAt = :now", "Username = :empty")
		removes = append(removes, "Salt", "Argon2Params", "WrappedPrivateKeys", "PreferencesBlob", "FailedVerifyCount", "LockUntil", "LastLoginDay")
		values[":now"] = &types.AttributeValueMemberS{Value: now.UTC().Format(time.RFC3339)}
		values[":empty"] = &types.AttributeValueMemberS{Value: ""}
	}
	if !waiting {
		removes = append(removes, "GSI1PK", "GSI1SK")
	}
	if len(sets) == 0 && len(removes) == 0 {
		return nil
	}
	expr := ""
	if len(sets) > 0 {
		expr += "SET " + strings.Join(sets, ", ")
	}
	if len(removes) > 0 {
		expr += " REMOVE " + strings.Join(removes, ", ")
	}
	in := &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + plan.userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		UpdateExpression:    aws.String(strings.TrimSpace(expr)),
		ConditionExpression: aws.String("attribute_exists(PK)"),
	}
	if len(values) > 0 {
		in.ExpressionAttributeValues = values
	}
	_, err := c.ddb.UpdateItem(ctx, in)
	return err
}

// isTestProfile is the purge's test-account check: the flag, plus the reserved
// prefix while the username still exists.
func isTestProfile(u *models.User) bool {
	if !u.TestAccount {
		return false
	}
	return u.DeletedAt != "" || models.HasTestUsernamePrefix(u.Username)
}

func (c *Client) getProfileConsistent(ctx context.Context, userID string) (*models.User, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, nil
	}
	var u models.User
	if err := attributevalue.UnmarshalMap(out.Item, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// groupMemberIDs lists the user ids holding a MEMBER# row in the group,
// straight from the base table (consistent), not the GSI.
func (c *Client) groupMemberIDs(ctx context.Context, groupID string) ([]string, error) {
	var ids []string
	var start map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
			ProjectionExpression:   aws.String("SK"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
				":sk": &types.AttributeValueMemberS{Value: "MEMBER#"},
			},
			ExclusiveStartKey: start,
			ConsistentRead:    aws.Bool(true),
		})
		if err != nil {
			return nil, err
		}
		for _, it := range out.Items {
			if sk, ok := it["SK"].(*types.AttributeValueMemberS); ok {
				ids = append(ids, strings.TrimPrefix(sk.Value, "MEMBER#"))
			}
		}
		if out.LastEvaluatedKey == nil {
			return ids, nil
		}
		start = out.LastEvaluatedKey
	}
}

// partitionKeys returns the PK/SK of every item in one partition.
func (c *Client) partitionKeys(ctx context.Context, pk string) ([]map[string]types.AttributeValue, error) {
	var keys []map[string]types.AttributeValue
	var start map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			KeyConditionExpression: aws.String("PK = :pk"),
			ProjectionExpression:   aws.String("PK, SK"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: pk},
			},
			ExclusiveStartKey: start,
			ConsistentRead:    aws.Bool(true),
		})
		if err != nil {
			return nil, err
		}
		for _, it := range out.Items {
			keys = append(keys, map[string]types.AttributeValue{"PK": it["PK"], "SK": it["SK"]})
		}
		if out.LastEvaluatedKey == nil {
			return keys, nil
		}
		start = out.LastEvaluatedKey
	}
}
