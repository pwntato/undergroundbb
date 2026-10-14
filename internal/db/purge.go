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
	// MaxAccounts caps accounts examined per run (skipped ones count);
	// zero means DefaultPurgeMaxAccounts.
	MaxAccounts int
	// DryRun plans and reports but deletes nothing.
	DryRun bool
	// Now is the clock; zero means time.Now().
	Now time.Time

	// onlyUsers restricts a run to these ids. Tests share one DynamoDB Local
	// with other packages' test accounts, so they must not purge each other.
	onlyUsers map[string]bool
}

// PurgeSkip records an account the purge examined and left alone.
type PurgeSkip struct {
	UserID string `json:"userId"`
	Reason string `json:"reason"`
}

// PurgeReport says what a run did, or with DryRun what it would do.
type PurgeReport struct {
	DryRun bool `json:"dryRun"`
	// Examined counts accounts looked at. Purged are removed outright;
	// Tombstoned are removed except for a tombstone PROFILE, because they are
	// still members of a group with real members (KeptGroups counts those
	// groups, which are left alone). Groups counts the test-only groups deleted
	// whole, and Rows every item deleted (or that would be). All counts are
	// what would happen under DryRun.
	Examined   int         `json:"examined"`
	Purged     int         `json:"purged"`
	Tombstoned int         `json:"tombstoned"`
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
// real member is never touched: the test account stays a member of it, and its
// PROFILE is tombstoned (as DeleteAccount does) instead of deleted, because the
// real members' clients still need its public keys to verify grants it signed.
// An admin removes the leftover member with the ordinary removal flow
// (docs/DESIGN.md, "Test accounts are a reserved, opt-in namespace").
//
// An account counts as a test account only when its PROFILE carries
// TestAccount (written solely by a registration that also used the reserved
// username prefix) and, while it is still live, its username has that prefix.
// A deleted account's username is gone, so the flag alone identifies it.
// Candidates come from the GSI1 "TESTACCOUNT" partition, so nothing scans.
//
// Order within an account: test-only groups, then the user's other rows and
// invites, then the username claim, then PROFILE last (deleted, or tombstoned
// with its index keys removed). PROFILE is what the candidate query finds, so a
// run that dies partway is finished by the next. Unlike DeleteAccount, an
// account in no group with real members has its PROFILE removed outright: its
// uuid was minted fresh for a test and nothing else refers to it once its
// groups are gone.
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
		if !opts.DryRun {
			if err := c.executePurge(ctx, plan); err != nil {
				return report, fmt.Errorf("db: purge %s: %w", uid, err)
			}
		}
		report.Groups += len(plan.groups)
		report.KeptGroups += len(plan.keptGroups)
		report.Rows += len(plan.keys)
		if plan.claimLower != "" {
			report.Rows++
		}
		if len(plan.keptGroups) > 0 {
			report.Tombstoned++
		} else {
			report.Purged++
			report.Rows++ // PROFILE
		}
	}
	return report, nil
}

type purgePlan struct {
	userID     string
	claimLower string
	groups     []string                          // test-only groups, deleted whole
	keptGroups map[string]bool                   // groups with a real member, left alone
	wasDeleted bool                              // PROFILE is already a tombstone
	keys       []map[string]types.AttributeValue // everything except PROFILE
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
		plan.groups = append(plan.groups, gid)
		plan.keys = append(plan.keys, keys...)
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
	// join requests they made. Memberships come back too; those in groups being
	// deleted are already planned, and those in kept groups must stay.
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
			if plan.keptGroups[strings.TrimPrefix(pk.Value, "GROUP#")] && strings.HasPrefix(sk.Value, "MEMBER#") {
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

func (c *Client) executePurge(ctx context.Context, plan purgePlan) error {
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
	profileKey := map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "USER#" + plan.userID},
		"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
	}
	if len(plan.keptGroups) == 0 {
		_, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(c.table), Key: profileKey})
		return err
	}
	// Still a member of a group with real members: keep PROFILE as the same
	// tombstone DeleteAccount leaves (public keys stay so grants it signed still
	// verify), and drop the TESTACCOUNT index keys so later runs do not revisit.
	expr := "SET DeletedAt = :now, Username = :empty " +
		"REMOVE Salt, Argon2Params, WrappedPrivateKeys, PreferencesBlob, FailedVerifyCount, LockUntil, LastLoginDay, GSI1PK, GSI1SK"
	values := map[string]types.AttributeValue{
		":now":   &types.AttributeValueMemberS{Value: time.Now().UTC().Format(time.RFC3339)},
		":empty": &types.AttributeValueMemberS{Value: ""},
	}
	if plan.wasDeleted {
		expr, values = "REMOVE GSI1PK, GSI1SK", nil
	}
	_, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(c.table),
		Key:                       profileKey,
		UpdateExpression:          aws.String(expr),
		ConditionExpression:       aws.String("attribute_exists(PK)"),
		ExpressionAttributeValues: values,
	})
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
