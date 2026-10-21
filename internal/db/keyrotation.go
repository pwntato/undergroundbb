package db

import (
	"bytes"
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

// Item sort keys for the key-rotation rows (#62).
const (
	handoffPrefix      = "HANDOFF#"
	keyChangePrefix    = "KEYCHANGE#"
	rotCooldownSortKey = "ROTCOOLDOWN"
)

// KeyChangeSortKey is the KEYCHANGE# sort key for the rotation that produced
// epoch n, zero-padded to six digits so the chain reads in order, as GENKEY#
// does.
func KeyChangeSortKey(n uint64) string { return fmt.Sprintf("%s%06d", keyChangePrefix, n) }

var (
	// ErrKeyEpochStale: the account's KeyEpoch is not the one the rotation was
	// signed against (another rotation landed first, or the request is a
	// replay). Nothing was written.
	ErrKeyEpochStale = errors.New("db: key epoch is stale; the keys were rotated by another request")
	// ErrRotationCooldown: this account rotated keys more recently than the
	// cooldown allows. Nothing was written.
	ErrRotationCooldown = errors.New("db: key rotation is on cooldown")
	// ErrHandoffPending: a handoff row naming the account's CURRENT wrapping key
	// exists, so PUT refuses to replace it (it is the only copy of a group key
	// a committed rotation's self re-key can use).
	ErrHandoffPending = errors.New("db: a handoff row for the current key already exists")
	// ErrHandoffNotAdmin: the caller is not an admin of the group, or their own
	// entry point is not at the generation the row names, so they cannot be
	// holding the key they are handing off.
	ErrHandoffNotAdmin = errors.New("db: caller is not an admin of the group at that generation")
	// ErrHandoffAccountChanged: the account's wrapping key is no longer the one
	// the handler compared the row against (a rotation committed in between).
	ErrHandoffAccountChanged = errors.New("db: the account's keys changed")
)

// GroupCurrentGeneration returns the generation a group's key is at now: one
// past its newest GENKEY# link (a link for generation g is written when the
// rotation to g+1 starts, so a rotation in progress counts), or 0 for a group
// that has never rotated. Strongly consistent.
func (c *Client) GroupCurrentGeneration(ctx context.Context, groupID string) (int64, error) {
	out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(c.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			":sk": &types.AttributeValueMemberS{Value: "GENKEY#"},
		},
		ProjectionExpression: aws.String("SK"),
		ScanIndexForward:     aws.Bool(false),
		Limit:                aws.Int32(1),
		ConsistentRead:       aws.Bool(true),
	})
	if err != nil {
		return 0, fmt.Errorf("db: newest generation key: %w", err)
	}
	if len(out.Items) == 0 {
		return 0, nil
	}
	sk, _ := out.Items[0]["SK"].(*types.AttributeValueMemberS)
	if sk == nil {
		return 0, errors.New("db: generation key without a sort key")
	}
	n, err := ParseGenKeySortKey(sk.Value)
	if err != nil {
		return 0, err
	}
	return n + 1, nil
}

// AdminGroup is a group the user is an admin of, with the generation their own
// entry point is at.
type AdminGroup struct {
	GroupID    string
	Generation int64
}

// ListAdminGroups returns the groups userID currently administers. The list
// comes from the GSI1 membership index, which is eventually consistent; a role
// granted in the last moments can be missed, and a group missed here is one the
// caller gets no handoff row for, which the design accepts (docs/DESIGN.md,
// "One window remains").
func (c *Client) ListAdminGroups(ctx context.Context, userID string) ([]AdminGroup, error) {
	memberships, err := c.queryMembershipsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("db: list admin groups: %w", err)
	}
	var groups []AdminGroup
	for _, m := range memberships {
		if m.Role == models.RoleAdmin {
			groups = append(groups, AdminGroup{GroupID: groupIDFromMembership(m), Generation: m.Generation})
		}
	}
	return groups, nil
}

// ListHandoffs returns every HANDOFF# row in the user's own partition,
// strongly consistent.
func (c *Client) ListHandoffs(ctx context.Context, userID string) ([]models.Handoff, error) {
	var rows []models.Handoff
	var start map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "USER#" + userID},
				":sk": &types.AttributeValueMemberS{Value: handoffPrefix},
			},
			ExclusiveStartKey: start,
			ConsistentRead:    aws.Bool(true),
		})
		if err != nil {
			return nil, fmt.Errorf("db: list handoffs: %w", err)
		}
		var page []models.Handoff
		if err := attributevalue.UnmarshalListOfMaps(out.Items, &page); err != nil {
			return nil, fmt.Errorf("db: unmarshal handoffs: %w", err)
		}
		rows = append(rows, page...)
		if out.LastEvaluatedKey == nil {
			return rows, nil
		}
		start = out.LastEvaluatedKey
	}
}

// PutHandoffInput is one handoff row. CurrentWrappingKey is the account's
// current X25519 key as the handler read it.
type PutHandoffInput struct {
	UserID               string
	GroupID              string
	Generation           int64
	NewWrappingPublicKey []byte
	WrappedGroupKey      models.WrappedKey
	CurrentWrappingKey   []byte
}

// PutHandoff writes (or replaces) the caller's handoff row for a group in one
// transaction: (0) the caller is still an admin whose own entry point is at
// Generation, (1) the account's wrapping key is still CurrentWrappingKey, so a
// rotation that committed meanwhile cannot have its row clobbered by a stale
// request, (2) the row is new or names a key other than the current one, since
// a row naming the current key is a committed rotation's only copy and is never
// replaced (docs/DESIGN.md, "The order is enforced so a pending row is never
// overwritten").
func (c *Client) PutHandoff(ctx context.Context, in PutHandoffInput) error {
	item, err := attributevalue.MarshalMap(models.Handoff{
		Record: models.Record{
			PK:   "USER#" + in.UserID,
			SK:   handoffPrefix + in.GroupID,
			Type: "Handoff",
		},
		GroupID:              in.GroupID,
		Generation:           in.Generation,
		NewWrappingPublicKey: in.NewWrappingPublicKey,
		WrappedGroupKey:      in.WrappedGroupKey,
	})
	if err != nil {
		return fmt.Errorf("db: marshal handoff: %w", err)
	}
	curKey, err := attributevalue.Marshal(in.CurrentWrappingKey)
	if err != nil {
		return err
	}
	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{ConditionCheck: &types.ConditionCheck{
				TableName:                aws.String(c.table),
				Key:                      memberKey(in.GroupID, in.UserID),
				ConditionExpression:      aws.String("#role = :admin AND #gen = :gen"),
				ExpressionAttributeNames: map[string]string{"#role": "Role", "#gen": "Generation"},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin},
					":gen":   genAttr(in.Generation),
				},
			}},
			{ConditionCheck: &types.ConditionCheck{
				TableName: aws.String(c.table),
				Key: map[string]types.AttributeValue{
					"PK": &types.AttributeValueMemberS{Value: "USER#" + in.UserID},
					"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
				},
				ConditionExpression:       aws.String("WrappingPublicKey = :cur AND attribute_not_exists(DeletedAt)"),
				ExpressionAttributeValues: map[string]types.AttributeValue{":cur": curKey},
			}},
			{Put: &types.Put{
				TableName:                 aws.String(c.table),
				Item:                      item,
				ConditionExpression:       aws.String("attribute_not_exists(PK) OR NewWrappingPublicKey <> :cur"),
				ExpressionAttributeValues: map[string]types.AttributeValue{":cur": curKey},
			}},
		},
	})
	if err != nil {
		switch {
		case isConditionalCheckFailure(err, 0):
			return ErrHandoffNotAdmin
		case isConditionalCheckFailure(err, 1):
			return ErrHandoffAccountChanged
		case isConditionalCheckFailure(err, 2):
			return ErrHandoffPending
		}
		return err
	}
	return nil
}

// DeleteHandoff removes the caller's handoff row for a group. Deleting a row
// that is not there succeeds.
func (c *Client) DeleteHandoff(ctx context.Context, userID, groupID string) error {
	_, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(c.table),
		Key:       handoffKey(userID, groupID),
	})
	if err != nil {
		return fmt.Errorf("db: delete handoff: %w", err)
	}
	return nil
}

func handoffKey(userID, groupID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
		"SK": &types.AttributeValueMemberS{Value: handoffPrefix + groupID},
	}
}

// SweepHandoffs deletes the handoff rows a committed rotation left behind that
// nothing can use: rows naming a key other than the account's current one
// (an abandoned attempt), and rows for a group where the caller is no longer an
// admin (a co-admin's demotion, or removal from an Open group, would otherwise
// leave a row no re-key can use and the account unable to rotate). Rows that
// name the current key for a group the caller still administers are the
// handoff itself and stay. Membership is read per row with a consistent read,
// not from the eventually consistent GSI, so a freshly granted role is never
// misread as lost.
func (c *Client) SweepHandoffs(ctx context.Context, userID string, currentWrappingKey []byte) error {
	rows, err := c.ListHandoffs(ctx, userID)
	if err != nil {
		return err
	}
	var doomed []map[string]types.AttributeValue
	for _, row := range rows {
		gid := strings.TrimPrefix(row.SK, handoffPrefix)
		if !bytes.Equal(row.NewWrappingPublicKey, currentWrappingKey) {
			doomed = append(doomed, handoffKey(userID, gid))
			continue
		}
		out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
			TableName:                aws.String(c.table),
			Key:                      memberKey(gid, userID),
			ConsistentRead:           aws.Bool(true),
			ProjectionExpression:     aws.String("#role"),
			ExpressionAttributeNames: map[string]string{"#role": "Role"},
		})
		if err != nil {
			return fmt.Errorf("db: sweep handoffs: %w", err)
		}
		role, _ := out.Item["Role"].(*types.AttributeValueMemberS)
		if role == nil || role.Value != models.RoleAdmin {
			doomed = append(doomed, handoffKey(userID, gid))
		}
	}
	return c.batchDelete(ctx, doomed)
}

// ListKeyChanges returns the user's KEYCHANGE# chain in epoch order.
func (c *Client) ListKeyChanges(ctx context.Context, userID string) ([]models.KeyChange, error) {
	var rows []models.KeyChange
	var start map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "USER#" + userID},
				":sk": &types.AttributeValueMemberS{Value: keyChangePrefix},
			},
			ExclusiveStartKey: start,
			ConsistentRead:    aws.Bool(true),
		})
		if err != nil {
			return nil, fmt.Errorf("db: list key changes: %w", err)
		}
		var page []models.KeyChange
		if err := attributevalue.UnmarshalListOfMaps(out.Items, &page); err != nil {
			return nil, fmt.Errorf("db: unmarshal key changes: %w", err)
		}
		rows = append(rows, page...)
		if out.LastEvaluatedKey == nil {
			return rows, nil
		}
		start = out.LastEvaluatedKey
	}
}

// RotateKeysInput is a verified key rotation. The handler has checked both
// signatures, the day, and that ExpectedKeyEpoch is the account's; this
// package, as everywhere, stores the signatures without checking them.
type RotateKeysInput struct {
	// Credentials is the full re-wrap of PROFILE and RECOVERY under a new
	// password and a new recovery code, written in the same transaction.
	// ExpectedCredentialVersion and NewCredentialVersion are set by the caller.
	Credentials RewrapCredentialsInput

	ExpectedKeyEpoch uint64

	OldSigningPublicKey  []byte
	OldWrappingPublicKey []byte
	NewSigningPublicKey  []byte
	NewWrappingPublicKey []byte

	// SupersededFrom and SupersededUntil are the RFC 3339 bounds appended to
	// SupersededSigningKeys for the old signing key (day resolution).
	SupersededFrom  string
	SupersededUntil string

	// PreferencesBlob is the preferences re-sealed under the new X25519 key, or
	// nil when the account has none.
	PreferencesBlob *models.WrappedBlob

	// KeyChange is the KEYCHANGE# row; its Record and KeyEpoch are filled in
	// here.
	KeyChange models.KeyChange

	// Cooldown is how long a following rotation is refused; Now is the clock.
	Cooldown time.Duration
	Now      time.Time
}

// RotateKeys commits a rotation in one TransactWriteItems (docs/DESIGN.md,
// "What a rotation writes"):
//
//   - PROFILE: the new public keys, the credentials re-wrapped under a new
//     password, the old signing key appended to SupersededSigningKeys,
//     KeyEpoch+1, SessionGeneration+1 and the re-sealed preferences, all
//     conditioned on KeyEpoch and CredentialVersion still being what the
//     request was signed against and on the old keys still being current.
//   - RECOVERY: the new keys wrapped under a new recovery code.
//   - KEYCHANGE#<epoch>: the payload and both signatures, new.
//   - ROTCOOLDOWN: refuses a second rotation until its TTL passes.
//
// Four items, so the number of groups the user is in never meets the 100-item
// transaction limit; the per-group handoff rows are written before, by
// PutHandoff.
func (c *Client) RotateKeys(ctx context.Context, in RotateKeysInput) error {
	userID := in.Credentials.UserID
	newEpoch := in.ExpectedKeyEpoch + 1

	superseded, err := attributevalue.Marshal([]models.SupersededKey{{
		PublicKey: in.OldSigningPublicKey,
		From:      in.SupersededFrom,
		Until:     in.SupersededUntil,
	}})
	if err != nil {
		return err
	}
	vals, err := attributevalue.MarshalMap(map[string]any{
		":newSign":   in.NewSigningPublicKey,
		":newWrap":   in.NewWrappingPublicKey,
		":oldSign":   in.OldSigningPublicKey,
		":oldWrap":   in.OldWrappingPublicKey,
		":newEpoch":  newEpoch,
		":expEpoch":  in.ExpectedKeyEpoch,
		":emptyList": []models.SupersededKey{},
	})
	if err != nil {
		return err
	}
	extras := profileExtras{
		set: ", SigningPublicKey = :newSign, WrappingPublicKey = :newWrap, KeyEpoch = :newEpoch, " +
			"SupersededSigningKeys = list_append(if_not_exists(SupersededSigningKeys, :emptyList), :superseded)",
		values: map[string]types.AttributeValue{
			":newSign":    vals[":newSign"],
			":newWrap":    vals[":newWrap"],
			":oldSign":    vals[":oldSign"],
			":oldWrap":    vals[":oldWrap"],
			":newEpoch":   vals[":newEpoch"],
			":expEpoch":   vals[":expEpoch"],
			":emptyList":  vals[":emptyList"],
			":superseded": superseded,
		},
		condition: " AND attribute_not_exists(DeletedAt) AND SigningPublicKey = :oldSign AND WrappingPublicKey = :oldWrap",
	}
	if in.ExpectedKeyEpoch == 0 {
		extras.condition += " AND (attribute_not_exists(KeyEpoch) OR KeyEpoch = :expEpoch)"
	} else {
		extras.condition += " AND KeyEpoch = :expEpoch"
	}
	if in.PreferencesBlob != nil {
		prefs, err := attributevalue.Marshal(*in.PreferencesBlob)
		if err != nil {
			return err
		}
		extras.set += ", PreferencesBlob = :prefs"
		extras.values[":prefs"] = prefs
	}

	profileUpdate, recoveryUpdate, err := c.credentialUpdates(in.Credentials, extras)
	if err != nil {
		return err
	}

	kc := in.KeyChange
	kc.Record = models.Record{PK: "USER#" + userID, SK: KeyChangeSortKey(newEpoch), Type: "KeyChange"}
	kc.KeyEpoch = newEpoch
	if kc.Roster == nil {
		kc.Roster = [][]byte{}
	}
	kcItem, err := attributevalue.MarshalMap(kc)
	if err != nil {
		return fmt.Errorf("db: marshal key change: %w", err)
	}
	cooldownItem, err := attributevalue.MarshalMap(models.RotationCooldown{
		Record: models.Record{PK: "USER#" + userID, SK: rotCooldownSortKey, Type: "RotationCooldown"},
		TTL:    in.Now.Add(in.Cooldown).Unix(),
	})
	if err != nil {
		return fmt.Errorf("db: marshal rotation cooldown: %w", err)
	}

	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Update: profileUpdate},
			{Update: recoveryUpdate},
			{Put: &types.Put{
				TableName:           aws.String(c.table),
				Item:                kcItem,
				ConditionExpression: aws.String("attribute_not_exists(PK)"),
			}},
			{Put: &types.Put{
				TableName:                aws.String(c.table),
				Item:                     cooldownItem,
				ConditionExpression:      aws.String("attribute_not_exists(PK) OR #ttl <= :now"),
				ExpressionAttributeNames: map[string]string{"#ttl": "TTL"},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":now": &types.AttributeValueMemberN{Value: strconv.FormatInt(in.Now.Unix(), 10)},
				},
			}},
		},
	})
	if err == nil {
		return nil
	}
	switch {
	case isConditionalCheckFailure(err, 3):
		return ErrRotationCooldown
	case isConditionalCheckFailure(err, 2):
		return ErrKeyEpochStale
	case isConditionalCheckFailure(err, 0), isConditionalCheckFailure(err, 1):
		// PROFILE and RECOVERY share the credential-version condition and the
		// rest is PROFILE's; read it back to say which one failed.
		user, getErr := c.getUserConsistent(ctx, userID)
		switch {
		case errors.Is(getErr, ErrUserNotFound):
			return ErrUserNotFound
		case getErr != nil:
			return err
		case user.DeletedAt != "":
			return ErrUserNotFound
		case user.KeyEpoch != in.ExpectedKeyEpoch,
			!bytes.Equal(user.SigningPublicKey, in.OldSigningPublicKey),
			!bytes.Equal(user.WrappingPublicKey, in.OldWrappingPublicKey):
			return ErrKeyEpochStale
		}
		return ErrCredentialVersionStale
	}
	return err
}

// getUserConsistent is GetUserByID with a strongly consistent read, for the
// caller that must see a write made moments ago.
func (c *Client) getUserConsistent(ctx context.Context, userID string) (*models.User, error) {
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
		return nil, ErrUserNotFound
	}
	var user models.User
	if err := attributevalue.UnmarshalMap(out.Item, &user); err != nil {
		return nil, err
	}
	return &user, nil
}
