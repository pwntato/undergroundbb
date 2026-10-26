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
	handoffSeqSortKey  = "HANDOFFSEQ"
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
	// ErrWrapEpochStale: a group key was wrapped to a key its recipient has
	// since rotated away from (the recipient's PROFILE KeyEpoch is no longer the
	// one the write was built against). Nothing was written; the client
	// re-reads the recipient's keys and wraps again.
	ErrWrapEpochStale = errors.New("db: the recipient's keys changed; the wrap is stale")
	// ErrHandoffChanged: a handoff row was written or deleted after the handler
	// read the rows it checked, so the rotation was built against rows that may
	// no longer be there. Nothing was written; the client retries.
	ErrHandoffChanged = errors.New("db: the handoff rows changed during the rotation")
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

// HandoffGroup is a group the user owes a handoff row for, with the generation
// their own entry point is at: one they administer, or any group with no
// rotation (Open or public) they belong to, where every member self-wraps.
type HandoffGroup struct {
	GroupID    string
	Generation int64
}

// ListHandoffGroups returns the groups userID owes a handoff row for. The list
// comes from the GSI1 membership index, which is eventually consistent; a role
// granted or a group joined in the last moments can be missed, and a group
// missed here is one the caller gets no handoff row for, which the design
// accepts (docs/DESIGN.md, "One window remains").
func (c *Client) ListHandoffGroups(ctx context.Context, userID string) ([]HandoffGroup, error) {
	memberships, err := c.queryMembershipsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("db: list handoff groups: %w", err)
	}
	// Only a non-admin's group needs its META read, to tell Open from Rotating.
	var others []string
	for _, m := range memberships {
		if m.Role != models.RoleAdmin {
			others = append(others, groupIDFromMembership(m))
		}
	}
	var metas map[string]models.Group
	if len(others) > 0 {
		if metas, err = c.batchGetGroupMetas(ctx, others); err != nil {
			return nil, fmt.Errorf("db: list handoff groups: %w", err)
		}
	}
	var groups []HandoffGroup
	for _, m := range memberships {
		gid := groupIDFromMembership(m)
		if m.Role != models.RoleAdmin {
			meta, ok := metas[gid]
			if !ok || !meta.HasNoRotation() {
				continue
			}
		}
		groups = append(groups, HandoffGroup{GroupID: gid, Generation: m.Generation})
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
	// Open is true for a group with no rotation (Open or public), where any
	// member, not only an admin, hands off the key it holds to self-wrap.
	Open bool
}

// PutHandoff writes (or replaces) the caller's handoff row for a group in one
// transaction: (0) the caller is still an admin (any member, for an Open group)
// whose own entry point is at Generation, (1) the account's wrapping key is still CurrentWrappingKey, so a
// rotation that committed meanwhile cannot have its row clobbered by a stale
// request, (2) the row is new or names a key other than the current one, since
// a row naming the current key is a committed rotation's only copy and is never
// replaced (docs/DESIGN.md, "The order is enforced so a pending row is never
// overwritten"), and (3) the HANDOFFSEQ counter moves, which fails a rotation
// whose handoff check read the rows before this one.
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
	// DynamoDB rejects a name or value the expression does not use.
	memberCond := "#role = :admin AND #gen = :gen"
	memberNames := map[string]string{"#role": "Role", "#gen": "Generation"}
	memberValues := map[string]types.AttributeValue{
		":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin},
		":gen":   genAttr(in.Generation),
	}
	if in.Open {
		memberCond = "#gen = :gen"
		memberNames = map[string]string{"#gen": "Generation"}
		memberValues = map[string]types.AttributeValue{":gen": genAttr(in.Generation)}
	}
	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{ConditionCheck: &types.ConditionCheck{
				TableName:                 aws.String(c.table),
				Key:                       memberKey(in.GroupID, in.UserID),
				ConditionExpression:       aws.String(memberCond),
				ExpressionAttributeNames:  memberNames,
				ExpressionAttributeValues: memberValues,
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
			c.bumpHandoffSeq(in.UserID),
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

// DeleteHandoff removes the caller's handoff row for a group and bumps the
// HANDOFFSEQ counter in the same transaction, so a rotation that checked the
// rows before this one fails instead of committing without it. Deleting a row
// that is not there succeeds. For an account that is deleted or gone it also
// succeeds and writes nothing: account deletion has swept its rows, and a bump
// here would recreate a HANDOFFSEQ item that nothing removes.
func (c *Client) DeleteHandoff(ctx context.Context, userID, groupID string) error {
	_, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Delete: &types.Delete{TableName: aws.String(c.table), Key: handoffKey(userID, groupID)}},
			c.bumpHandoffSeq(userID),
			{ConditionCheck: &types.ConditionCheck{
				TableName: aws.String(c.table),
				Key: map[string]types.AttributeValue{
					"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
					"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
				},
				ConditionExpression: aws.String("attribute_exists(PK) AND attribute_not_exists(DeletedAt)"),
			}},
		},
	})
	if isConditionalCheckFailure(err, 2) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("db: delete handoff: %w", err)
	}
	return nil
}

func handoffSeqKey(userID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
		"SK": &types.AttributeValueMemberS{Value: handoffSeqSortKey},
	}
}

// bumpHandoffSeq is the transaction item that moves the HANDOFFSEQ counter.
func (c *Client) bumpHandoffSeq(userID string) types.TransactWriteItem {
	return types.TransactWriteItem{Update: &types.Update{
		TableName:                aws.String(c.table),
		Key:                      handoffSeqKey(userID),
		UpdateExpression:         aws.String("SET #type = :type ADD #seq :one"),
		ExpressionAttributeNames: map[string]string{"#type": "Type", "#seq": "Seq"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":type": &types.AttributeValueMemberS{Value: "HandoffSeq"},
			":one":  &types.AttributeValueMemberN{Value: "1"},
		},
	}}
}

// GetHandoffSeq returns the HANDOFFSEQ counter, strongly consistent; absent is
// 0. Read it BEFORE ListHandoffs and pass it to RotateKeys as
// ExpectedHandoffSeq.
func (c *Client) GetHandoffSeq(ctx context.Context, userID string) (int64, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(c.table),
		Key:            handoffSeqKey(userID),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return 0, fmt.Errorf("db: read handoff seq: %w", err)
	}
	if out.Item == nil {
		return 0, nil
	}
	var seq models.HandoffSeq
	if err := attributevalue.UnmarshalMap(out.Item, &seq); err != nil {
		return 0, fmt.Errorf("db: unmarshal handoff seq: %w", err)
	}
	return seq.Seq, nil
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
		keep := role != nil && role.Value == models.RoleAdmin
		if role != nil && !keep {
			// A member's row is still the way into a group with no rotation.
			g, err := c.GetGroup(ctx, gid)
			if err != nil {
				return fmt.Errorf("db: sweep handoffs: %w", err)
			}
			keep = g != nil && g.HasNoRotation()
		}
		if !keep {
			doomed = append(doomed, handoffKey(userID, gid))
		}
	}
	return c.batchDelete(ctx, doomed)
}

// keyChangeServedAttrs are the KEYCHANGE# attributes served without the roster.
// The roster is client-supplied (up to 128 KiB a row), so the public read never
// pulls it.
const keyChangeServedAttrs = "PK, SK, KeyEpoch, #day, OldSigningPublicKey, OldWrappingPublicKey, " +
	"NewSigningPublicKey, NewWrappingPublicKey, RosterDigest, OldSignature, NewSignature"

// ListKeyChanges returns the user's KEYCHANGE# chain in epoch order. Roster is
// filled in only when withRoster is set, which is for the owner's own pin list;
// the public read of the chain passes false and the rows come back without it.
func (c *Client) ListKeyChanges(ctx context.Context, userID string, withRoster bool) ([]models.KeyChange, error) {
	var rows []models.KeyChange
	var start map[string]types.AttributeValue
	for {
		in := &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "USER#" + userID},
				":sk": &types.AttributeValueMemberS{Value: keyChangePrefix},
			},
			ExclusiveStartKey: start,
			ConsistentRead:    aws.Bool(true),
		}
		if !withRoster {
			in.ProjectionExpression = aws.String(keyChangeServedAttrs)
			in.ExpressionAttributeNames = map[string]string{"#day": "Day"}
		}
		out, err := c.ddb.Query(ctx, in)
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

	// ExpectedHandoffSeq is the HANDOFFSEQ counter as GetHandoffSeq read it
	// before the handoff rows were listed. The commit fails with
	// ErrHandoffChanged if a PutHandoff or DeleteHandoff has moved it since.
	ExpectedHandoffSeq int64

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

	// Cooldown is how long a following rotation is refused, rounded up to the end
	// of its UTC day; zero or less turns the limit off. Now is the clock.
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
//   - ROTCOOLDOWN: refuses a second rotation until its TTL passes (omitted when
//     the cooldown is off).
//   - HANDOFFSEQ: a condition check that no handoff row was written or deleted
//     since the handler read them (docs/DESIGN.md, "A handoff change during a
//     rotation").
//
// At most five items, so the number of groups the user is in never meets the 100-item
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
	items := []types.TransactWriteItem{
		{Update: profileUpdate},
		{Update: recoveryUpdate},
		{Put: &types.Put{
			TableName:           aws.String(c.table),
			Item:                kcItem,
			ConditionExpression: aws.String("attribute_not_exists(PK)"),
		}},
	}
	// The cooldown item goes last. A cooldown of zero or less turns the limit off
	// (config never produces one; it clamps to an hour at least), and then no
	// item is written. Its TTL is rounded up to the end of its UTC day like every
	// stored TTL (docs/DESIGN.md, "Every stored TTL value is rounded up"): an
	// unrounded one would be the second the rotation happened, in the clear, so
	// the limit is the setting plus up to a day.
	const cooldownIndex = 3
	if in.Cooldown > 0 {
		cooldownItem, err := attributevalue.MarshalMap(models.RotationCooldown{
			Record: models.Record{PK: "USER#" + userID, SK: rotCooldownSortKey, Type: "RotationCooldown"},
			TTL:    RoundUpToEndOfUTCDay(in.Now.Add(in.Cooldown)).Unix(),
		})
		if err != nil {
			return fmt.Errorf("db: marshal rotation cooldown: %w", err)
		}
		items = append(items, types.TransactWriteItem{Put: &types.Put{
			TableName:                aws.String(c.table),
			Item:                     cooldownItem,
			ConditionExpression:      aws.String("attribute_not_exists(PK) OR #ttl <= :now"),
			ExpressionAttributeNames: map[string]string{"#ttl": "TTL"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":now": &types.AttributeValueMemberN{Value: strconv.FormatInt(in.Now.Unix(), 10)},
			},
		}})
	}

	seqIndex := len(items)
	items = append(items, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName:                aws.String(c.table),
		Key:                      handoffSeqKey(userID),
		ConditionExpression:      aws.String("attribute_not_exists(#seq) OR #seq = :seq"),
		ExpressionAttributeNames: map[string]string{"#seq": "Seq"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":seq": &types.AttributeValueMemberN{Value: strconv.FormatInt(in.ExpectedHandoffSeq, 10)},
		},
	}})

	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if err == nil {
		return nil
	}
	switch {
	case in.Cooldown > 0 && isConditionalCheckFailure(err, cooldownIndex):
		return ErrRotationCooldown
	case isConditionalCheckFailure(err, seqIndex):
		return ErrHandoffChanged
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

// epochEquals is a condition fragment requiring attr to equal the epoch held in
// placeholder, where an absent attribute reads as 0 (KeyEpoch and WrapEpoch are
// both omitted until a user first rotates).
func epochEquals(attr, placeholder string, epoch uint64) string {
	if epoch == 0 {
		return "(attribute_not_exists(" + attr + ") OR " + attr + " = " + placeholder + ")"
	}
	return attr + " = " + placeholder
}

func epochAttr(epoch uint64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatUint(epoch, 10)}
}

// profileKey is the PK/SK of a user's PROFILE item.
func profileKey(userID string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
		"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
	}
}

// keyEpochCheck asserts userID's PROFILE is not deleted and still at KeyEpoch
// epoch: the same-transaction half of "every path that writes a MEMBER# wrap
// sets WrapEpoch from the recipient's KeyEpoch and checks it" (docs/DESIGN.md,
// "Dormancy is derived, not stored"), so a wrap to a key that has just been
// replaced is refused instead of stored.
func (c *Client) keyEpochCheck(userID string, epoch uint64) types.TransactWriteItem {
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName:                 aws.String(c.table),
		Key:                       profileKey(userID),
		ConditionExpression:       aws.String("attribute_not_exists(DeletedAt) AND " + epochEquals("KeyEpoch", ":kep", epoch)),
		ExpressionAttributeValues: map[string]types.AttributeValue{":kep": epochAttr(epoch)},
	}}
}

// whyProfileCheckFailed says why a keyEpochCheck failed: deleted is true for a
// tombstoned (or missing) account; otherwise the epoch moved, ErrWrapEpochStale.
func (c *Client) whyProfileCheckFailed(ctx context.Context, userID string) (deleted bool, err error) {
	user, err := c.getUserConsistent(ctx, userID)
	if errors.Is(err, ErrUserNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return user.DeletedAt != "", nil
}
