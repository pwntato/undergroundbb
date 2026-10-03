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

// ErrGroupIDTaken is returned when the GROUP#<gid> META item already exists
// and the attempt is a genuine conflict, not the caller's own earlier,
// successful call being resent -- see isOwnGroupCreation, consulted first.
// gid is client-generated (createGroupRequest.GroupID's own doc comment),
// the same reasoning RegisterInput.UserID gives for why this is not
// astronomically rare in the same way a server-generated id would be: a
// lost response to a genuinely identical retry is an expected case here,
// not just a CSPRNG collision. See ErrUserIDTaken's own doc comment for the
// fuller argument this one extends.
var ErrGroupIDTaken = errors.New("db: group id taken")

// CreateGroupInput is everything CreateGroup needs to create a group and its
// creator's own membership and root role grant. GroupID is client-generated
// (handlers.createGroup's own doc comment) and passed in rather than
// generated here, so the caller can use it to build CreatorSigningPublicKey's
// signature payload (crypto.TrustAnchorPayload, crypto.RoleGrantPayload)
// before this call -- the same reason RegisterInput takes UserID rather than
// generating it.
type CreateGroupInput struct {
	GroupID string

	CreatorUserID           string
	CreatorSigningPublicKey []byte
	// TrustAnchorSignature is the creator's signature (crypto.Sign under
	// crypto.ContextTrustAnchor, over crypto.TrustAnchorPayload) proving
	// CreatorUserID actually holds CreatorSigningPublicKey's private half.
	// This package does not itself call crypto.Verify -- see CreateGroup's
	// own doc comment for why that check belongs in the handler, ahead of
	// this call, alongside the same reasoning register.go's handler applies
	// to every other structural/cryptographic validation.
	TrustAnchorSignature []byte

	Visibility string // models.VisibilityPrivate or models.VisibilityPublic

	NamePlaintext         string              // set only when Visibility is public
	DescriptionPlaintext  string              // set only when Visibility is public
	NameCiphertext        *models.WrappedBlob // set only when Visibility is private
	DescriptionCiphertext *models.WrappedBlob // set only when Visibility is private

	RevocationMode string // models.RevocationRotating or models.RevocationOpen
	ExpirationDays int64  // 0 means "never expire"

	// GenerationKeyWrapped is the group's Generation 0 key, ECIES-wrapped to
	// the creator's own X25519 public key -- stored on the creator's own
	// MEMBER# item (models.Membership.WrappedGroupKey) as their entry point
	// to the group key. Not duplicated onto META (PR #142 review): the only
	// reader of a member's wrapped key is that member, via their own
	// MEMBER# item, and a second copy on META would go stale at the first
	// key rotation while still looking current to anyone who fetched it.
	GenerationKeyWrapped models.WrappedKey

	// RootGrantSortKey is the GRANT# item's sort key
	// ("GRANT#<uuid>#<YYYY-MM-DD>#<rand>"), client-generated and signed as
	// part of RootGrantSignature's own payload (crypto.RoleGrantPayload's
	// own doc comment) -- the handler validates its shape and day
	// (idgen.ValidGrantSortKey) before this call, but does not construct
	// it, matching the "caller passes through what the signature needs"
	// pattern GroupID/TrustAnchorSignature already follow. The same value
	// doubles as the signed payload's grantorGrantRef for any grant issued
	// later against this one and as the actual DynamoDB sort key here.
	RootGrantSortKey string
	// RootGrantSignature is the creator's self-signature (crypto.Sign under
	// crypto.ContextRoleGrant, over crypto.RoleGrantPayload with an empty
	// grantorGrantRef) over the root grant -- see models.RoleGrant's own doc
	// comment.
	RootGrantSignature []byte
}

// CreateGroup creates a group: the GROUP#<gid>/META item, the creator's own
// GROUP#<gid>/MEMBER#<uuid> item, and the self-signed root
// GROUP#<gid>/GRANT#<uuid>#<day>#<rand> item that anchors the chain of
// trust, as one TransactWriteItems -- see docs/DESIGN.md, "Roles and the
// chain of trust": "The anchor is signed by the creator at group creation."
// A group without its root grant already committed would be a group a
// client-side chain walk could never verify past its own creator, so this
// is subject to the same partial-write reasoning Register's own doc comment
// gives for signup's three-item transaction: no interruption (a timeout, a
// throttle) may leave a group without one of these ever accessible again
// through the ordinary write paths that assume the other two already exist.
//
// This package does not verify TrustAnchorSignature or RootGrantSignature --
// db is a pure data-access layer with no cryptographic policy of its own
// (matching RegisterInput's own doc comment on where structural validation
// belongs), and neither signature is a value this package could usefully
// check anyway: verifying them only proves CreatorUserID holds the private
// key behind CreatorSigningPublicKey, which every client that later reads
// this group must independently verify before trusting the anchor regardless
// of whether the server bothered to check it first (see DESIGN.md,
// "Pinning the key... matters because... anchoring on the uuid alone would
// still let the server choose"). The handler validates shape, size and
// encoding before this call, the same division register.go's handler and
// this package already use.
//
// Returns the root grant's actual sort key -- in.RootGrantSortKey on a
// fresh write, but the STORED one (which may differ) on a lost-response
// retry, since the client re-signs a brand new grantSortKey on every
// attempt including a resumed one (PR #142 round 2 review: the caller must
// never echo back an address nothing was written under).
func (c *Client) CreateGroup(ctx context.Context, in CreateGroupInput) (string, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	group := models.Group{
		Record: models.Record{
			PK:        "GROUP#" + in.GroupID,
			SK:        "META",
			Type:      "Group",
			CreatedAt: now,
		},
		CreatorUserID:           in.CreatorUserID,
		CreatorSigningPublicKey: in.CreatorSigningPublicKey,
		TrustAnchorSignature:    in.TrustAnchorSignature,
		RootGrantSortKey:        in.RootGrantSortKey,
		Visibility:              in.Visibility,
		NamePlaintext:           in.NamePlaintext,
		DescriptionPlaintext:    in.DescriptionPlaintext,
		NameCiphertext:          in.NameCiphertext,
		DescriptionCiphertext:   in.DescriptionCiphertext,
		RevocationMode:          in.RevocationMode,
		ExpirationDays:          in.ExpirationDays,
	}
	if in.Visibility == models.VisibilityPublic {
		// See docs/DESIGN.md, "Visibility": the directory entry is a sparse
		// GSI1 write present only on public groups. shard is fixed at "0" for
		// now -- the doc describes PUBLIC#<shard> fan-out as a future
		// scaling concern ("a small fixed fan-out is enough"), and #71
		// (public group directory) is what will actually read this index;
		// #34 only needs to write a shape #71 can build on without a schema
		// change later.
		group.GSI1PK = "PUBLIC#0"
		group.GSI1SK = "NAME#" + in.NamePlaintext + "#" + in.GroupID
	}

	membership := models.Membership{
		Record: models.Record{
			PK:        "GROUP#" + in.GroupID,
			SK:        "MEMBER#" + in.CreatorUserID,
			Type:      "Membership",
			CreatedAt: now,
			GSI1PK:    "USER#" + in.CreatorUserID,
			GSI1SK:    "GROUP#" + in.GroupID,
		},
		Role:            models.RoleAdmin,
		Generation:      0,
		WrappedGroupKey: in.GenerationKeyWrapped,
		GrantSortKey:    in.RootGrantSortKey,
	}

	grant := models.RoleGrant{
		Record: models.Record{
			PK:        "GROUP#" + in.GroupID,
			SK:        in.RootGrantSortKey,
			Type:      "RoleGrant",
			CreatedAt: now,
		},
		SubjectUserID:           in.CreatorUserID,
		GrantedRole:             models.RoleAdmin,
		GrantorUserID:           in.CreatorUserID,
		GrantorSigningPublicKey: in.CreatorSigningPublicKey,
		Signature:               in.RootGrantSignature,
	}

	groupItem, err := attributevalue.MarshalMap(group)
	if err != nil {
		return "", err
	}
	membershipItem, err := attributevalue.MarshalMap(membership)
	if err != nil {
		return "", err
	}
	grantItem, err := attributevalue.MarshalMap(grant)
	if err != nil {
		return "", err
	}

	// groupItemIndex names the one conditional item's position, matching
	// Register's own isConditionalCheckFailure(err, itemIndex) pattern -- see
	// that function's doc comment for why position rather than a scan.
	const (
		groupItemIndex   = 0
		creatorGoneIndex = 3
	)

	_, err = c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{
				Put: &types.Put{
					TableName:           aws.String(c.table),
					Item:                groupItem,
					ConditionExpression: aws.String("attribute_not_exists(PK)"),
				},
			},
			{Put: &types.Put{TableName: aws.String(c.table), Item: membershipItem}},
			{Put: &types.Put{TableName: aws.String(c.table), Item: grantItem}},
			// The creator's account must not have been deleted (#77): a
			// session cookie issued before deletion stays valid until it
			// expires, and without this a stale cookie would make the
			// tombstone the admin of a new group. CompleteInvite carries the
			// same check; these are the only two writers of a MEMBER# row.
			{ConditionCheck: &types.ConditionCheck{
				TableName: aws.String(c.table),
				Key: map[string]types.AttributeValue{
					"PK": &types.AttributeValueMemberS{Value: "USER#" + in.CreatorUserID},
					"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
				},
				ConditionExpression: aws.String("attribute_not_exists(DeletedAt)"),
			}},
		},
	})
	if err != nil {
		if isConditionalCheckFailure(err, creatorGoneIndex) {
			return "", ErrCreatorDeleted
		}
		if isConditionalCheckFailure(err, groupItemIndex) {
			// Before reporting a conflict, check whether this is the
			// caller's own earlier, successful call being resent after a
			// lost response -- see isOwnGroupCreation's own doc comment.
			// Unlike Register's isOwnRegistration, this is checked on every
			// GroupID conflict, not only one paired with a second failing
			// condition: there is only one conditional item here (META),
			// so a lost-response retry looks identical to a genuine
			// collision at this point, and the two are told apart by
			// reading META back and comparing it to in below.
			storedRootGrantSortKey, isRetry, checkErr := c.isOwnGroupCreation(ctx, in)
			if checkErr != nil {
				return "", checkErr
			}
			if isRetry {
				// Return the STORED root grant sort key, not
				// in.RootGrantSortKey -- the client re-signs a brand new
				// grantSortKey on every attempt, including a resumed one
				// (CreateGroupScreen calls signGroupCreation again, which
				// calls generateGrantSortKey again), so this retry's own
				// request value addresses a row that was never written.
				return storedRootGrantSortKey, nil
			}
			return "", ErrGroupIDTaken
		}
		return "", err
	}
	return in.RootGrantSortKey, nil
}

// isOwnGroupCreation reports whether a CreateGroup call that lost the META
// condition is actually in.GroupID's own earlier, successful call being
// resent -- not a genuine collision with someone else's group, and not a
// resend whose signed material has since diverged from what was actually
// stored. See CreateGroup's own call site for why this is checked on every
// conflict here (unlike Register's isOwnRegistration, which only applies
// when a second condition fails alongside the first).
//
// Matching CreatorUserID alone would not be enough (the same PR #133 round
// 1 reasoning isOwnRegistration's own doc comment gives): it would only
// prove this caller created *a* group at this id before, not that it was
// created with THIS request's signed material. TrustAnchorSignature is
// compared as the proof of that -- it is deterministic over
// (CreatorUserID, CreatorSigningPublicKey, GroupID) and this package never
// re-signs it, so an exact match means the client is resending the very
// same signed request, while any divergence (a different caller, or the
// same caller with regenerated keys) fails loudly with ErrGroupIDTaken
// instead of silently reporting success for a write that never happened.
//
// On a match, also returns the STORED RootGrantSortKey -- PR #142 round 2
// review found that a real retry re-signs a brand new grantSortKey on every
// attempt (unlike TrustAnchorSignature, which is deterministic and so
// matches byte-for-byte), so in.RootGrantSortKey on a retry addresses a
// GRANT# row that was never written. The caller must use this returned
// value, not in.RootGrantSortKey, when isRetry is true.
func (c *Client) isOwnGroupCreation(ctx context.Context, in CreateGroupInput) (string, bool, error) {
	metaOut, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + in.GroupID},
			"SK": &types.AttributeValueMemberS{Value: "META"},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return "", false, err
	}
	if metaOut.Item == nil {
		// The condition check just reported this item exists; a strongly
		// consistent read finding it gone a moment later would mean
		// something this package's model doesn't support (META is never
		// deleted) -- treat it as "not a match" rather than assume retry.
		return "", false, nil
	}
	var group models.Group
	if err := attributevalue.UnmarshalMap(metaOut.Item, &group); err != nil {
		return "", false, err
	}
	if group.CreatorUserID != in.CreatorUserID {
		// This group id belongs to a different creator entirely -- a
		// genuine conflict, not this caller's own write.
		return "", false, nil
	}
	if !bytes.Equal(group.TrustAnchorSignature, in.TrustAnchorSignature) {
		// Same creator, but the signed material has diverged -- not a safe
		// resend (isOwnGroupCreation's own doc comment).
		return "", false, nil
	}
	return group.RootGrantSortKey, true, nil
}

// batchGetItemLimit is DynamoDB's own hard cap on keys per BatchGetItem
// call -- ListGroups chunks its META reads to this size rather than relying
// on the SDK to do it, since exceeding it is a request-time
// ValidationException, not something the client silently retries around.
const batchGetItemLimit = 100

// maxUnprocessedKeysRetries and unprocessedKeysBaseDelay bound
// batchGetGroupMetas' UnprocessedKeys retry loop (PR #144 review): retrying
// immediately with no backoff is the pattern AWS's own BatchGetItem docs
// advise against, since UnprocessedKeys often means the request is already
// being throttled. Capped exponential backoff (base * 2^attempt, doubling
// each retry) gives a transient throttle room to clear; the attempt cap
// keeps this from being bounded only by ctx/the Lambda timeout, and a
// caller that exhausts it gets a real error instead of a request that
// silently hangs until the function times out.
const (
	maxUnprocessedKeysRetries = 5
	unprocessedKeysBaseDelay  = 50 * time.Millisecond
)

// errBatchGetGroupMetasExhausted is returned when
// maxUnprocessedKeysRetries is reached with keys still unprocessed --
// DynamoDB has been sufficiently overloaded that continuing to retry this
// specific call isn't the right response; a fresh top-level request should
// go through normal Lambda/client retry behavior instead.
var errBatchGetGroupMetasExhausted = errors.New("db: batchGetGroupMetas: exhausted retries with UnprocessedKeys still outstanding")

// ListGroups implements issue #35: the one GSI1 Query that makes "list my
// groups" a bounded read, plus the per-group META fan-out docs/DESIGN.md
// names as the actual cost ("Rendering a user's group list is the one
// hot-path read that fans out... one GSI1 Query... plus one GetItem per
// group"). Returns memberships and their groups as separate, equal-purpose
// slices rather than a joined struct -- the handler decides how to shape a
// response from them; this package stays a pure data-access layer, matching
// CreateGroup's own division of labor.
//
// A membership whose META has since vanished (a state this schema does not
// otherwise produce, since Group's own doc comment says "TTL never: a
// group's own record does not expire") is dropped from the returned groups
// slice rather than erroring the whole call -- the caller can detect this
// by comparing the lengths of the two returned slices, and the handler's
// own doc comment covers why a defensive read prefers a partial result over
// a hard failure here.
//
// A brand-new user with no memberships gets back two empty, non-nil slices,
// not an error -- this is the ordinary state for an account that has never
// joined or created a group, not an anomaly.
func (c *Client) ListGroups(ctx context.Context, userID string) ([]models.Membership, []models.Group, error) {
	memberships, err := c.queryMembershipsByUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	if len(memberships) == 0 {
		return []models.Membership{}, []models.Group{}, nil
	}

	groupsByID, err := c.batchGetGroupMetas(ctx, membershipGroupIDs(memberships))
	if err != nil {
		return nil, nil, err
	}

	groups := make([]models.Group, 0, len(memberships))
	kept := memberships[:0] // reuse the backing array; distinct slice header from memberships below
	for _, m := range memberships {
		if g, ok := groupsByID[groupIDFromMembership(m)]; ok {
			kept = append(kept, m)
			groups = append(groups, g)
		}
	}
	return kept, groups, nil
}

// queryMembershipsByUser runs the GSI1 Query for GSI1PK = "USER#<userID>" --
// the first Query in this codebase; db.go's own package doc comment
// ("Query construction is confined to this package") anticipates exactly
// this. Paginates on LastEvaluatedKey rather than assuming one page:
// DESIGN.md is explicit that a user's own membership count, not the table,
// is the number that actually grows here ("the bound is the number that
// actually grows in use"), so a heavy user's memberships could exceed one
// Query page in principle even though none exist yet to prove it in
// practice.
//
// The query is restricted to GSI1SK begins_with "GROUP#" -- GSI1PK
// "USER#<uuid>" is NOT membership-exclusive. Per DESIGN.md's data-model
// table, Invite (PK "INVITE#<iid>", GSI1PK "USER#<invitee>", GSI1SK
// "INVITE#<YYYY-MM-DD, UTC>#<rand>") and Join request (PK "GROUP#<gid>",
// GSI1PK "USER#<requester>", GSI1SK "REQ#...") rows share this same
// partition ("the three user reverse-lookups"). PR #144 round 2 review
// corrected an earlier version of this comment that wrongly attributed
// "SENT#<iid>" here -- that IS an Invite-related sort key, but it belongs
// to a different row entirely (the Invite row's PK "INVITE#<iid>" /
// "SENT#<iid>", the inviter's own copy, GSI1PK "USER#<inviter>"), which has
// no GSI1 entry at all (blank GSI1PK/GSI1SK in DESIGN.md's own table) and
// so was never actually relevant to this filter.
//
// Without this filter, a pending join request -- PK "GROUP#<gid>", GSI1SK
// "REQ#..." -- would unmarshal as a Membership: groupIDFromMembership still
// recovers a real gid from its PK, so the requester (not a member at all)
// would get that group back with Role == "" (PR #144 review, reproduced
// live against DynamoDB Local: a REQ# row put alongside a real group made a
// non-member requester's own ListGroups return it). An invite row's PK is
// "INVITE#<iid>", so it would instead miss the META BatchGetItem entirely
// (wasted RCUs, but not a correctness bug) -- begins_with saves that read
// too. Neither invites nor join requests are built yet (#38-40 are next in
// M4), so this was silent until those land; TestListGroupsExcludesNonMembershipRows
// pins it before that happens.
func (c *Client) queryMembershipsByUser(ctx context.Context, userID string) ([]models.Membership, error) {
	var memberships []models.Membership
	var startKey map[string]types.AttributeValue
	for {
		out, err := c.ddb.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(c.table),
			IndexName:              aws.String("GSI1"),
			KeyConditionExpression: aws.String("GSI1PK = :pk AND begins_with(GSI1SK, :sk)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: "USER#" + userID},
				":sk": &types.AttributeValueMemberS{Value: "GROUP#"},
			},
			ExclusiveStartKey: startKey,
		})
		if err != nil {
			return nil, err
		}
		var page []models.Membership
		if err := attributevalue.UnmarshalListOfMaps(out.Items, &page); err != nil {
			return nil, err
		}
		memberships = append(memberships, page...)
		if out.LastEvaluatedKey == nil {
			break
		}
		startKey = out.LastEvaluatedKey
	}
	return memberships, nil
}

// groupIDFromMembership recovers "gid" from a Membership's own PK
// ("GROUP#<gid>") rather than parsing GSI1SK -- both encode the same value
// (models.Membership's own doc comment: "GSI1SK is GROUP#<gid>"), and PK is
// the field every other Membership consumer in this package already reads
// directly.
func groupIDFromMembership(m models.Membership) string {
	return strings.TrimPrefix(m.PK, "GROUP#")
}

// membershipGroupIDs collects the distinct group ids ListGroups needs META
// for -- distinct because BatchGetItem rejects a request with duplicate
// keys, which a caller could otherwise never construct here (a Query over
// GSI1 cannot return two Membership items with the same PK for one user),
// but de-duplicating defensively costs nothing and removes any dependence
// on that invariant holding.
func membershipGroupIDs(memberships []models.Membership) []string {
	seen := make(map[string]bool, len(memberships))
	ids := make([]string, 0, len(memberships))
	for _, m := range memberships {
		gid := groupIDFromMembership(m)
		if !seen[gid] {
			seen[gid] = true
			ids = append(ids, gid)
		}
	}
	return ids
}

// batchGetGroupMetas reads every GROUP#<gid>/META item in groupIDs via
// BatchGetItem, chunked to batchGetItemLimit keys per call and retrying any
// UnprocessedKeys DynamoDB hands back -- BatchGetItem does not guarantee it
// serves every requested key in one round trip even for a well-formed
// request within the size limit (throttling can return a partial batch),
// so a caller that ignores UnprocessedKeys can silently drop a group from
// the list it renders. Returns a map keyed by group id rather than a slice,
// since ListGroups needs to look up by id to rejoin with the membership
// each META belongs to, and BatchGetItem does not preserve request order.
func (c *Client) batchGetGroupMetas(ctx context.Context, groupIDs []string) (map[string]models.Group, error) {
	keys := make([]map[string]types.AttributeValue, 0, len(groupIDs))
	for _, gid := range groupIDs {
		keys = append(keys, map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + gid},
			"SK": &types.AttributeValueMemberS{Value: "META"},
		})
	}
	items, err := c.batchGetItems(ctx, keys)
	if err != nil {
		return nil, err
	}
	result := make(map[string]models.Group, len(groupIDs))
	for _, item := range items {
		var group models.Group
		if err := attributevalue.UnmarshalMap(item, &group); err != nil {
			return nil, err
		}
		result[strings.TrimPrefix(group.PK, "GROUP#")] = group
	}
	return result, nil
}

// batchGetItems reads every key via BatchGetItem, chunked to
// batchGetItemLimit keys per call with the UnprocessedKeys retry/backoff
// described on maxUnprocessedKeysRetries. Keys must be distinct (BatchGetItem
// rejects duplicates); results come back in no particular order.
func (c *Client) batchGetItems(ctx context.Context, allKeys []map[string]types.AttributeValue) ([]map[string]types.AttributeValue, error) {
	var result []map[string]types.AttributeValue

	for start := 0; start < len(allKeys); start += batchGetItemLimit {
		end := min(start+batchGetItemLimit, len(allKeys))
		requestItems := map[string]types.KeysAndAttributes{
			c.table: {Keys: allKeys[start:end]},
		}
		for attempt := 0; len(requestItems) > 0; attempt++ {
			// The cap check comes BEFORE the sleep (PR #144 round 2 review):
			// checking after would mean the exhausting pass (attempt ==
			// maxUnprocessedKeysRetries) waits out a full delay -- 800ms at
			// the default constants -- for a BatchGetItem call it then never
			// makes, adding dead latency to the already-throttled path for
			// no benefit.
			if attempt >= maxUnprocessedKeysRetries {
				return nil, errBatchGetGroupMetasExhausted
			}
			if attempt > 0 {
				delay := unprocessedKeysBaseDelay * time.Duration(1<<(attempt-1))
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			out, err := c.ddb.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
				RequestItems: requestItems,
			})
			if err != nil {
				return nil, err
			}
			result = append(result, out.Responses[c.table]...)
			requestItems = out.UnprocessedKeys
		}
	}
	return result, nil
}

// GetGroup reads one group's META item, or nil if it does not exist.
func (c *Client) GetGroup(ctx context.Context, groupID string) (*models.Group, error) {
	out, err := c.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.table),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			"SK": &types.AttributeValueMemberS{Value: "META"},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("db: get group: %w", err)
	}
	if out.Item == nil {
		return nil, nil
	}
	var g models.Group
	if err := attributevalue.UnmarshalMap(out.Item, &g); err != nil {
		return nil, fmt.Errorf("db: unmarshal group: %w", err)
	}
	return &g, nil
}

// ErrNotGroupAdmin is returned by UpdateGroupSettings when the caller's own
// membership is missing or is not Admin at write time.
var ErrNotGroupAdmin = errors.New("db: caller is not a group admin")

// ErrGroupVersionConflict is returned by UpdateGroupSettings when another
// edit landed since the caller read the group.
var ErrGroupVersionConflict = errors.New("db: group version conflict")

// UpdateGroupSettingsInput is a full replacement of a group's editable
// settings. Exactly one of the plaintext or ciphertext pairs is set,
// matching the group's Visibility, which the handler has already checked.
type UpdateGroupSettingsInput struct {
	GroupID         string
	AdminUserID     string
	Visibility      string
	ExpectedVersion int64

	NamePlaintext         string
	DescriptionPlaintext  string
	NameCiphertext        *models.WrappedBlob
	DescriptionCiphertext *models.WrappedBlob
	NameGeneration        int64

	ExpirationDays int64
}

// UpdateGroupSettings replaces a group's name, description and expiration
// policy in one transaction: a ConditionCheck that the caller's membership
// is still Admin (so a demotion between the handler's read and this write
// cannot be raced), and an Update of META conditioned on Version. Revocation
// mode and visibility are never touched here.
//
// A public group's directory entry (GSI1SK) is rewritten with the name.
func (c *Client) UpdateGroupSettings(ctx context.Context, in UpdateGroupSettingsInput) error {
	names := map[string]string{
		"#exp": "ExpirationDays",
		"#ver": "Version",
	}
	values := map[string]types.AttributeValue{
		":exp":  &types.AttributeValueMemberN{Value: strconv.FormatInt(in.ExpirationDays, 10)},
		":next": &types.AttributeValueMemberN{Value: strconv.FormatInt(in.ExpectedVersion+1, 10)},
		":cur":  &types.AttributeValueMemberN{Value: strconv.FormatInt(in.ExpectedVersion, 10)},
	}
	set := []string{"#exp = :exp", "#ver = :next"}

	if in.Visibility == models.VisibilityPublic {
		names["#np"] = "NamePlaintext"
		names["#gsk"] = "GSI1SK"
		values[":np"] = &types.AttributeValueMemberS{Value: in.NamePlaintext}
		values[":gsk"] = &types.AttributeValueMemberS{Value: "NAME#" + in.NamePlaintext + "#" + in.GroupID}
		set = append(set, "#np = :np", "#gsk = :gsk")
		names["#dp"] = "DescriptionPlaintext"
		if in.DescriptionPlaintext != "" {
			values[":dp"] = &types.AttributeValueMemberS{Value: in.DescriptionPlaintext}
			set = append(set, "#dp = :dp")
		}
		// An empty description is stored as an absent attribute (omitempty
		// on Group), so it is REMOVEd below rather than set to "".
	} else {
		nc, err := attributevalue.Marshal(in.NameCiphertext)
		if err != nil {
			return err
		}
		dc, err := attributevalue.Marshal(in.DescriptionCiphertext)
		if err != nil {
			return err
		}
		names["#nc"] = "NameCiphertext"
		names["#dc"] = "DescriptionCiphertext"
		names["#ng"] = "NameGeneration"
		values[":nc"] = nc
		values[":dc"] = dc
		values[":ng"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(in.NameGeneration, 10)}
		set = append(set, "#nc = :nc", "#dc = :dc", "#ng = :ng")
	}

	updateExpr := "SET " + strings.Join(set, ", ")
	if in.Visibility == models.VisibilityPublic && in.DescriptionPlaintext == "" {
		updateExpr += " REMOVE #dp"
	}

	// A group that has never been edited has no Version attribute, which
	// reads as zero.
	versionCond := "#ver = :cur"
	if in.ExpectedVersion == 0 {
		versionCond = "(attribute_not_exists(#ver) OR #ver = :cur)"
	}

	const (
		adminCheckIndex = 0
		metaIndex       = 1
		rotationIndex   = 2
	)
	items := []types.TransactWriteItem{
		{ConditionCheck: &types.ConditionCheck{
			TableName: aws.String(c.table),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "GROUP#" + in.GroupID},
				"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + in.AdminUserID},
			},
			ConditionExpression:       aws.String("#role = :admin"),
			ExpressionAttributeNames:  map[string]string{"#role": "Role"},
			ExpressionAttributeValues: map[string]types.AttributeValue{":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin}},
		}},
		{Update: &types.Update{
			TableName: aws.String(c.table),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "GROUP#" + in.GroupID},
				"SK": &types.AttributeValueMemberS{Value: "META"},
			},
			UpdateExpression:          aws.String(updateExpr),
			ConditionExpression:       aws.String("attribute_exists(PK) AND " + versionCond),
			ExpressionAttributeNames:  names,
			ExpressionAttributeValues: values,
		}},
	}
	// A private group's name is encrypted under the writer's own generation.
	// While a rotation runs the remover is already at the new one, which
	// members not yet re-wrapped cannot read, and the stored NameGeneration
	// would then lock gen-0 admins out. So private edits wait for the marker
	// to clear; the check shares the transaction, so a rotation cannot start
	// between the handler's read and this write.
	if in.Visibility != models.VisibilityPublic {
		items = append(items, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
			TableName: aws.String(c.table),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "GROUP#" + in.GroupID},
				"SK": &types.AttributeValueMemberS{Value: RotationSortKey},
			},
			ConditionExpression: aws.String("attribute_not_exists(PK)"),
		}})
	}
	_, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if err != nil {
		if isConditionalCheckFailure(err, adminCheckIndex) {
			return ErrNotGroupAdmin
		}
		if in.Visibility != models.VisibilityPublic && isConditionalCheckFailure(err, rotationIndex) {
			return ErrRotationInProgress
		}
		if isConditionalCheckFailure(err, metaIndex) {
			return ErrGroupVersionConflict
		}
		return err
	}
	return nil
}
