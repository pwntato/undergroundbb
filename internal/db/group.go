package db

import (
	"bytes"
	"context"
	"errors"
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
	const groupItemIndex = 0

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
		},
	})
	if err != nil {
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
