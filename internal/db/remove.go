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

// RotationSortKey is the SK of a group's rotation marker.
const RotationSortKey = "ROTATION"

// ErrRotationInProgress is returned when a removal would start a rotation but
// one is already running (its marker exists), or its generation was already
// minted. A second removal waits for the first rotation to finish; stacking
// them would need a rotation that targets a generation nobody holds yet.
var ErrRotationInProgress = errors.New("db: a key rotation is already in progress")

// ErrRotationStaleGeneration is returned when no rotation is running but the
// generation the removal would mint already has its chain link: the remover's
// own entry point is behind the group's (an invite wrapped at the old
// generation and accepted after the rotation finished). The link is never
// overwritten; the admin has to be re-wrapped at the current generation first.
var ErrRotationStaleGeneration = errors.New("db: the remover's key generation is behind the group's")

// GenKeySortKey is the GENKEY# sort key for generation n: zero-padded to six
// digits like every numeric sort-key component (docs/DESIGN.md).
func GenKeySortKey(n int64) string { return fmt.Sprintf("GENKEY#%06d", n) }

// ParseGenKeySortKey is GenKeySortKey's inverse: the generation a GENKEY#
// sort key names.
func ParseGenKeySortKey(sk string) (int64, error) {
	digits, ok := strings.CutPrefix(sk, "GENKEY#")
	if !ok {
		return 0, fmt.Errorf("db: %q is not a generation key sort key", sk)
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("db: malformed generation key sort key %q: %w", sk, err)
	}
	return n, nil
}

// RemoveMemberInput is one admin removing another member -- issue #58.
type RemoveMemberInput struct {
	GroupID       string
	SubjectUserID string
	// SubjectRole is the role the caller saw the subject hold; the delete is
	// conditioned on it so a role change in between is a conflict, not a
	// removal that signs the wrong demotion (or none).
	SubjectRole string

	RemoverUserID string
	// RemoverHasStoredGrant says whether the remover's MEMBER# row records
	// RemoverGrantRef (Membership.GrantSortKey); when false the ref came from
	// the Group.RootGrantSortKey fallback and the row must still lack it.
	RemoverHasStoredGrant bool
	RemoverGrantRef       string

	// Demotion is the remover's signed grant of "member" to the subject,
	// appended in the same transaction. Required exactly when SubjectRole is
	// admin or ambassador (nil otherwise): a removed admin's last grant would
	// otherwise still say admin, and a later rejoin (baseline member) would
	// read as a forged demotion. Because the REMOVER signs it, nothing here
	// needs the removed admin's cooperation, which is what an involuntary
	// removal cannot have.
	Demotion *RemoveDemotion

	// Rotation is required exactly when the group is Rotating (nil for Open):
	// removal there starts a key rotation in the same transaction.
	Rotation *RemoveRotation
}

// RemoveRotation is what a Rotating-group removal commits besides the delete.
// The client minted the new group key, so everything here arrives wrapped.
type RemoveRotation struct {
	// CurrentGeneration is the generation the remover's own entry point is at;
	// the rotation goes to CurrentGeneration+1. Every conditional below hangs
	// on it, so a stale view is a conflict, not a skipped generation.
	CurrentGeneration int64
	// Link is generation CurrentGeneration's key wrapped under the new one,
	// stored as GENKEY#<CurrentGeneration>. Committing it here, in the same
	// transaction as the marker and the remover's own re-wrap, means no
	// membership can point at the new generation without its chain link.
	Link models.WrappedBlob
	// RemoverWrappedKey re-wraps the new key for the remover, who then holds
	// it durably: it is the only copy of the minted key anywhere, so a resumed
	// rotation re-uses it rather than minting a second one.
	RemoverWrappedKey models.WrappedKey
	// StartSignature is the remover's signature over crypto.RotationStartPayload
	// for (group, remover, subject, CurrentGeneration+1), stored on the marker
	// so a resuming admin can tell whom this rotation removed (#178).
	StartSignature []byte
}

// RemoveDemotion is the signed grant a removal appends for an elevated subject.
type RemoveDemotion struct {
	GrantSortKey     string
	SigningPublicKey []byte // the remover's key, as served at write time
	Signature        []byte
}

// RemoveMember deletes the subject's membership in one transaction:
// (0) the remover is still Admin and still on the grant they signed against,
// (1) the subject still holds SubjectRole and is deleted, (2) for an elevated
// subject, the demotion grant is new. Grants the subject signed or received
// stay; history is append-only. The subject's own outstanding invites are
// removed afterwards, as on leaving.
//
// For an Open group that is the whole of removal (docs/DESIGN.md, "Revocation
// mode"). For a Rotating group (in.Rotation != nil) the same transaction also
// starts the rotation: the ROTATION marker, the GENKEY# link for the old
// generation, and the remover's own entry point at the new one. Re-wrapping
// every other member is the client's resumable job, not done here.
func (c *Client) RemoveMember(ctx context.Context, in RemoveMemberInput) error {
	elevated := in.SubjectRole != models.RoleMember
	if elevated != (in.Demotion != nil) {
		return ErrRoleChangeConflict
	}

	rotating := in.Rotation != nil
	removerCond := "#role = :admin AND attribute_not_exists(#gsk)"
	removerValues := map[string]types.AttributeValue{
		":admin": &types.AttributeValueMemberS{Value: models.RoleAdmin},
	}
	if in.RemoverHasStoredGrant {
		removerCond = "#role = :admin AND #gsk = :ref"
		removerValues[":ref"] = &types.AttributeValueMemberS{Value: in.RemoverGrantRef}
	}

	const (
		removerIndex = 0
		deleteIndex  = 1
		grantIndex   = 2
	)
	removerItem := types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName:                 aws.String(c.table),
		Key:                       memberKey(in.GroupID, in.RemoverUserID),
		ConditionExpression:       aws.String(removerCond),
		ExpressionAttributeNames:  map[string]string{"#role": "Role", "#gsk": "GrantSortKey"},
		ExpressionAttributeValues: removerValues,
	}}
	if rotating {
		// The remover's entry point moves to the new generation, conditioned
		// on still being at the one the request was built against.
		wrapped, err := attributevalue.Marshal(in.Rotation.RemoverWrappedKey)
		if err != nil {
			return err
		}
		removerValues[":cur"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(in.Rotation.CurrentGeneration, 10)}
		removerValues[":next"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(in.Rotation.CurrentGeneration+1, 10)}
		removerValues[":wrapped"] = wrapped
		removerItem = types.TransactWriteItem{Update: &types.Update{
			TableName:                 aws.String(c.table),
			Key:                       memberKey(in.GroupID, in.RemoverUserID),
			ConditionExpression:       aws.String(removerCond + " AND #gen = :cur"),
			UpdateExpression:          aws.String("SET #gen = :next, #wrapped = :wrapped"),
			ExpressionAttributeNames:  map[string]string{"#role": "Role", "#gsk": "GrantSortKey", "#gen": "Generation", "#wrapped": "WrappedGroupKey"},
			ExpressionAttributeValues: removerValues,
		}}
	}
	items := []types.TransactWriteItem{
		removerItem,
		{Delete: &types.Delete{
			TableName:                aws.String(c.table),
			Key:                      memberKey(in.GroupID, in.SubjectUserID),
			ConditionExpression:      aws.String("#role = :old"),
			ExpressionAttributeNames: map[string]string{"#role": "Role"},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":old": &types.AttributeValueMemberS{Value: in.SubjectRole},
			},
		}},
	}
	if elevated {
		grantItem, err := attributevalue.MarshalMap(models.RoleGrant{
			Record: models.Record{
				PK:   "GROUP#" + in.GroupID,
				SK:   in.Demotion.GrantSortKey,
				Type: "RoleGrant",
			},
			SubjectUserID:           in.SubjectUserID,
			GrantedRole:             models.RoleMember,
			GrantorUserID:           in.RemoverUserID,
			GrantorSigningPublicKey: in.Demotion.SigningPublicKey,
			GrantorGrantRef:         in.RemoverGrantRef,
			Signature:               in.Demotion.Signature,
		})
		if err != nil {
			return err
		}
		items = append(items, types.TransactWriteItem{Put: &types.Put{
			TableName:           aws.String(c.table),
			Item:                grantItem,
			ConditionExpression: aws.String("attribute_not_exists(PK)"),
		}})
	}

	rotationIndex := -1
	if rotating {
		now := time.Now().UTC().Format(time.RFC3339)
		link, err := attributevalue.MarshalMap(models.GenerationKey{
			Record: models.Record{
				PK:        "GROUP#" + in.GroupID,
				SK:        GenKeySortKey(in.Rotation.CurrentGeneration),
				Type:      "GenerationKey",
				CreatedAt: now,
			},
			Wrapped: in.Rotation.Link,
		})
		if err != nil {
			return err
		}
		marker, err := attributevalue.MarshalMap(models.Rotation{
			Record: models.Record{
				PK:        "GROUP#" + in.GroupID,
				SK:        RotationSortKey,
				Type:      "Rotation",
				CreatedAt: now,
			},
			Generation: in.Rotation.CurrentGeneration + 1,
			StartedAt:  now,
			StartedBy:  in.RemoverUserID,

			RemovedUserID:  in.SubjectUserID,
			StartSignature: in.Rotation.StartSignature,
		})
		if err != nil {
			return err
		}
		// The marker's condition is the "one rotation at a time" rule; the
		// link's is the guard that a generation is only ever minted once.
		rotationIndex = len(items)
		items = append(items,
			types.TransactWriteItem{Put: &types.Put{
				TableName:           aws.String(c.table),
				Item:                marker,
				ConditionExpression: aws.String("attribute_not_exists(PK)"),
			}},
			types.TransactWriteItem{Put: &types.Put{
				TableName:           aws.String(c.table),
				Item:                link,
				ConditionExpression: aws.String("attribute_not_exists(PK)"),
			}},
		)
	}

	// The removed member's admission record goes with their membership (#178);
	// see admissionDelete. Last, so no condition-check index above shifts.
	items = append(items, admissionDelete(c.table, in.GroupID, in.SubjectUserID))
	if _, err := c.ddb.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items}); err != nil {
		switch {
		case rotating && isConditionalCheckFailure(err, rotationIndex):
			return ErrRotationInProgress
		case rotating && isConditionalCheckFailure(err, rotationIndex+1):
			return ErrRotationStaleGeneration
		case isConditionalCheckFailure(err, removerIndex):
			return ErrGrantorChanged
		case isConditionalCheckFailure(err, deleteIndex):
			return ErrSubjectRoleChanged
		case elevated && isConditionalCheckFailure(err, grantIndex):
			return ErrGrantKeyTaken
		case isTransactionConflict(err):
			return ErrRoleChangeConflict
		}
		return err
	}
	if err := c.deleteOwnInvites(ctx, in.GroupID, in.SubjectUserID); err != nil {
		return fmt.Errorf("%w: %v", ErrInviteCleanupIncomplete, err)
	}
	return nil
}
