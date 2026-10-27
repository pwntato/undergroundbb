package db

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// WrapRecord is the wrapper's signed statement of who set a member's entry
// (#280, docs/DESIGN.md, "Who wrapped a member's entry"). The handler has
// already verified Signature under the wrapper's current signing key over
// crypto.WrapRecordPayload for the generation and epoch this write sets; like
// every other signature this package stores, db does not check it.
type WrapRecord struct {
	WrapperUserID string
	// Reason is "self" or "approval", fixed by the endpoint.
	Reason string
	// Day is the signed UTC date (YYYY-MM-DD).
	Day       string
	Signature []byte
}

// applyWrapRecord extends a member-entry update that sets WrapEpoch with the
// record for that wrap, or, with none, removes any record an earlier wrap left,
// so a write by a client that signs nothing does not sit beside a stale one.
// Readers rebuild the signed payload from the entry's own generation and
// epoch, so this is hygiene, not what makes a stale record harmless.
func applyWrapRecord(u *types.Update, rec *WrapRecord) {
	if rec == nil {
		u.UpdateExpression = aws.String(*u.UpdateExpression + " REMOVE WrapperUserID, WrapReason, WrapDay, WrapSignature")
		return
	}
	u.UpdateExpression = aws.String(*u.UpdateExpression + ", WrapperUserID = :wru, WrapReason = :wrr, WrapDay = :wrd, WrapSignature = :wrs")
	u.ExpressionAttributeValues[":wru"] = &types.AttributeValueMemberS{Value: rec.WrapperUserID}
	u.ExpressionAttributeValues[":wrr"] = &types.AttributeValueMemberS{Value: rec.Reason}
	u.ExpressionAttributeValues[":wrd"] = &types.AttributeValueMemberS{Value: rec.Day}
	u.ExpressionAttributeValues[":wrs"] = &types.AttributeValueMemberB{Value: rec.Signature}
}
