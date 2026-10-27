package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// approveRekeyRequest is the body of POST /api/groups/{groupId}/rotation/approve/{userId}.
type approveRekeyRequest struct {
	Generation int64       `json:"generation"`
	Link       wrappedBlob `json:"link"`
	// WrappedKey is the new key wrapped for the admin (their copy).
	WrappedKey wrappedKey `json:"wrappedKey"`
	// MemberWrappedKey is the new key wrapped to the member's new key, whose
	// keyEpoch the server checks is still current.
	MemberWrappedKey wrappedKey `json:"memberWrappedKey"`
	MemberKeyEpoch   uint64     `json:"memberKeyEpoch"`
	StartSignature   string     `json:"startSignature"`
	wrapRecordFields
}

// approveRekey implements POST /api/groups/{groupId}/rotation/approve/{userId}
// (#62): an admin approves a dormant member's new keys by starting a rotation
// that removes no one, when the member's entry is still at the admin's
// generation (the old keys hold the current key, so approving must mint). The
// start writes the member's entry at the new generation in its own
// transaction, since the ordinary re-wrap refuses a dormant member. The reason
// is fixed to `approval` here and signed. Admin only; a member behind the
// generation is 409 rekey_not_required, which sends the admin to
// POST /rewrap/{uid}.
func (h *Handler) approveRekey(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	groupID := r.PathValue("groupId")
	memberID := r.PathValue("userId")
	if !idgen.ValidUUID(groupID) {
		groupNotFound(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRewrapBodyBytes)
	var req approveRekeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	// Every read happens before any 404 branch, as in selfRekey.
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not approve the key change")
		return
	}
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not approve the key change")
		return
	}
	if caller == nil || group == nil {
		groupNotFound(w)
		return
	}
	if caller.Role != models.RoleAdmin {
		WriteError(w, http.StatusForbidden, "only a group admin can approve with a re-key")
		return
	}
	if group.GroupType == "dm" || group.RevocationMode == models.RevocationOpen {
		WriteErrorWithCode(w, http.StatusBadRequest, "this group does not rotate keys", "rotation_not_applicable")
		return
	}
	if !idgen.ValidUUID(memberID) {
		WriteError(w, http.StatusNotFound, "member not found")
		return
	}
	if memberID == userID {
		WriteError(w, http.StatusBadRequest, "you cannot approve your own key change")
		return
	}
	if req.Generation != caller.Generation+1 {
		WriteError(w, http.StatusBadRequest, fmt.Sprintf("generation: must be %d (one past your own key generation)", caller.Generation+1))
		return
	}
	link, err := decodeWrappedBlob(req.Link)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "link: "+err.Error())
		return
	}
	adminWrapped, err := decodeWrappedKey(req.WrappedKey)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "wrappedKey: "+err.Error())
		return
	}
	memberWrapped, err := decodeWrappedKey(req.MemberWrappedKey)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "memberWrappedKey: "+err.Error())
		return
	}
	sig, err := decodeBase64Field(req.StartSignature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		WriteErrorWithCode(w, http.StatusBadRequest, "startSignature: "+err.Error(), "bad_signature")
		return
	}
	self, err := h.db.GetUserByIDConsistent(r.Context(), userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not approve the key change")
		return
	}
	payload := crypto.RotationRekeyPayload(groupID, userID, memberID, req.Generation, crypto.RekeyReasonApproval)
	if !crypto.Verify(self.SigningPublicKey, crypto.ContextRotationRekey, payload, sig) {
		WriteErrorWithCode(w, http.StatusBadRequest, "startSignature: does not verify against the caller's current signing key", "bad_signature")
		return
	}
	// The member's entry is written at the generation one past the admin's.
	rec, problem, err := h.wrapRecord(r, req.wrapRecordFields, groupID, userID, memberID, caller.Generation+1, req.MemberKeyEpoch, crypto.RekeyReasonApproval)
	if err != nil {
		WriteInternalError(w, r, err, "could not approve the key change")
		return
	}
	if problem != nil {
		problem.write(w)
		return
	}
	err = h.db.ApproveRekey(r.Context(), db.ApproveRekeyInput{
		GroupID:           groupID,
		AdminUserID:       userID,
		MemberUserID:      memberID,
		CurrentGeneration: caller.Generation,
		Link:              link,
		AdminWrappedKey:   adminWrapped,
		AdminKeyEpoch:     self.KeyEpoch,
		MemberWrappedKey:  memberWrapped,
		MemberKeyEpoch:    req.MemberKeyEpoch,
		Reason:            crypto.RekeyReasonApproval,
		StartSignature:    sig,
		WrapRecord:        rec,
	})
	switch {
	case errors.Is(err, db.ErrRotationInProgress):
		WriteErrorWithCode(w, http.StatusConflict, "a key rotation is already in progress; finish it first", "rotation_in_progress")
	case errors.Is(err, db.ErrCallerKeyEpochStale):
		WriteErrorWithCode(w, http.StatusConflict, "your keys were rotated by another request; reload and try again", "key_epoch_stale")
	case errors.Is(err, db.ErrRekeyNotRequired):
		WriteErrorWithCode(w, http.StatusConflict, "the member's entry is behind the current generation; approve with a plain wrap instead", "rekey_not_required")
	case errors.Is(err, db.ErrMemberNotDormant):
		WriteErrorWithCode(w, http.StatusConflict, "the member's entry is already wrapped to their current key", "member_not_dormant")
	case errors.Is(err, db.ErrRewrapMemberChanged):
		WriteError(w, http.StatusNotFound, "member not found")
	default:
		if !h.writeRotationErr(w, r, err, "could not approve the key change") {
			w.WriteHeader(http.StatusNoContent)
		}
	}
}
