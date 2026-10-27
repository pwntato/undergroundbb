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

const maxRewrapBodyBytes = 64 * 1024

// rewrapMembersRequest is the body of PUT /api/groups/{groupId}/rotation/members:
// up to db.MaxRewrapBatch members' entry points wrapped for the rotation's
// generation. The client minted the key and does the wrapping; the server only
// stores. Resume is state-driven (members whose generation is behind the
// marker's), so there is no cursor here to get wrong.
type rewrapMembersRequest struct {
	Generation int64            `json:"generation"`
	Wraps      []memberRewrapIn `json:"wraps"`
}

type memberRewrapIn struct {
	UserID     string     `json:"userId"`
	WrappedKey wrappedKey `json:"wrappedKey"`
	// WrapEpoch is the recipient's keyEpoch (as served by GET /api/users) the
	// key was wrapped to; 0 for a user who has never rotated. The server checks
	// it is their current epoch, in the same transaction as the write (#62).
	WrapEpoch uint64 `json:"wrapEpoch"`
}

// rewrapMembers implements PUT /api/groups/{groupId}/rotation/members. Admin
// only, and the caller must already hold the rotation's generation (their own
// entry point is at it), since that is the only way to be wrapping its key.
// All-or-nothing: a member who left or moved on fails the batch (409
// member_changed) and the client re-lists and resends.
func (h *Handler) rewrapMembers(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	groupID := r.PathValue("groupId")
	if !idgen.ValidUUID(groupID) {
		groupNotFound(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRewrapBodyBytes)
	var req rewrapMembersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if len(req.Wraps) == 0 || len(req.Wraps) > db.MaxRewrapBatch {
		WriteError(w, http.StatusBadRequest, fmt.Sprintf("wraps: must hold between 1 and %d entries", db.MaxRewrapBatch))
		return
	}
	in := db.RewrapMembersInput{GroupID: groupID, CallerUserID: userID, Generation: req.Generation}
	seen := map[string]bool{}
	for _, w2 := range req.Wraps {
		if !idgen.ValidUUID(w2.UserID) {
			WriteError(w, http.StatusBadRequest, "wraps: malformed userId")
			return
		}
		if w2.UserID == userID || seen[w2.UserID] {
			WriteError(w, http.StatusBadRequest, "wraps: duplicate userId, or the caller's own (already at the generation)")
			return
		}
		seen[w2.UserID] = true
		wk, err := decodeWrappedKey(w2.WrappedKey)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "wraps: wrappedKey: "+err.Error())
			return
		}
		in.Wraps = append(in.Wraps, db.MemberRewrap{UserID: w2.UserID, Wrapped: wk, WrapEpoch: w2.WrapEpoch})
	}

	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not re-wrap members")
		return
	}
	if caller == nil {
		groupNotFound(w)
		return
	}
	if caller.Role != models.RoleAdmin {
		WriteError(w, http.StatusForbidden, "only a group admin can re-wrap members")
		return
	}

	if !h.writeRotationErr(w, r, h.db.RewrapMembers(r.Context(), in), "could not re-wrap members") {
		w.WriteHeader(http.StatusNoContent)
	}
}

type completeRotationRequest struct {
	Generation int64 `json:"generation"`
}

// completeRotation implements POST /api/groups/{groupId}/rotation/complete:
// clears the marker once every member's entry point is at its generation.
// 409 rotation_not_active also covers "someone already finished it", which the
// client treats as done.
func (h *Handler) completeRotation(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	groupID := r.PathValue("groupId")
	if !idgen.ValidUUID(groupID) {
		groupNotFound(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxChangeRoleBodyBytes)
	var req completeRotationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not complete rotation")
		return
	}
	if caller == nil {
		groupNotFound(w)
		return
	}
	if caller.Role != models.RoleAdmin {
		WriteError(w, http.StatusForbidden, "only a group admin can complete a rotation")
		return
	}
	if !h.writeRotationErr(w, r, h.db.CompleteRotation(r.Context(), groupID, userID, req.Generation), "could not complete rotation") {
		w.WriteHeader(http.StatusNoContent)
	}
}

// takeOverRotationRequest is the same material a removal's rotation carries,
// minted by the calling admin in place of the bare marker a leaver left.
type takeOverRotationRequest struct {
	Generation int64       `json:"generation"`
	Link       wrappedBlob `json:"link"`
	// WrappedKey is the new key wrapped for the caller (their only copy).
	WrappedKey     wrappedKey `json:"wrappedKey"`
	StartSignature string     `json:"startSignature"`
	wrapRecordFields
}

// takeOverRotation implements POST /api/groups/{groupId}/rotation/takeover
// (#178): an admin at the leaver's generation turns the marker a leaving member
// wrote into a rotation the admin mints. The leaver only signed the start, so
// they never hold the new key. Refused (409 rotation_not_active) when the
// running rotation is not an unclaimed leaver's: another admin got there first,
// it finished, or it was a removal's.
func (h *Handler) takeOverRotation(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	groupID := r.PathValue("groupId")
	if !idgen.ValidUUID(groupID) {
		groupNotFound(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRewrapBodyBytes)
	var req takeOverRotationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not take over the rotation")
		return
	}
	if caller == nil {
		groupNotFound(w)
		return
	}
	if caller.Role != models.RoleAdmin {
		WriteError(w, http.StatusForbidden, "only a group admin can take over a rotation")
		return
	}
	marker, err := h.db.GetRotation(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not take over the rotation")
		return
	}
	if marker == nil || marker.RemovedUserID == "" || marker.StartedBy != marker.RemovedUserID || marker.Generation != caller.Generation+1 {
		h.writeRotationErr(w, r, db.ErrRotationNotActive, "could not take over the rotation")
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
	wrapped, err := decodeWrappedKey(req.WrappedKey)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "wrappedKey: "+err.Error())
		return
	}
	sig, keyEpoch, rej, msg := h.verifyRotationStart(r.Context(), userID, groupID, marker.RemovedUserID, req.StartSignature, caller.Generation)
	if msg != "" {
		if rej.code == "" {
			WriteError(w, rej.status, msg)
		} else {
			WriteErrorWithCode(w, rej.status, msg, rej.code)
		}
		return
	}
	rec, problem, err := h.wrapRecord(r, req.wrapRecordFields, groupID, userID, userID, caller.Generation+1, keyEpoch, crypto.RekeyReasonSelf)
	if err != nil {
		WriteInternalError(w, r, err, "could not take over the rotation")
		return
	}
	if problem != nil {
		problem.write(w)
		return
	}
	in := db.TakeOverLeaveRotationInput{
		GroupID:           groupID,
		CallerUserID:      userID,
		LeaverUserID:      marker.RemovedUserID,
		CurrentGeneration: caller.Generation,
		Link:              link,
		CallerWrappedKey:  wrapped,
		CallerKeyEpoch:    keyEpoch,
		StartSignature:    sig,
		WrapRecord:        rec,
	}
	err = h.db.TakeOverLeaveRotation(r.Context(), in)
	if errors.Is(err, db.ErrWrapEpochStale) {
		WriteErrorWithCode(w, http.StatusConflict, "your keys were rotated by another request; reload and try again", "key_epoch_stale")
		return
	}
	if !h.writeRotationErr(w, r, err, "could not take over the rotation") {
		w.WriteHeader(http.StatusNoContent)
	}
}

// writeRotationErr maps the shared rotation errors; it reports whether it
// wrote a response (true for any non-nil err).
func (h *Handler) writeRotationErr(w http.ResponseWriter, r *http.Request, err error, fallback string) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, db.ErrRotationNotActive):
		WriteErrorWithCode(w, http.StatusConflict, "no key rotation for that generation is in progress", "rotation_not_active")
	case errors.Is(err, db.ErrRewrapCallerBehind):
		WriteErrorWithCode(w, http.StatusConflict, "your own key is not at the rotation's generation; reload", "rotation_caller_behind")
	case errors.Is(err, db.ErrRewrapMemberChanged):
		WriteErrorWithCode(w, http.StatusConflict, "a member in the batch left or changed; re-list members and resend", "member_changed")
	case errors.Is(err, db.ErrRewrapMemberDormant):
		WriteErrorWithCode(w, http.StatusConflict, "a member in the batch rotated their keys; a key rotation does not wrap to them until an admin approves the change", "member_dormant")
	case errors.Is(err, db.ErrWrapEpochStale):
		WriteErrorWithCode(w, http.StatusConflict, "a member's keys changed since you read them; re-read their keys and wrap again", "wrap_epoch_stale")
	case errors.Is(err, db.ErrMembersBehind):
		WriteErrorWithCode(w, http.StatusConflict, "some members are not yet on the new key generation", "members_behind")
	case errors.Is(err, db.ErrRoleChangeConflict):
		WriteErrorWithCode(w, http.StatusConflict, "another change was in progress; retry", "conflict_retry")
	default:
		WriteInternalError(w, r, err, fallback)
	}
	return true
}

// selfRekeyRequest is the body of POST /api/groups/{groupId}/rotation/rekey.
type selfRekeyRequest struct {
	Generation int64       `json:"generation"`
	Link       wrappedBlob `json:"link"`
	// WrappedKey is the new key wrapped for the caller (their only copy).
	WrappedKey     wrappedKey `json:"wrappedKey"`
	StartSignature string     `json:"startSignature"`
	wrapRecordFields
}

// selfRekey implements POST /api/groups/{groupId}/rotation/rekey (#62): an
// admin who rotated their account keys starts the rotation that brings their
// own entry point to the new key, from the group key their handoff row holds.
// It removes no one. The start consumes the handoff row in its own transaction;
// a row that is missing, names another key, holds another generation or
// belongs to a group that has moved past it is 409 handoff_stale, which tells
// the client to delete it. Only a Rotating group
// has a rotation to start.
func (h *Handler) selfRekey(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	groupID := r.PathValue("groupId")
	if !idgen.ValidUUID(groupID) {
		groupNotFound(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRewrapBodyBytes)
	var req selfRekeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	// Same rule as getGroup: every read happens before any 404 branch.
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not start the re-key")
		return
	}
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not start the re-key")
		return
	}
	if caller == nil || group == nil {
		groupNotFound(w)
		return
	}
	if caller.Role != models.RoleAdmin {
		WriteError(w, http.StatusForbidden, "only a group admin can re-key")
		return
	}
	if group.GroupType == "dm" || group.RevocationMode == models.RevocationOpen {
		WriteErrorWithCode(w, http.StatusBadRequest, "this group does not rotate keys", "rotation_not_applicable")
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
	wrapped, err := decodeWrappedKey(req.WrappedKey)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "wrappedKey: "+err.Error())
		return
	}
	sig, err := decodeBase64Field(req.StartSignature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		WriteErrorWithCode(w, http.StatusBadRequest, "startSignature: "+err.Error(), "bad_signature")
		return
	}
	// The strongly consistent read: the key epoch and the wrapping key below
	// are re-checked by the transaction, but a stale read would send an honest
	// client a spurious refusal.
	self, err := h.db.GetUserByIDConsistent(r.Context(), userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not start the re-key")
		return
	}
	payload := crypto.RotationRekeyPayload(groupID, userID, userID, req.Generation, crypto.RekeyReasonSelf)
	if !crypto.Verify(self.SigningPublicKey, crypto.ContextRotationRekey, payload, sig) {
		WriteErrorWithCode(w, http.StatusBadRequest, "startSignature: does not verify against the caller's current signing key", "bad_signature")
		return
	}
	rec, problem, err := h.wrapRecord(r, req.wrapRecordFields, groupID, userID, userID, req.Generation, self.KeyEpoch, crypto.RekeyReasonSelf)
	if err != nil {
		WriteInternalError(w, r, err, "could not start the re-key")
		return
	}
	if problem != nil {
		problem.write(w)
		return
	}
	err = h.db.SelfRekey(r.Context(), db.SelfRekeyInput{
		GroupID:           groupID,
		CallerUserID:      userID,
		CurrentGeneration: caller.Generation,
		Link:              link,
		CallerWrappedKey:  wrapped,
		CallerKeyEpoch:    self.KeyEpoch,
		CallerWrappingKey: self.WrappingPublicKey,
		Reason:            crypto.RekeyReasonSelf,
		StartSignature:    sig,
		WrapRecord:        rec,
	})
	switch {
	case errors.Is(err, db.ErrHandoffStale):
		WriteErrorWithCode(w, http.StatusConflict, "your handoff for this group is missing or out of date; delete it", "handoff_stale")
	case errors.Is(err, db.ErrRotationInProgress):
		WriteErrorWithCode(w, http.StatusConflict, "a key rotation is already in progress; finish it first", "rotation_in_progress")
	case errors.Is(err, db.ErrWrapEpochStale):
		WriteErrorWithCode(w, http.StatusConflict, "your keys were rotated by another request; reload and try again", "key_epoch_stale")
	default:
		if !h.writeRotationErr(w, r, err, "could not start the re-key") {
			w.WriteHeader(http.StatusNoContent)
		}
	}
}
