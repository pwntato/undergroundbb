package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// postEditCiphertextLimit is the longest ciphertext an edit of a post may carry.
func (h *Handler) postEditCiphertextLimit() int {
	return h.postCiphertextLimit() + editedAtOverhead
}

// editPostRequest is the body of PUT /api/posts/{postId}: the post's new sealed
// text, signed again over the same sort key and the day it signs today. The
// sort key is the URL's, never the body's.
type editPostRequest struct {
	Generation int64  `json:"generation"`
	SignedDay  string `json:"signedDay"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Signature  string `json:"signature"`
}

func writePostGone(w http.ResponseWriter) {
	WriteErrorWithCode(w, http.StatusConflict, "this post is gone; reload and try again", "post_gone")
}

// editPost implements PUT /api/posts/{postId} (#45), editComment's rules for a
// post: the author only, only while it is not a tombstone, a fresh nonce
// (never one an earlier edition used), the freshness rules of a new post, and a
// signature under the caller's current key over the post's own sort key and
// the day signed TODAY. A post's sort key carries the day it was created, so
// the edit's day is stored on the row (SignedDay) and a reader uses it in
// place of the sort key's. A resend of exactly the stored bytes answers 200
// before any freshness check.
func (h *Handler) editPost(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	postID := r.PathValue("postId")
	groupID, postSortKey, ok := idgen.ParsePostID(postID)
	if !ok {
		postNotFound(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(h.postEditCiphertextLimit())*2+4096)
	var req editPostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	const fail = "could not edit the post"
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, fail)
		return
	}
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, fail)
		return
	}
	self, err := h.db.GetUserByIDConsistent(r.Context(), userID)
	if err != nil {
		WriteInternalError(w, r, err, fail)
		return
	}
	current, err := h.db.GroupCurrentGeneration(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, fail)
		return
	}
	marker, err := h.db.GetRotation(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, fail)
		return
	}
	post, err := h.db.GetPost(r.Context(), groupID, postSortKey)
	if err != nil {
		WriteInternalError(w, r, err, fail)
		return
	}
	now := time.Now()
	if caller == nil || group == nil || post == nil || db.PostExpired(post, now) {
		postNotFound(w)
		return
	}
	signedDay, err := time.Parse("2006-01-02", req.SignedDay)
	if err != nil || signedDay.Format("2006-01-02") != req.SignedDay {
		WriteError(w, http.StatusBadRequest, "signedDay: must be a UTC date, YYYY-MM-DD")
		return
	}
	nonce, err := decodeBase64Field(req.Nonce, crypto.NonceSize, crypto.NonceSize)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "nonce: "+err.Error())
		return
	}
	ciphertext, err := decodeBase64Field(req.Ciphertext, 0, h.postEditCiphertextLimit())
	if err != nil {
		WriteError(w, http.StatusBadRequest, "ciphertext: "+err.Error())
		return
	}
	if len(ciphertext) < postMinCiphertext {
		WriteError(w, http.StatusBadRequest, "ciphertext: too short to hold a post")
		return
	}
	sig, err := decodeBase64Field(req.Signature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "signature: "+err.Error())
		return
	}
	payload := crypto.SignedPayload(userID, groupID, postSortKey, uint64(req.Generation), req.SignedDay, ciphertext)
	if !crypto.Verify(self.SigningPublicKey, crypto.ContextPost, payload, sig) {
		WriteErrorWithCode(w, http.StatusBadRequest, "signature: does not verify against your current signing key", "bad_signature")
		return
	}
	if post.Deleted {
		writePostGone(w)
		return
	}
	if post.AuthorUserID != userID {
		WriteError(w, http.StatusForbidden, "only the author can edit a post")
		return
	}
	in := db.EditPostInput{
		GroupID: groupID, SortKey: postSortKey, AuthorUserID: userID, Generation: req.Generation,
		SignedDay: req.SignedDay, Nonce: nonce, Ciphertext: ciphertext, Signature: sig,
		PriorNonce: post.Nonce, AuthorKeyEpoch: self.KeyEpoch, MarkerPresent: marker != nil, Now: now,
	}
	if marker != nil {
		in.MarkerGeneration = marker.Generation
	}
	if in.Matches(post) {
		WriteJSON(w, http.StatusOK, map[string]string{"sortKey": postSortKey})
		return
	}
	if in.ReusesNonce(post) {
		WriteErrorWithCode(w, http.StatusBadRequest, "nonce: an edit must be sealed under a new nonce", "nonce_reused")
		return
	}
	if skew := time.Since(signedDay); skew < -grantDaySkewTolerance || skew > 24*time.Hour+grantDaySkewTolerance {
		WriteError(w, http.StatusBadRequest, "signedDay: not within tolerance of the current UTC day")
		return
	}
	postGeneration := current
	if marker != nil {
		postGeneration = marker.Generation - 1
	}
	if req.Generation != postGeneration {
		WriteErrorWithCode(w, http.StatusConflict, "generation: not the generation new posts use; reload and try again", "generation_stale")
		return
	}
	if caller.Generation < postGeneration {
		WriteErrorWithCode(w, http.StatusConflict, "your key for this group is behind; wait for the rotation to reach you", "member_behind")
		return
	}
	if caller.WrapEpoch < self.KeyEpoch {
		WriteErrorWithCode(w, http.StatusConflict, "your keys changed and an admin has not approved them for this group yet", "member_dormant")
		return
	}
	err = h.db.EditPost(r.Context(), in)
	switch {
	case err == nil:
		WriteJSON(w, http.StatusOK, map[string]string{"sortKey": postSortKey})
	case errors.Is(err, db.ErrPostGone):
		writePostGone(w)
	case errors.Is(err, db.ErrPostMarkerChanged):
		WriteErrorWithCode(w, http.StatusConflict, "the group's key rotation changed; reload and try again", "generation_stale")
	case errors.Is(err, db.ErrPostMemberChanged):
		WriteErrorWithCode(w, http.StatusConflict, "your membership changed; reload and try again", "membership_changed")
	case errors.Is(err, db.ErrWrapEpochStale):
		WriteErrorWithCode(w, http.StatusConflict, "your keys were rotated by another request; reload and try again", "key_epoch_stale")
	case errors.Is(err, db.ErrRoleChangeConflict):
		WriteErrorWithCode(w, http.StatusConflict, "another change was in progress; retry", "conflict_retry")
	default:
		WriteInternalError(w, r, err, fail)
	}
}

// deletePost implements DELETE /api/posts/{postId} (#45): the post's author or
// an admin of its group turns it into a tombstone (see db.DeletePost). Its
// comments stay readable; it takes no new ones. Repeating it is the same 204.
// It needs membership and a live post but no key. Deletion is advisory: any
// member may have kept a copy.
func (h *Handler) deletePost(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	postID := r.PathValue("postId")
	groupID, postSortKey, ok := idgen.ParsePostID(postID)
	if !ok {
		postNotFound(w)
		return
	}
	const fail = "could not delete the post"
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, fail)
		return
	}
	post, err := h.db.GetPost(r.Context(), groupID, postSortKey)
	if err != nil {
		WriteInternalError(w, r, err, fail)
		return
	}
	if caller == nil || post == nil || db.PostExpired(post, time.Now()) {
		postNotFound(w)
		return
	}
	if post.AuthorUserID != userID && caller.Role != models.RoleAdmin {
		WriteError(w, http.StatusForbidden, "only the author or an admin can delete a post")
		return
	}
	if err := h.db.DeletePost(r.Context(), groupID, postSortKey, postID); err != nil {
		if errors.Is(err, db.ErrPostGone) {
			postNotFound(w)
			return
		}
		WriteInternalError(w, r, err, fail)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
