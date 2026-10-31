package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// editCommentRequest is the body of PUT /api/posts/{postId}/comments/{path}:
// the comment's new sealed text, signed again over the same sort key. The path
// is the URL's, never the body's.
type editCommentRequest struct {
	Generation int64  `json:"generation"`
	SignedDay  string `json:"signedDay"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Signature  string `json:"signature"`
}

func writeCommentGone(w http.ResponseWriter) {
	WriteErrorWithCode(w, http.StatusConflict, "this comment is gone; reload and try again", "comment_gone")
}

// editComment implements PUT /api/posts/{postId}/comments/{path} (#45). Only the
// comment's author may edit it, and only while it is not a tombstone. The new
// text is sealed under a FRESH nonce (the same key, address and generation seal
// two different plaintexts, which GCM does not survive a reused nonce for) and
// signed again with the same checks as a new comment: the caller's current
// signing key over crypto.SignedPayload with "CMT#<path>" and the day it signs
// today, so a verifier picks the key interval for the edit and not for the
// original. When the edit happened is inside the ciphertext, not on the row. A
// resend of exactly the stored bytes answers 200 before any freshness check, as
// a resent comment does.
func (h *Handler) editComment(w http.ResponseWriter, r *http.Request) {
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
	r.Body = http.MaxBytesReader(w, r.Body, int64(h.commentCiphertextLimit())*2+4096)
	var req editCommentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	const fail = "could not edit the comment"
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
	path := r.PathValue("path")
	if _, ok := idgen.ValidCommentPath(path); !ok {
		WriteError(w, http.StatusBadRequest, "path: must be one to "+strconv.Itoa(idgen.MaxCommentDepth)+" segments of four digits from 0001, joined by dots")
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
	ciphertext, err := decodeBase64Field(req.Ciphertext, 0, h.commentCiphertextLimit())
	if err != nil {
		WriteError(w, http.StatusBadRequest, "ciphertext: "+err.Error())
		return
	}
	if len(ciphertext) < commentMinCiphertext {
		WriteError(w, http.StatusBadRequest, "ciphertext: too short to hold a comment")
		return
	}
	sig, err := decodeBase64Field(req.Signature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "signature: "+err.Error())
		return
	}
	payload := crypto.SignedPayload(userID, groupID, db.CommentSortKeyPrefix+path, uint64(req.Generation), req.SignedDay, ciphertext)
	if !crypto.Verify(self.SigningPublicKey, crypto.ContextComment, payload, sig) {
		WriteErrorWithCode(w, http.StatusBadRequest, "signature: does not verify against your current signing key", "bad_signature")
		return
	}
	have, err := h.db.GetComment(r.Context(), postID, path)
	if err != nil {
		WriteInternalError(w, r, err, fail)
		return
	}
	if have == nil || have.Deleted {
		writeCommentGone(w)
		return
	}
	if have.AuthorUserID != userID {
		WriteError(w, http.StatusForbidden, "only the author can edit a comment")
		return
	}
	in := db.EditCommentInput{
		GroupID: groupID, PostID: postID, PostSortKey: postSortKey, Path: path,
		AuthorUserID: userID, Generation: req.Generation, SignedDay: req.SignedDay,
		Nonce: nonce, Ciphertext: ciphertext, Signature: sig,
		AuthorKeyEpoch: self.KeyEpoch, MarkerPresent: marker != nil, Now: now,
	}
	if marker != nil {
		in.MarkerGeneration = marker.Generation
	}
	if same, err := h.db.EditCommentSame(r.Context(), in); err != nil {
		WriteInternalError(w, r, err, fail)
		return
	} else if same {
		WriteJSON(w, http.StatusOK, map[string]string{"path": path})
		return
	}
	if bytes.Equal(have.Nonce, nonce) {
		WriteErrorWithCode(w, http.StatusBadRequest, "nonce: an edit must be sealed under a new nonce", "nonce_reused")
		return
	}
	if skew := time.Since(signedDay); skew < -grantDaySkewTolerance || skew > 24*time.Hour+grantDaySkewTolerance {
		WriteError(w, http.StatusBadRequest, "signedDay: not within tolerance of the current UTC day")
		return
	}
	commentGeneration := current
	if marker != nil {
		commentGeneration = marker.Generation - 1
	}
	if req.Generation != commentGeneration {
		WriteErrorWithCode(w, http.StatusConflict, "generation: not the generation new comments use; reload and try again", "generation_stale")
		return
	}
	if caller.Generation < commentGeneration {
		WriteErrorWithCode(w, http.StatusConflict, "your key for this group is behind; wait for the rotation to reach you", "member_behind")
		return
	}
	if caller.WrapEpoch < self.KeyEpoch {
		WriteErrorWithCode(w, http.StatusConflict, "your keys changed and an admin has not approved them for this group yet", "member_dormant")
		return
	}
	err = h.db.EditComment(r.Context(), in)
	switch {
	case err == nil:
		WriteJSON(w, http.StatusOK, map[string]string{"path": path})
	case errors.Is(err, db.ErrCommentGone):
		writeCommentGone(w)
	case errors.Is(err, db.ErrCommentPostGone):
		postNotFound(w)
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

// deleteComment implements DELETE /api/posts/{postId}/comments/{path} (#45):
// the comment's author or an admin of its group turns it into a tombstone, so
// replies keep their place, and its reactions are removed. Deleting a tombstone
// again is the same 204 (and finishes a sweep that stopped half way). It needs
// membership and a live post but no key, so a dormant member can still delete
// their own. Deletion is advisory: any member may have kept a copy.
func (h *Handler) deleteComment(w http.ResponseWriter, r *http.Request) {
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
	const fail = "could not delete the comment"
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
	path := r.PathValue("path")
	if _, ok := idgen.ValidCommentPath(path); !ok {
		WriteError(w, http.StatusBadRequest, "path: must be one to "+strconv.Itoa(idgen.MaxCommentDepth)+" segments of four digits from 0001, joined by dots")
		return
	}
	have, err := h.db.GetComment(r.Context(), postID, path)
	if err != nil {
		WriteInternalError(w, r, err, fail)
		return
	}
	if have == nil {
		WriteError(w, http.StatusNotFound, "comment not found")
		return
	}
	if have.AuthorUserID != userID && caller.Role != models.RoleAdmin {
		WriteError(w, http.StatusForbidden, "only the author or an admin can delete a comment")
		return
	}
	if err := h.db.DeleteComment(r.Context(), postID, path); err != nil {
		if errors.Is(err, db.ErrCommentGone) {
			WriteError(w, http.StatusNotFound, "comment not found")
			return
		}
		WriteInternalError(w, r, err, fail)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
