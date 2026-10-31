package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

// putReactionRequest is the body of PUT /api/posts/{postId}/reactions/{target}.
// A reaction is not signed (docs/DESIGN.md "Reactions"): the server takes the
// reactor from the session, and the ciphertext's AAD binds it.
type putReactionRequest struct {
	Generation int64  `json:"generation"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// reactionTarget reads {target}: a comment path, or 0000 for the post itself.
func reactionTarget(w http.ResponseWriter, r *http.Request) (string, bool) {
	target := r.PathValue("target")
	if _, ok := idgen.ValidCommentPath(target); !ok && target != db.PostLevelReactionTarget {
		WriteError(w, http.StatusBadRequest, "target: must be 0000 for the post or a comment path")
		return "", false
	}
	return target, true
}

// putReaction implements PUT /api/posts/{postId}/reactions/{target} (#46). It
// sets the caller's reaction on the post or one of its comments, replacing any
// they had there, so a repeat is harmless. The server checks what it can see: a
// current, non-dormant member holding the generation new items use, a live
// post, a comment that exists, and a ciphertext of exactly the one length a
// reaction seals to (crypto.ReactionCiphertextSize), so a client cannot park
// anything else in these rows. Which emoji it is stays unreadable.
func (h *Handler) putReaction(w http.ResponseWriter, r *http.Request) {
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
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req putReactionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	// Every read happens before any 404 branch, so the response does not tell a
	// non-member which of the things they asked about is missing.
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not save the reaction")
		return
	}
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not save the reaction")
		return
	}
	self, err := h.db.GetUserByIDConsistent(r.Context(), userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not save the reaction")
		return
	}
	current, err := h.db.GroupCurrentGeneration(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not save the reaction")
		return
	}
	marker, err := h.db.GetRotation(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not save the reaction")
		return
	}
	post, err := h.db.GetPost(r.Context(), groupID, postSortKey)
	if err != nil {
		WriteInternalError(w, r, err, "could not save the reaction")
		return
	}
	now := time.Now()
	if caller == nil || group == nil || post == nil || db.PostExpired(post, now) {
		postNotFound(w)
		return
	}
	target, ok := reactionTarget(w, r)
	if !ok {
		return
	}
	nonce, err := decodeBase64Field(req.Nonce, crypto.NonceSize, crypto.NonceSize)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "nonce: "+err.Error())
		return
	}
	ciphertext, err := decodeBase64Field(req.Ciphertext, crypto.ReactionCiphertextSize, crypto.ReactionCiphertextSize)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "ciphertext: "+err.Error())
		return
	}
	reactionGeneration := current
	if marker != nil {
		reactionGeneration = marker.Generation - 1
	}
	if req.Generation != reactionGeneration {
		WriteErrorWithCode(w, http.StatusConflict, "generation: not the generation new reactions use; reload and try again", "generation_stale")
		return
	}
	if caller.Generation < reactionGeneration {
		WriteErrorWithCode(w, http.StatusConflict, "your key for this group is behind; wait for the rotation to reach you", "member_behind")
		return
	}
	if caller.WrapEpoch < self.KeyEpoch {
		WriteErrorWithCode(w, http.StatusConflict, "your keys changed and an admin has not approved them for this group yet", "member_dormant")
		return
	}

	in := db.PutReactionInput{
		GroupID:         groupID,
		PostID:          postID,
		PostSortKey:     postSortKey,
		PostTTL:         post.TTL,
		Target:          target,
		ReactorID:       userID,
		Generation:      req.Generation,
		Nonce:           nonce,
		Ciphertext:      ciphertext,
		ReactorKeyEpoch: self.KeyEpoch,
		MarkerPresent:   marker != nil,
		Now:             now,
	}
	if marker != nil {
		in.MarkerGeneration = marker.Generation
	}
	err = h.db.PutReaction(r.Context(), in)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, db.ErrCommentPostGone):
		postNotFound(w)
	case errors.Is(err, db.ErrReactionTargetGone):
		WriteErrorWithCode(w, http.StatusConflict, "the comment you reacted to is gone; reload and try again", "parent_gone")
	case errors.Is(err, db.ErrPostMarkerChanged):
		WriteErrorWithCode(w, http.StatusConflict, "the group's key rotation changed; reload and try again", "generation_stale")
	case errors.Is(err, db.ErrPostMemberChanged):
		WriteErrorWithCode(w, http.StatusConflict, "your membership changed; reload and try again", "membership_changed")
	case errors.Is(err, db.ErrWrapEpochStale):
		WriteErrorWithCode(w, http.StatusConflict, "your keys were rotated by another request; reload and try again", "key_epoch_stale")
	case errors.Is(err, db.ErrRoleChangeConflict):
		WriteErrorWithCode(w, http.StatusConflict, "another change was in progress; retry", "conflict_retry")
	default:
		WriteInternalError(w, r, err, "could not save the reaction")
	}
}

// deleteReaction implements DELETE /api/posts/{postId}/reactions/{target}: the
// caller takes back their own reaction there. The reactor is the session's
// user, never a parameter, so nobody can remove another member's. Removing one
// that is not there is the same 204, so a repeated undo is harmless. It needs
// membership and a live post but no key, so a dormant member can still undo.
func (h *Handler) deleteReaction(w http.ResponseWriter, r *http.Request) {
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
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not remove the reaction")
		return
	}
	post, err := h.db.GetPost(r.Context(), groupID, postSortKey)
	if err != nil {
		WriteInternalError(w, r, err, "could not remove the reaction")
		return
	}
	if caller == nil || post == nil || db.PostExpired(post, time.Now()) {
		postNotFound(w)
		return
	}
	target, ok := reactionTarget(w, r)
	if !ok {
		return
	}
	if err := h.db.DeleteReaction(r.Context(), postID, target, userID); err != nil {
		WriteInternalError(w, r, err, "could not remove the reaction")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
