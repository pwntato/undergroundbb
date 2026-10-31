package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// commentEnvelopeOverhead is what a comment's ciphertext adds to its text:
// the version byte, two 4-byte length prefixes (text, time) and the 24-byte
// timestamp (33 bytes), the 16-byte GCM tag, and slack. docs/DESIGN.md
// "Comments" pins the layout.
const commentEnvelopeOverhead = 64

// commentMinCiphertext is the shortest valid ciphertext: the tag plus the empty
// envelope.
const commentMinCiphertext = 16 + 33

// commentCiphertextLimit is the longest ciphertext the configured cap allows.
func (h *Handler) commentCiphertextLimit() int {
	return h.cfg.MaxCommentBytes + commentEnvelopeOverhead
}

func postNotFound(w http.ResponseWriter) {
	WriteError(w, http.StatusNotFound, "post not found")
}

// createCommentRequest is the body of POST /api/posts/{postId}/comments. Path
// is chosen by the client because the signature and the ciphertext's AAD both
// cover it; SignedDay is the UTC day it signed, which a comment's sort key does
// not carry and a verifier needs to pick the key interval.
type createCommentRequest struct {
	Path       string `json:"path"`
	Generation int64  `json:"generation"`
	SignedDay  string `json:"signedDay"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Signature  string `json:"signature"`
}

// createComment implements POST /api/posts/{postId}/comments (#44). The post id
// carries its group, and membership is checked against that group, so a caller
// cannot name a group they are not in. Like createPost the server checks what
// it can see: a current, non-dormant member holding the generation new items
// use, a well formed path no deeper than eight segments under a parent that
// exists, a signing day near today, the ciphertext within the cap, and a
// signature that verifies under the caller's CURRENT signing key over
// crypto.SignedPayload with the comment's own sort key, "CMT#<path>". The
// ciphertext is sealed under crypto.CommentAAD, which binds the post.
//
// The path is the client's choice, so two people replying to the same comment
// can pick the same next number. The write is conditional on the path being
// free; the loser gets 409 comment_path_taken with the next free path, and
// reseals (the signature and the AAD cover the path, so the server cannot
// renumber it).
func (h *Handler) createComment(w http.ResponseWriter, r *http.Request) {
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
	var req createCommentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	// Every read happens before any 404 branch, so the response does not tell a
	// non-member which of the things they asked about is missing.
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not create the comment")
		return
	}
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not create the comment")
		return
	}
	self, err := h.db.GetUserByIDConsistent(r.Context(), userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not create the comment")
		return
	}
	current, err := h.db.GroupCurrentGeneration(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not create the comment")
		return
	}
	marker, err := h.db.GetRotation(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not create the comment")
		return
	}
	post, err := h.db.GetPost(r.Context(), groupID, postSortKey)
	if err != nil {
		WriteInternalError(w, r, err, "could not create the comment")
		return
	}
	now := time.Now()
	if caller == nil || group == nil || post == nil || db.PostExpired(post, now) {
		postNotFound(w)
		return
	}

	if _, ok := idgen.ValidCommentPath(req.Path); !ok {
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
	payload := crypto.SignedPayload(userID, groupID, db.CommentSortKeyPrefix+req.Path, uint64(req.Generation), req.SignedDay, ciphertext)
	if !crypto.Verify(self.SigningPublicKey, crypto.ContextComment, payload, sig) {
		WriteErrorWithCode(w, http.StatusBadRequest, "signature: does not verify against your current signing key", "bad_signature")
		return
	}

	in := db.CreateCommentInput{
		GroupID:        groupID,
		PostID:         postID,
		PostSortKey:    postSortKey,
		PostTTL:        post.TTL,
		Path:           req.Path,
		AuthorUserID:   userID,
		Generation:     req.Generation,
		SignedDay:      req.SignedDay,
		Nonce:          nonce,
		Ciphertext:     ciphertext,
		Signature:      sig,
		AuthorKeyEpoch: self.KeyEpoch,
		MarkerPresent:  marker != nil,
		Now:            now,
	}
	if marker != nil {
		in.MarkerGeneration = marker.Generation
	}
	// A resend of a comment that already landed is answered by what was
	// written, before any freshness check, for the reason createPost gives.
	if stored, err := h.db.CommentAlreadyStored(r.Context(), in); err != nil {
		WriteInternalError(w, r, err, "could not create the comment")
		return
	} else if stored {
		WriteJSON(w, http.StatusCreated, map[string]string{"path": req.Path})
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
	// A path may be at most one past the highest sibling, so numbers are never
	// skipped: a member cannot take 9999 first and leave no room under a parent,
	// or choose where a comment sorts. The segments are fixed width under one
	// parent, so string order is numeric order. This cannot go stale: the
	// highest sibling only grows, so a path no more than one past it now is no
	// more than one past it when written, and two writers at the same number
	// still meet the write's own condition.
	//
	// A reply under a comment that does not exist is parent_gone, whatever its
	// number: asked first, so the skip rule below never sends such a reply to a
	// "next free path" under nothing. A deleted comment is a tombstone and is
	// still there, so replies under it are fine.
	if parent := idgen.CommentParentPath(req.Path); parent != "" {
		have, perr := h.db.GetComment(r.Context(), postID, parent)
		if perr != nil {
			WriteInternalError(w, r, perr, "could not create the comment")
			return
		}
		if have == nil {
			writeParentGone(w)
			return
		}
	}
	next, nerr := h.db.NextCommentPath(r.Context(), postID, idgen.CommentParentPath(req.Path))
	switch {
	case errors.Is(nerr, db.ErrCommentSiblingsFull):
		writeRepliesFull(w)
		return
	case nerr != nil:
		WriteInternalError(w, r, nerr, "could not create the comment")
		return
	case req.Path > next:
		writeNextPath(w, "comment_path_skips", "this path skips a number; seal again with the next free one", next)
		return
	}
	err = h.db.CreateComment(r.Context(), in)
	switch {
	case err == nil:
		WriteJSON(w, http.StatusCreated, map[string]string{"path": req.Path})
	case errors.Is(err, db.ErrCommentPathTaken):
		// Another writer took the number between the check and the write.
		next, nerr := h.db.NextCommentPath(r.Context(), postID, idgen.CommentParentPath(req.Path))
		switch {
		case errors.Is(nerr, db.ErrCommentSiblingsFull):
			writeRepliesFull(w)
		case nerr != nil:
			WriteInternalError(w, r, nerr, "could not create the comment")
		default:
			writeNextPath(w, "comment_path_taken", "another comment already has this path; seal again with the next free one", next)
		}
	case errors.Is(err, db.ErrCommentPostGone):
		postNotFound(w)
	case errors.Is(err, db.ErrCommentParentGone):
		writeParentGone(w)
	case errors.Is(err, db.ErrPostMarkerChanged):
		WriteErrorWithCode(w, http.StatusConflict, "the group's key rotation changed; reload and try again", "generation_stale")
	case errors.Is(err, db.ErrPostMemberChanged):
		WriteErrorWithCode(w, http.StatusConflict, "your membership changed; reload and try again", "membership_changed")
	case errors.Is(err, db.ErrWrapEpochStale):
		WriteErrorWithCode(w, http.StatusConflict, "your keys were rotated by another request; reload and try again", "key_epoch_stale")
	case errors.Is(err, db.ErrRoleChangeConflict):
		WriteErrorWithCode(w, http.StatusConflict, "another change was in progress; retry", "conflict_retry")
	default:
		WriteInternalError(w, r, err, "could not create the comment")
	}
}

func writeParentGone(w http.ResponseWriter) {
	WriteErrorWithCode(w, http.StatusConflict, "the comment you replied to is gone; reload and try again", "parent_gone")
}

func writeRepliesFull(w http.ResponseWriter) {
	WriteErrorWithCode(w, http.StatusConflict, "this comment already has as many replies as it can number", "replies_full")
}

// writeNextPath answers a path the client must change, with the one to use.
func writeNextPath(w http.ResponseWriter, code, msg, nextPath string) {
	WriteJSON(w, http.StatusConflict, map[string]string{"error": msg, "code": code, "nextPath": nextPath})
}

// Page sizes for GET /api/posts/{postId}/thread. A comment is about 14 KB on
// the wire at the default cap, like a post.
const (
	defaultCommentPageSize = 50
	maxCommentPageSize     = 100
)

// commentEntry is one stored comment as the reader needs it. The server checked
// what it could when it was written and verifies nothing now; the reader opens
// the ciphertext and verifies the signature itself.
type commentEntry struct {
	Path         string `json:"path"`
	AuthorUserID string `json:"authorUserId"`
	Generation   int64  `json:"generation"`
	SignedDay    string `json:"signedDay"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
	Signature    string `json:"signature"`
	// Deleted marks a tombstone: the fields above are empty and the reader
	// shows only that the comment was deleted.
	Deleted bool `json:"deleted,omitempty"`
}

// reactionEntry is one stored reaction. Target is the comment path it is on, or
// 0000 for the post itself.
type reactionEntry struct {
	Target        string `json:"target"`
	ReactorUserID string `json:"reactorUserId"`
	Generation    int64  `json:"generation"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
}

type threadResponse struct {
	Comments   []commentEntry  `json:"comments"`
	Reactions  []reactionEntry `json:"reactions"`
	NextCursor string          `json:"nextCursor,omitempty"`
}

// getThread implements GET /api/posts/{postId}/thread (#44): one page of a
// post's comments in display order, with the reactions that belong to exactly
// those comments (and the post's own, on the first page). That is two small
// queries a page rather than the whole thread at once, so a long thread never
// loads in one response. Members only, with the post's 404 for anyone else (a
// dormant member included: they can read what their keys open).
func (h *Handler) getThread(w http.ResponseWriter, r *http.Request) {
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
	limit := defaultCommentPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxCommentPageSize {
			WriteError(w, http.StatusBadRequest, "limit: must be between 1 and "+strconv.Itoa(maxCommentPageSize))
			return
		}
		limit = n
	}
	cursor := r.URL.Query().Get("cursor")
	if cursor != "" {
		if _, ok := idgen.ValidCommentPath(cursor); !ok {
			WriteError(w, http.StatusBadRequest, "cursor: must be a comment path")
			return
		}
	}
	m, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not read the thread")
		return
	}
	post, err := h.db.GetPost(r.Context(), groupID, postSortKey)
	if err != nil {
		WriteInternalError(w, r, err, "could not read the thread")
		return
	}
	if m == nil || post == nil || db.PostExpired(post, time.Now()) {
		postNotFound(w)
		return
	}
	rows, next, err := h.db.ListComments(r.Context(), postID, cursor, limit)
	if err != nil {
		WriteInternalError(w, r, err, "could not read the thread")
		return
	}
	first, last := "", ""
	if len(rows) > 0 {
		first = strings.TrimPrefix(rows[0].SK, db.CommentSortKeyPrefix)
		last = strings.TrimPrefix(rows[len(rows)-1].SK, db.CommentSortKeyPrefix)
	}
	rxns, err := h.db.ListReactions(r.Context(), postID, first, last, cursor == "")
	if err != nil {
		WriteInternalError(w, r, err, "could not read the thread")
		return
	}
	rxns = withoutDeletedTargets(rows, rxns)
	// A page that would outgrow the response budget is cut short, not capped
	// reaction by reaction: the comments after the cut, with their reactions,
	// come on the next page, because the cursor moves back to the last comment
	// kept. Dropping a reaction instead would be silent.
	if keep, keepRxns := fitThreadPage(rows, rxns, h.threadBudgetBytes()); keep < len(rows) {
		rows, rxns = rows[:keep], rxns[:keepRxns]
		next = strings.TrimPrefix(rows[keep-1].SK, db.CommentSortKeyPrefix)
	}
	enc := base64.StdEncoding.EncodeToString
	out := threadResponse{
		Comments:   make([]commentEntry, 0, len(rows)),
		Reactions:  make([]reactionEntry, 0, len(rxns)),
		NextCursor: next,
	}
	for _, c := range rows {
		if c.Deleted {
			// Nothing but the place: who wrote it, and who deleted it, is not served.
			out.Comments = append(out.Comments, commentEntry{
				Path: strings.TrimPrefix(c.SK, db.CommentSortKeyPrefix), Deleted: true,
			})
			continue
		}
		out.Comments = append(out.Comments, commentEntry{
			Path:         strings.TrimPrefix(c.SK, db.CommentSortKeyPrefix),
			AuthorUserID: c.AuthorUserID,
			Generation:   c.Generation,
			SignedDay:    c.SignedDay,
			Nonce:        enc(c.Nonce),
			Ciphertext:   enc(c.Ciphertext),
			Signature:    enc(c.Signature),
			Deleted:      c.Deleted,
		})
	}
	for _, x := range rxns {
		target, reactor, ok := strings.Cut(strings.TrimPrefix(x.SK, db.ReactionSortKeyPrefix), "#")
		if !ok {
			continue
		}
		out.Reactions = append(out.Reactions, reactionEntry{
			Target:        target,
			ReactorUserID: reactor,
			Generation:    x.Generation,
			Nonce:         enc(x.Nonce),
			Ciphertext:    enc(x.Ciphertext),
		})
	}
	WriteJSON(w, http.StatusOK, out)
}

// withoutDeletedTargets drops reactions on the page's tombstones. DeleteComment
// removes them, but it does so after writing the tombstone, so for a moment
// (or for good, if the sweep failed) some may remain; they must not be served.
func withoutDeletedTargets(rows []models.Comment, rxns []models.Reaction) []models.Reaction {
	gone := map[string]bool{}
	for _, c := range rows {
		if c.Deleted {
			gone[strings.TrimPrefix(c.SK, db.CommentSortKeyPrefix)] = true
		}
	}
	if len(gone) == 0 {
		return rxns
	}
	kept := make([]models.Reaction, 0, len(rxns))
	for _, x := range rxns {
		target, _, _ := strings.Cut(strings.TrimPrefix(x.SK, db.ReactionSortKeyPrefix), "#")
		if !gone[target] {
			kept = append(kept, x)
		}
	}
	return kept
}
