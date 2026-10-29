package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

// postEnvelopeOverhead is what a post's ciphertext adds to its title and body
// bytes: the version byte, three 4-byte length prefixes and the 24-byte
// timestamp (37 bytes), the 16-byte GCM tag, and slack. docs/DESIGN.md "Posts"
// pins the plaintext layout, which is why the server's limit can sit this
// close to the caps: JSON would escape bytes and force a much looser one.
const postEnvelopeOverhead = 64

// postMinCiphertext is the shortest valid ciphertext: the tag plus the empty
// envelope (version, three length prefixes, timestamp).
const postMinCiphertext = 16 + 37

// createPostRequest is the body of POST /api/groups/{groupId}/posts. SortKey
// and Generation are signed into Signature (crypto.SignedPayload), and the
// ciphertext is sealed under crypto.PostAAD(group, SortKey, Generation).
type createPostRequest struct {
	SortKey    string `json:"sortKey"`
	Generation int64  `json:"generation"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Signature  string `json:"signature"`
}

// postCiphertextLimit is the longest ciphertext the configured caps allow.
func (h *Handler) postCiphertextLimit() int {
	return h.cfg.MaxPostTitleBytes + h.cfg.MaxPostBodyBytes + postEnvelopeOverhead
}

// createPost implements POST /api/groups/{groupId}/posts (#42). The server
// cannot read a post, so it checks what it can see: the caller is a current,
// non-dormant member holding the post's generation, the generation is the one
// new posts use now, the sort key's day is today, the ciphertext is within the
// size the caps allow, and the signature verifies under the caller's CURRENT
// signing key, so a leaked superseded key cannot land a post (docs/DESIGN.md,
// "A leaked superseded key must not be able to write").
//
// New posts use the group's settled generation: while a rotation runs they
// stay on the old one, which every member who is not yet re-wrapped holds
// and a re-wrapped member can derive.
func (h *Handler) createPost(w http.ResponseWriter, r *http.Request) {
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
	r.Body = http.MaxBytesReader(w, r.Body, int64(h.postCiphertextLimit())*2+4096)
	var req createPostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	// Same rule as getGroup: every read happens before any 404 branch.
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not create the post")
		return
	}
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not create the post")
		return
	}
	self, err := h.db.GetUserByIDConsistent(r.Context(), userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not create the post")
		return
	}
	current, err := h.db.GroupCurrentGeneration(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not create the post")
		return
	}
	marker, err := h.db.GetRotation(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not create the post")
		return
	}
	if caller == nil || group == nil {
		groupNotFound(w)
		return
	}

	day, ok := idgen.ValidPostSortKey(req.SortKey)
	if !ok {
		WriteError(w, http.StatusBadRequest, "sortKey: must be POST#<YYYY-MM-DD>#<16 hex characters>")
		return
	}
	nonce, err := decodeBase64Field(req.Nonce, crypto.NonceSize, crypto.NonceSize)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "nonce: "+err.Error())
		return
	}
	ciphertext, err := decodeBase64Field(req.Ciphertext, 0, h.postCiphertextLimit())
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
	payload := crypto.SignedPayload(userID, groupID, req.SortKey, uint64(req.Generation), day.Format("2006-01-02"), ciphertext)
	if !crypto.Verify(self.SigningPublicKey, crypto.ContextPost, payload, sig) {
		WriteErrorWithCode(w, http.StatusBadRequest, "signature: does not verify against your current signing key", "bad_signature")
		return
	}

	in := db.CreatePostInput{
		GroupID:        groupID,
		SortKey:        req.SortKey,
		AuthorUserID:   userID,
		Generation:     req.Generation,
		Nonce:          nonce,
		Ciphertext:     ciphertext,
		Signature:      sig,
		AuthorKeyEpoch: self.KeyEpoch,
		MarkerPresent:  marker != nil,
		ExpirationDays: group.ExpirationDays,
		Now:            time.Now(),
	}
	if marker != nil {
		in.MarkerGeneration = marker.Generation
	}
	// A resend of a post that already landed is answered by what was written,
	// before any freshness check: the first send committed and its response was
	// lost, and a rotation may have completed or the day passed since. Refusing
	// the resend would make the client seal a second post.
	if stored, err := h.db.PostAlreadyStored(r.Context(), in); err != nil {
		WriteInternalError(w, r, err, "could not create the post")
		return
	} else if stored {
		WriteJSON(w, http.StatusCreated, map[string]string{"sortKey": req.SortKey})
		return
	}
	if skew := time.Since(day); skew < -grantDaySkewTolerance || skew > 24*time.Hour+grantDaySkewTolerance {
		WriteError(w, http.StatusBadRequest, "sortKey: day is not within tolerance of the current UTC day")
		return
	}
	// New posts use the settled generation; a running rotation counts in
	// GroupCurrentGeneration, so the settled one is one below.
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
	err = h.db.CreatePost(r.Context(), in)
	switch {
	case err == nil:
		WriteJSON(w, http.StatusCreated, map[string]string{"sortKey": req.SortKey})
	case errors.Is(err, db.ErrPostExists):
		WriteErrorWithCode(w, http.StatusConflict, "a different post already has this address; try again", "post_exists")
	case errors.Is(err, db.ErrPostMarkerChanged):
		WriteErrorWithCode(w, http.StatusConflict, "the group's key rotation changed; reload and try again", "generation_stale")
	case errors.Is(err, db.ErrPostMemberChanged):
		WriteErrorWithCode(w, http.StatusConflict, "your membership changed; reload and try again", "membership_changed")
	case errors.Is(err, db.ErrWrapEpochStale):
		WriteErrorWithCode(w, http.StatusConflict, "your keys were rotated by another request; reload and try again", "key_epoch_stale")
	case errors.Is(err, db.ErrRoleChangeConflict):
		WriteErrorWithCode(w, http.StatusConflict, "another change was in progress; retry", "conflict_retry")
	default:
		WriteInternalError(w, r, err, "could not create the post")
	}
}

// Page sizes for GET /api/groups/{groupId}/posts. A post is at most about
// 14 KB on the wire at the default caps, so a full page of the maximum stays
// well inside a Lambda response.
const (
	defaultPostPageSize = 20
	maxPostPageSize     = 50
)

// postEntry is one stored post as the reader needs it. Nothing here is checked
// by the server beyond what createPost checked when it was written: the reader
// opens the ciphertext and verifies the signature itself (docs/DESIGN.md,
// "For the reader").
type postEntry struct {
	SortKey      string `json:"sortKey"`
	AuthorUserID string `json:"authorUserId"`
	Generation   int64  `json:"generation"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
	Signature    string `json:"signature"`
}

type listPostsResponse struct {
	Posts      []postEntry `json:"posts"`
	NextCursor string      `json:"nextCursor,omitempty"`
}

// listPosts implements GET /api/groups/{groupId}/posts -- #43. Members only,
// with the roster's 404 for anyone else (a dormant member included: they can
// read what their keys open, and the client says what it cannot). Newest sort
// key first; serves the stored rows and verifies nothing.
func (h *Handler) listPosts(w http.ResponseWriter, r *http.Request) {
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
	limit := defaultPostPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxPostPageSize {
			WriteError(w, http.StatusBadRequest, "limit: must be between 1 and "+strconv.Itoa(maxPostPageSize))
			return
		}
		limit = n
	}
	cursor := r.URL.Query().Get("cursor")
	if cursor != "" {
		if _, ok := idgen.ValidPostSortKey(cursor); !ok {
			WriteError(w, http.StatusBadRequest, "cursor: must be a post sort key")
			return
		}
	}
	m, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not list posts")
		return
	}
	if m == nil {
		groupNotFound(w)
		return
	}
	rows, next, err := h.db.ListPosts(r.Context(), groupID, cursor, limit, time.Now())
	if err != nil {
		WriteInternalError(w, r, err, "could not list posts")
		return
	}
	enc := base64.StdEncoding.EncodeToString
	entries := make([]postEntry, 0, len(rows))
	for _, p := range rows {
		entries = append(entries, postEntry{
			SortKey:      p.SK,
			AuthorUserID: p.AuthorUserID,
			Generation:   p.Generation,
			Nonce:        enc(p.Nonce),
			Ciphertext:   enc(p.Ciphertext),
			Signature:    enc(p.Signature),
		})
	}
	WriteJSON(w, http.StatusOK, listPostsResponse{Posts: entries, NextCursor: next})
}
