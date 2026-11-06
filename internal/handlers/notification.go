package handlers

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

const (
	defaultNotificationPageSize = 20
	maxNotificationPageSize     = 50
	// notificationMaxPasses bounds the reply reads one request makes while dropping rows for
	// groups left and posts gone (the same bound ListPosts uses).
	notificationMaxPasses = db.ListPostsMaxPasses
	// maxMarkRead is how many ids one mark-read request takes.
	maxMarkRead = 25
)

// notificationEntry is one notification as the client renders it: identifiers only, never text
// (docs/DESIGN.md, "Notification items hold identifiers, not text").
type notificationEntry struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	ActorUserID string `json:"actorUserId"`
	GroupID     string `json:"groupId"`
	PostID      string `json:"postId"`
	CmtPath     string `json:"cmtPath"`
	Read        bool   `json:"read"`
}

type listNotificationsResponse struct {
	Notifications []notificationEntry `json:"notifications"`
	// NextCursor is opaque; absent when the list ends.
	NextCursor string `json:"nextCursor,omitempty"`
}

func notificationEntryOf(n models.Notification) notificationEntry {
	return notificationEntry{ID: n.SK, Kind: n.Kind, ActorUserID: n.ActorUserID, GroupID: n.GroupID, PostID: n.PostID, CmtPath: n.CmtPath, Read: n.Read}
}

// notificationFilter answers whether a notification is still worth showing: the caller is still in
// the group and the post is neither gone, deleted nor past its TTL. Leaving a group removes none
// of its notifications, so the reader drops them here. Answers are cached for the request.
type notificationFilter struct {
	h      *Handler
	r      *http.Request
	userID string
	now    time.Time
	member map[string]bool
	post   map[string]bool
}

func (f *notificationFilter) keep(n models.Notification) (bool, error) {
	groupID, postSK, ok := idgen.ParsePostID(n.PostID)
	if !ok {
		return false, nil
	}
	in, seen := f.member[groupID]
	if !seen {
		m, err := f.h.db.GetMembership(f.r.Context(), groupID, f.userID)
		if err != nil {
			return false, err
		}
		in = m != nil
		f.member[groupID] = in
	}
	if !in {
		return false, nil
	}
	live, seen := f.post[n.PostID]
	if !seen {
		p, err := f.h.db.GetPost(f.r.Context(), groupID, postSK)
		if err != nil {
			return false, err
		}
		live = p != nil && !p.Deleted && !db.PostExpired(p, f.now)
		f.post[n.PostID] = live
	}
	return live, nil
}

// postDay is the day inside a post id ("" for a malformed one, which sorts last).
func postDay(postID string) string {
	_, sk, ok := idgen.ParsePostID(postID)
	if !ok {
		return ""
	}
	return strings.Split(sk, "#")[1]
}

// listNotifications implements GET /api/notifications?cursor=&limit= (#69). Reply notifications
// first, newest day first, paged in key order; then reaction notifications, newest post first by
// the day in post_id (their keys carry no time, so that range is read once, sorted, and paged by
// offset). The cursor is opaque: "r:<sort key>" in the reply range, "x:<offset>" in the reaction
// range.
func (h *Handler) listNotifications(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	limit := defaultNotificationPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxNotificationPageSize {
			WriteError(w, http.StatusBadRequest, "limit: must be between 1 and "+strconv.Itoa(maxNotificationPageSize))
			return
		}
		limit = n
	}
	inReactions, replyAfter, offset := false, "", 0
	if c := r.URL.Query().Get("cursor"); c != "" {
		switch {
		case strings.HasPrefix(c, "r:") && idgen.ValidNotificationSortKey(c[2:]):
			replyAfter = c[2:]
		case strings.HasPrefix(c, "x:"):
			n, err := strconv.Atoi(c[2:])
			if err != nil || n < 0 {
				WriteError(w, http.StatusBadRequest, "cursor: malformed")
				return
			}
			inReactions, offset = true, n
		default:
			WriteError(w, http.StatusBadRequest, "cursor: malformed")
			return
		}
	}
	f := &notificationFilter{h: h, r: r, userID: userID, now: time.Now(), member: map[string]bool{}, post: map[string]bool{}}
	fail := func(err error) { WriteInternalError(w, r, err, "could not list notifications") }
	resp := listNotificationsResponse{Notifications: []notificationEntry{}}

	if !inReactions {
		for pass := 0; ; pass++ {
			rows, last, done, err := h.db.ListReplyNotifications(r.Context(), userID, replyAfter, limit-len(resp.Notifications))
			if err != nil {
				fail(err)
				return
			}
			for _, n := range rows {
				keep, err := f.keep(n)
				if err != nil {
					fail(err)
					return
				}
				if keep {
					resp.Notifications = append(resp.Notifications, notificationEntryOf(n))
				}
			}
			if last != "" {
				replyAfter = last
			}
			if done {
				inReactions = true
				break
			}
			if len(resp.Notifications) >= limit {
				resp.NextCursor = "r:" + replyAfter
				WriteJSON(w, http.StatusOK, resp)
				return
			}
			if pass+1 == notificationMaxPasses {
				// Everything up to replyAfter is shown or dropped; resume strictly after it.
				resp.NextCursor = "r:" + replyAfter
				WriteJSON(w, http.StatusOK, resp)
				return
			}
		}
	}

	rows, err := h.db.ListReactionNotifications(r.Context(), userID)
	if err != nil {
		fail(err)
		return
	}
	var kept []models.Notification
	for _, n := range rows {
		keep, err := f.keep(n)
		if err != nil {
			fail(err)
			return
		}
		if keep {
			kept = append(kept, n)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool {
		di, dj := postDay(kept[i].PostID), postDay(kept[j].PostID)
		if di != dj {
			return di > dj
		}
		return kept[i].SK < kept[j].SK
	})
	for offset < len(kept) && len(resp.Notifications) < limit {
		resp.Notifications = append(resp.Notifications, notificationEntryOf(kept[offset]))
		offset++
	}
	if offset < len(kept) {
		resp.NextCursor = "x:" + strconv.Itoa(offset)
	}
	WriteJSON(w, http.StatusOK, resp)
}

type markReadRequest struct {
	IDs []string `json:"ids"`
}

// markNotificationsRead implements PUT /api/notifications/read (#69): sets Read on up to
// maxMarkRead of the caller's own notifications. Ids that name nothing are skipped.
func (h *Handler) markNotificationsRead(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	var req markReadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > maxMarkRead {
		WriteError(w, http.StatusBadRequest, "ids: between 1 and "+strconv.Itoa(maxMarkRead)+" required")
		return
	}
	for _, id := range req.IDs {
		if !idgen.ValidNotificationSortKey(id) {
			WriteError(w, http.StatusBadRequest, "ids: not a notification id")
			return
		}
	}
	for _, id := range req.IDs {
		if err := h.db.MarkNotificationRead(r.Context(), userID, id); err != nil {
			WriteInternalError(w, r, err, "could not mark notifications read")
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
