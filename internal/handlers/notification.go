package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

const (
	defaultNotificationPageSize = 20
	maxNotificationPageSize     = 50
	// notificationReadBatch rows are read per pass, and at most notificationMaxPasses passes per
	// request, while dropping rows for groups left and posts gone: a request examines at most
	// 1000 rows and checks each distinct post once.
	notificationReadBatch = 100
	notificationMaxPasses = 10
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

// listNotifications implements GET /api/notifications?cursor=&limit= (#69). One descending read of
// the user's NOTIF# range is the whole order: reply notifications newest day first, then reaction
// notifications newest post first (the post's day is in their key, docs/DESIGN.md "What the reader
// does with them"). The cursor is the sort key of the last row to resume after. Rows the caller
// should not see are dropped and the page is filled past them, up to notificationMaxPasses reads
// of notificationReadBatch rows; past that the page is returned short with a cursor to continue.
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
	after := r.URL.Query().Get("cursor")
	if after != "" && !idgen.ValidNotificationSortKey(after) {
		WriteError(w, http.StatusBadRequest, "cursor: malformed")
		return
	}
	f := &notificationFilter{h: h, r: r, userID: userID, now: time.Now(), member: map[string]bool{}, post: map[string]bool{}}
	resp := listNotificationsResponse{Notifications: []notificationEntry{}}
	for pass := 0; pass < notificationMaxPasses; pass++ {
		rows, last, done, err := h.db.ListNotifications(r.Context(), userID, after, notificationReadBatch)
		if err != nil {
			WriteInternalError(w, r, err, "could not list notifications")
			return
		}
		for i, n := range rows {
			keep, err := f.keep(n)
			if err != nil {
				WriteInternalError(w, r, err, "could not list notifications")
				return
			}
			if !keep {
				continue
			}
			resp.Notifications = append(resp.Notifications, notificationEntryOf(n))
			if len(resp.Notifications) == limit {
				if i < len(rows)-1 || !done {
					resp.NextCursor = n.SK
				}
				WriteJSON(w, http.StatusOK, resp)
				return
			}
		}
		if done {
			WriteJSON(w, http.StatusOK, resp)
			return
		}
		after = last
	}
	// Everything up to `after` is shown or dropped; resume strictly after it.
	resp.NextCursor = after
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
