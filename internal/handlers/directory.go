package handlers

import (
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/pwntato/undergroundbb/internal/db"
)

// The public group directory (#71): GET /api/groups/public?q=&limit=&cursor=. docs/DESIGN.md,
// "Visibility -- private and public groups". Public means discoverable, not readable: an entry is a
// group's id, its plaintext name and its description, and nothing about its posts or its members.
//
// It requires a session like the rest of /api. That is not what keeps the names private (an invite
// id already shows a public group's name to anyone holding it, #290); it keeps an anonymous crawler
// from walking the whole directory.
//
// Names are not unique, so a listing can hold several groups with the same name: that is correct
// output, and the id is what tells them apart.

const (
	defaultDirectoryPage = 25
	maxDirectoryPage     = 50
)

type directoryEntry struct {
	GroupID     string `json:"groupId"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type directoryResponse struct {
	Groups     []directoryEntry `json:"groups"`
	NextCursor string           `json:"nextCursor,omitempty"`
}

// listPublicGroups implements GET /api/groups/public. q is a case-sensitive name prefix (the index
// key is the name as typed, so a case-insensitive search would need a second key).
func (h *Handler) listPublicGroups(w http.ResponseWriter, r *http.Request) {
	if _, ok := sessionUserID(r); !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	q := r.URL.Query().Get("q")
	if len(q) > maxGroupNameLen || !utf8.ValidString(q) {
		WriteError(w, http.StatusBadRequest, "q: must be valid text of at most "+strconv.Itoa(maxGroupNameLen)+" bytes")
		return
	}
	limit := defaultDirectoryPage
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxDirectoryPage {
			WriteError(w, http.StatusBadRequest, "limit: must be a number from 1 to "+strconv.Itoa(maxDirectoryPage))
			return
		}
		limit = n
	}
	cursor := r.URL.Query().Get("cursor")
	if cursor != "" && !db.ValidDirectoryCursor(cursor, q) {
		WriteError(w, http.StatusBadRequest, "cursor: not a cursor this endpoint issued for this search")
		return
	}
	rows, next, err := h.db.ListPublicGroups(r.Context(), q, limit, cursor)
	if err != nil {
		WriteInternalError(w, r, err, "could not list public groups")
		return
	}
	resp := directoryResponse{Groups: make([]directoryEntry, 0, len(rows)), NextCursor: next}
	for _, g := range rows {
		resp.Groups = append(resp.Groups, directoryEntry{GroupID: g.GroupID, Name: g.Name, Description: g.Description})
	}
	WriteJSON(w, http.StatusOK, resp)
}
