package handlers

import (
	"net/http"
	"strconv"

	"github.com/pwntato/undergroundbb/internal/idgen"
)

// maxKeychainPage bounds one response: each link is a nonce and a 48-byte
// ciphertext, so a page is a few tens of kilobytes at most.
const maxKeychainPage = 200

// maxKeychainGeneration is the largest generation a GENKEY# sort key can
// carry (six zero-padded digits, docs/DESIGN.md).
const maxKeychainGeneration = 999999

type keychainLink struct {
	// Generation is the generation whose key Wrapped holds; Wrapped is that
	// key sealed under generation+1's.
	Generation int64       `json:"generation"`
	Wrapped    wrappedBlob `json:"wrapped"`
}

type keychainResponse struct {
	Links []keychainLink `json:"links"`
	// NextFrom is the generation to pass as `from` for the next page; absent
	// when the range is exhausted.
	NextFrom *int64 `json:"nextFrom,omitempty"`
}

// keychain implements GET /api/groups/{groupId}/keychain?from=A&to=B -- the
// read side of the GENKEY# chain (docs/DESIGN.md, "Revocation mode"). It
// returns the links for generations A..B inclusive, ascending, so a member
// who holds generation B+1's key can walk back to A: link n is generation n's
// key wrapped under n+1's. Members only, with the roster's 404 for anyone else.
//
// The server verifies nothing about the links (it cannot open them); a
// missing generation in the range is not an error here, since the floor of a
// truncated chain looks the same as a gap. The client decides which it is.
func (h *Handler) keychain(w http.ResponseWriter, r *http.Request) {
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
	from, ok := parseGeneration(w, r, "from")
	if !ok {
		return
	}
	to, ok := parseGeneration(w, r, "to")
	if !ok {
		return
	}
	if from > to {
		WriteError(w, http.StatusBadRequest, "from: must not be greater than to")
		return
	}

	m, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not read the key chain")
		return
	}
	if m == nil {
		groupNotFound(w)
		return
	}
	links, next, err := h.db.ListGenerationKeys(r.Context(), groupID, from, to, maxKeychainPage)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not read the key chain")
		return
	}
	resp := keychainResponse{Links: make([]keychainLink, 0, len(links))}
	for _, l := range links {
		gen, err := strconv.ParseInt(l.SK[len("GENKEY#"):], 10, 64)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "could not read the key chain")
			return
		}
		resp.Links = append(resp.Links, keychainLink{Generation: gen, Wrapped: encodeWrappedBlob(l.Wrapped)})
	}
	if next >= 0 {
		resp.NextFrom = &next
	}
	WriteJSON(w, http.StatusOK, resp)
}

// parseGeneration reads a required query parameter as a generation in
// [0, maxKeychainGeneration], writing the 400 itself on failure.
func parseGeneration(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	raw := r.URL.Query().Get(name)
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 || n > maxKeychainGeneration {
		WriteError(w, http.StatusBadRequest, name+": must be a generation between 0 and "+strconv.Itoa(maxKeychainGeneration))
		return 0, false
	}
	return n, true
}
