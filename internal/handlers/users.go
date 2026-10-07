package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// supersededKeyEntry is one prior signing key and the interval it was
// current for.
type supersededKeyEntry struct {
	PublicKey string `json:"publicKey"`
	From      string `json:"from"`
	Until     string `json:"until,omitempty"`
}

// userProjection is the wire shape of GET /api/users/{userId}: the username
// and the public keys, current and superseded, and nothing else. It is an
// explicit allowlist rather than the User item with fields blanked, so a
// field added to the item later is not served by default. The Argon2id salt
// and the wrapped private keys are offline-cracking material and are
// available only from POST /api/auth/challenge (docs/DESIGN.md, "The actor's
// username").
type userProjection struct {
	UserID                string               `json:"userId"`
	Username              string               `json:"username"`
	SigningPublicKey      string               `json:"signingPublicKey"`
	WrappingPublicKey     string               `json:"wrappingPublicKey"`
	SupersededSigningKeys []supersededKeyEntry `json:"supersededSigningKeys"`
	// Deleted marks a tombstoned account (#77): the username is empty and the
	// keys are served only so signatures the user made still verify.
	Deleted bool `json:"deleted,omitempty"`
}

// getUser implements GET /api/users/{userId} -- issue #157. Any
// authenticated user may read any user's projection. A malformed id and an
// unknown id get the same 404.
func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := sessionUserID(r); !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	id := r.PathValue("userId")
	if !idgen.ValidUUID(id) {
		userNotFound(w)
		return
	}
	user, err := h.db.GetUserByID(r.Context(), id)
	if errors.Is(err, db.ErrUserNotFound) {
		userNotFound(w)
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not read user")
		return
	}
	WriteJSON(w, http.StatusOK, projectUser(id, user))
}

// projectUser is the one place a User item becomes its served projection, for
// both the single and the batch read.
func projectUser(id string, user *models.User) userProjection {
	superseded := make([]supersededKeyEntry, 0, len(user.SupersededSigningKeys))
	for _, k := range user.SupersededSigningKeys {
		superseded = append(superseded, supersededKeyEntry{
			PublicKey: base64.StdEncoding.EncodeToString(k.PublicKey),
			From:      k.From,
			Until:     k.Until,
		})
	}
	return userProjection{
		UserID:                id,
		Username:              user.Username,
		SigningPublicKey:      base64.StdEncoding.EncodeToString(user.SigningPublicKey),
		WrappingPublicKey:     base64.StdEncoding.EncodeToString(user.WrappingPublicKey),
		SupersededSigningKeys: superseded,
		Deleted:               user.DeletedAt != "",
	}
}

const maxBatchUsersBodyBytes = 16 * 1024

type batchUsersRequest struct {
	IDs []string `json:"ids"`
}

// batchUsersResponse answers each requested id exactly once: Users holds the
// projections that exist, NotFound the ids that do not (unknown or malformed,
// the same answer GET gives with a 404). Order is not significant.
type batchUsersResponse struct {
	Users    []userProjection `json:"users"`
	NotFound []string         `json:"notFound"`
}

// batchUsers implements POST /api/users:batch -- issue #160. It returns the
// same allowlist projection as getUser for up to db.MaxBatchUsers ids in one
// request, so a large roster costs one call per hundred members rather than
// one per member. Any authenticated user may read any user's projection, as
// with the single read.
func (h *Handler) batchUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := sessionUserID(r); !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBatchUsersBodyBytes)
	var req batchUsersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > db.MaxBatchUsers {
		WriteError(w, http.StatusBadRequest, "ids: between 1 and "+strconv.Itoa(db.MaxBatchUsers)+" ids per request")
		return
	}
	resp := batchUsersResponse{Users: []userProjection{}, NotFound: []string{}}
	seen := make(map[string]bool, len(req.IDs))
	valid := make([]string, 0, len(req.IDs))
	for _, id := range req.IDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		if idgen.ValidUUID(id) {
			valid = append(valid, id)
		} else {
			resp.NotFound = append(resp.NotFound, id)
		}
	}
	users, err := h.db.BatchGetUsers(r.Context(), valid)
	if errors.Is(err, db.ErrBatchUsersIncomplete) {
		WriteError(w, http.StatusServiceUnavailable, "could not read every user; try again")
		return
	}
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not read users")
		return
	}
	for _, id := range valid {
		if user, ok := users[id]; ok {
			resp.Users = append(resp.Users, projectUser(id, user))
		} else {
			resp.NotFound = append(resp.NotFound, id)
		}
	}
	WriteJSON(w, http.StatusOK, resp)
}

func userNotFound(w http.ResponseWriter) {
	WriteError(w, http.StatusNotFound, "user not found")
}
