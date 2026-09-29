package handlers

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
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
	superseded := make([]supersededKeyEntry, 0, len(user.SupersededSigningKeys))
	for _, k := range user.SupersededSigningKeys {
		superseded = append(superseded, supersededKeyEntry{
			PublicKey: base64.StdEncoding.EncodeToString(k.PublicKey),
			From:      k.From,
			Until:     k.Until,
		})
	}
	WriteJSON(w, http.StatusOK, userProjection{
		UserID:                id,
		Username:              user.Username,
		SigningPublicKey:      base64.StdEncoding.EncodeToString(user.SigningPublicKey),
		WrappingPublicKey:     base64.StdEncoding.EncodeToString(user.WrappingPublicKey),
		SupersededSigningKeys: superseded,
	})
}

func userNotFound(w http.ResponseWriter) {
	WriteError(w, http.StatusNotFound, "user not found")
}
