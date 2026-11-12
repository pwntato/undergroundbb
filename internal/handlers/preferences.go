package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/models"
)

const (
	// maxPreferencesCiphertextLen bounds the sealed preferences. They hold the
	// theme choice and up to five custom themes of about 2 KB each, so the
	// general 4 KiB blob cap (maxCiphertextLen) is too small. The key rotation
	// re-seals the same blob, so it uses this cap too.
	maxPreferencesCiphertextLen = 32 * 1024
	// maxPreferencesBody covers the base64 of the largest blob plus the envelope.
	maxPreferencesBody = 64 * 1024
)

// decodePreferencesBlob is decodeWrappedBlob with the preferences size cap.
func decodePreferencesBlob(b wrappedBlob) (models.WrappedBlob, error) {
	nonce, err := decodeBase64Field(b.Nonce, crypto.NonceSize, crypto.NonceSize)
	if err != nil {
		return models.WrappedBlob{}, err
	}
	ciphertext, err := decodeBase64Field(b.Ciphertext, 0, maxPreferencesCiphertextLen)
	if err != nil {
		return models.WrappedBlob{}, err
	}
	return models.WrappedBlob{Nonce: nonce, Ciphertext: ciphertext}, nil
}

// preferencesResponse is GET /api/account/preferences: the account's key epoch
// (what a write must name) and the sealed blob, absent until one is written.
type preferencesResponse struct {
	KeyEpoch        uint64       `json:"keyEpoch"`
	PreferencesBlob *wrappedBlob `json:"preferencesBlob,omitempty"`
}

type putPreferencesRequest struct {
	ExpectedKeyEpoch uint64      `json:"expectedKeyEpoch"`
	PreferencesBlob  wrappedBlob `json:"preferencesBlob"`
}

// getPreferences implements GET /api/account/preferences (#366). The blob is
// opaque ciphertext the server never opens; only its owner is served it.
func (h *Handler) getPreferences(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	user, err := h.db.GetUserByIDConsistent(r.Context(), userID)
	if errors.Is(err, db.ErrUserNotFound) {
		WriteError(w, http.StatusNotFound, "account not found")
		return
	}
	if err != nil {
		WriteInternalError(w, r, err, "could not read preferences")
		return
	}
	if user.DeletedAt != "" {
		WriteError(w, http.StatusNotFound, "account not found")
		return
	}
	resp := preferencesResponse{KeyEpoch: user.KeyEpoch}
	if user.PreferencesBlob != nil {
		resp.PreferencesBlob = &wrappedBlob{
			Nonce:      base64.StdEncoding.EncodeToString(user.PreferencesBlob.Nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(user.PreferencesBlob.Ciphertext),
		}
	}
	WriteJSON(w, http.StatusOK, resp)
}

// putPreferences implements PUT /api/account/preferences (#366): replace the
// sealed blob. The caller names the KeyEpoch it sealed for; a rotation that
// landed since is 409 key_epoch_stale, because a blob sealed under the old key
// would never open again.
func (h *Handler) putPreferences(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPreferencesBody)
	var req putPreferencesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	blob, err := decodePreferencesBlob(req.PreferencesBlob)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "preferencesBlob: "+err.Error())
		return
	}
	switch err := h.db.SetPreferences(r.Context(), userID, req.ExpectedKeyEpoch, blob); {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, db.ErrUserNotFound):
		WriteError(w, http.StatusNotFound, "account not found")
	case errors.Is(err, db.ErrKeyEpochStale):
		WriteErrorWithCode(w, http.StatusConflict, "your keys were rotated by another request; reload and try again", "key_epoch_stale")
	default:
		WriteInternalError(w, r, err, "could not save preferences")
	}
}
