package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

const (
	maxPinBodyBytes    = 16 * 1024
	maxPinSigningKeys  = 64
	defaultPinPageSize = 100
	maxPinPageSize     = 200
)

// pinRequest is the wire shape of PUT /api/pins/{userId}. The client signs
// crypto.PinPayload(pinnerUUID, pinnedUUID, pinnerSigningPublicKey,
// wrappingPublicKey, signingPublicKeys) under crypto.ContextPin with its own
// current signing key. All keys are base64.
type pinRequest struct {
	SigningPublicKeys      []string `json:"signingPublicKeys"`
	WrappingPublicKey      string   `json:"wrappingPublicKey"`
	PinnerSigningPublicKey string   `json:"pinnerSigningPublicKey"`
	Signature              string   `json:"signature"`
}

// pinEntry is one pin as served by GET /api/pins.
type pinEntry struct {
	PinnedUserID           string   `json:"pinnedUserId"`
	SigningPublicKeys      []string `json:"signingPublicKeys"`
	WrappingPublicKey      string   `json:"wrappingPublicKey"`
	PinnerSigningPublicKey string   `json:"pinnerSigningPublicKey"`
	Signature              string   `json:"signature"`
}

type listPinsResponse struct {
	Pins       []pinEntry `json:"pins"`
	NextCursor string     `json:"nextCursor,omitempty"`
}

// putPin implements PUT /api/pins/{userId} -- issue #63. It stores the
// caller's signed pin of another user's key set, replacing any earlier one.
//
// The server verifies the signature against the caller's CURRENT signing key
// and rejects anything else, so the table holds no garbage. That is hygiene,
// not the trust boundary: the party that must verify a pin is the client that
// reads it back, because the server is who a pin protects against.
func (h *Handler) putPin(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	pinnedID := r.PathValue("userId")
	if !idgen.ValidUUID(pinnedID) {
		userNotFound(w)
		return
	}
	if pinnedID == userID {
		WriteError(w, http.StatusBadRequest, "you cannot pin yourself")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPinBodyBytes)
	var req pinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	dec := base64.StdEncoding.DecodeString
	if len(req.SigningPublicKeys) < 1 || len(req.SigningPublicKeys) > maxPinSigningKeys {
		WriteError(w, http.StatusBadRequest, "signingPublicKeys: must hold 1 to "+strconv.Itoa(maxPinSigningKeys)+" keys")
		return
	}
	keys := make([][]byte, 0, len(req.SigningPublicKeys))
	seen := map[string]bool{}
	for _, k := range req.SigningPublicKeys {
		b, err := dec(k)
		if err != nil || len(b) != ed25519.PublicKeySize {
			WriteError(w, http.StatusBadRequest, "signingPublicKeys: each must be a base64 32-byte key")
			return
		}
		if seen[string(b)] {
			WriteError(w, http.StatusBadRequest, "signingPublicKeys: duplicate key")
			return
		}
		seen[string(b)] = true
		keys = append(keys, b)
	}
	wrapping, err := dec(req.WrappingPublicKey)
	if err != nil || len(wrapping) != 32 {
		WriteError(w, http.StatusBadRequest, "wrappingPublicKey: must be a base64 32-byte key")
		return
	}
	signer, err := dec(req.PinnerSigningPublicKey)
	if err != nil || len(signer) != ed25519.PublicKeySize {
		WriteError(w, http.StatusBadRequest, "pinnerSigningPublicKey: must be a base64 32-byte key")
		return
	}
	sig, err := dec(req.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		WriteError(w, http.StatusBadRequest, "signature: must be a base64 64-byte signature")
		return
	}

	// Every read happens before any 404 branch, as elsewhere.
	pinner, err := h.db.GetUserByID(r.Context(), userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not save pin")
		return
	}
	_, pinnedErr := h.db.GetUserByID(r.Context(), pinnedID)
	if errors.Is(pinnedErr, db.ErrUserNotFound) {
		userNotFound(w)
		return
	}
	if pinnedErr != nil {
		WriteError(w, http.StatusInternalServerError, "could not save pin")
		return
	}

	if string(signer) != string(pinner.SigningPublicKey) {
		WriteErrorWithCode(w, http.StatusConflict, "pin is not signed under your current key; re-sign", "pin_signer_stale")
		return
	}
	payload := crypto.PinPayload(userID, pinnedID, signer, wrapping, keys)
	if !crypto.Verify(pinner.SigningPublicKey, crypto.ContextPin, payload, sig) {
		WriteError(w, http.StatusBadRequest, "signature: does not verify")
		return
	}
	if err := h.db.PutPin(r.Context(), userID, pinnedID, keys, wrapping, signer, sig); err != nil {
		WriteError(w, http.StatusInternalServerError, "could not save pin")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listPins implements GET /api/pins -- issue #63. It serves the caller's OWN
// pins, paginated by pinned uuid. The server verifies nothing on read: the
// client must check every signature before trusting a pin.
func (h *Handler) listPins(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	limit := defaultPinPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxPinPageSize {
			WriteError(w, http.StatusBadRequest, "limit: must be between 1 and "+strconv.Itoa(maxPinPageSize))
			return
		}
		limit = n
	}
	cursor := r.URL.Query().Get("cursor")
	if cursor != "" && !idgen.ValidUUID(cursor) {
		WriteError(w, http.StatusBadRequest, "cursor: malformed")
		return
	}
	pins, next, err := h.db.ListPins(r.Context(), userID, cursor, limit)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not list pins")
		return
	}
	enc := base64.StdEncoding.EncodeToString
	entries := make([]pinEntry, 0, len(pins))
	for _, p := range pins {
		keys := make([]string, 0, len(p.SigningPublicKeys))
		for _, k := range p.SigningPublicKeys {
			keys = append(keys, enc(k))
		}
		entries = append(entries, pinEntry{
			PinnedUserID:           p.SK[len("PIN#"):],
			SigningPublicKeys:      keys,
			WrappingPublicKey:      enc(p.WrappingPublicKey),
			PinnerSigningPublicKey: enc(p.PinnerSigningPublicKey),
			Signature:              enc(p.Signature),
		})
	}
	WriteJSON(w, http.StatusOK, listPinsResponse{Pins: entries, NextCursor: next})
}
