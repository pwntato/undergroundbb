package handlers

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

const (
	// maxRotateKeysBodyBytes bounds POST /api/account/rotate-keys: the
	// credential re-wrap (as for a password change) plus the roster list, up to
	// maxRosterEntries 16-byte ids.
	maxRotateKeysBodyBytes = 256 * 1024
	// maxRosterEntries bounds the roster behind a rotation's digest: one id per
	// PIN# and VERIFIED# row the caller holds. A row per entry keeps the
	// KEYCHANGE# item (16 bytes an entry, 8192 of them is 128 KiB) well inside
	// DynamoDB's 400 KiB item limit.
	maxRosterEntries = 8192
	rosterEntrySize  = 16

	maxHandoffBodyBytes = 4 * 1024
)

// rotateKeysRequest is the wire shape of POST /api/account/rotate-keys
// (docs/DESIGN.md, "What a rotation writes"). The client signs
// crypto.KeyRotationPayload(userUUID, oldSigning, oldWrapping, newSigning,
// newWrapping, signedDay, expectedKeyEpoch, RosterDigest(roster)) twice under
// crypto.ContextKeyRotation: OldSignature with the current Ed25519 key,
// NewSignature with the new one. All keys and signatures are base64.
type rotateKeysRequest struct {
	ExpectedKeyEpoch          uint64 `json:"expectedKeyEpoch"`
	ExpectedCredentialVersion int64  `json:"expectedCredentialVersion"`
	SignedDay                 string `json:"signedDay"`

	NewSigningPublicKey  string `json:"newSigningPublicKey"`
	NewWrappingPublicKey string `json:"newWrappingPublicKey"`

	// Roster is the list behind the digest both keys signed: one
	// crypto.RosterEntryID per PIN# and VERIFIED# row the caller holds.
	Roster []string `json:"roster"`

	OldSignature string `json:"oldSignature"`
	NewSignature string `json:"newSignature"`

	// PreferencesBlob is the preferences blob re-sealed under the new X25519
	// key. Required when the account has one: the sealing key derives from the
	// X25519 private key, so the old blob would otherwise become unreadable.
	PreferencesBlob *wrappedBlob `json:"preferencesBlob,omitempty"`

	credentialRewrapFields
}

type rotateKeysResponse struct {
	KeyEpoch          uint64 `json:"keyEpoch"`
	CredentialVersion int64  `json:"credentialVersion"`
}

// groupsConflict is a 409 that names the groups it is about, so the flow knows
// which handoff rows to (re)write or which job to wait for.
type groupsConflict struct {
	Error  string   `json:"error"`
	Code   string   `json:"code"`
	Groups []string `json:"groups"`
}

func writeGroupsConflict(w http.ResponseWriter, msg, code string, groups []string) {
	slices.Sort(groups)
	WriteJSON(w, http.StatusConflict, groupsConflict{Error: msg, Code: code, Groups: groups})
}

// rotateKeys implements POST /api/account/rotate-keys -- issue #62, slice 2.
//
// A session AND two signatures: the old Ed25519 key proves the caller holds the
// keys being replaced (so this is not a way out of losing both credentials, and
// nobody can rotate an account they cannot already open), the new one proves
// they hold the new private key. The server checks both, the signed day against
// its clock, and that the epoch is the one it holds, which also makes the
// request single-use. One rotation per cooldown per account.
//
// Before the transaction it checks the handoff rows (docs/DESIGN.md, "The self
// re-key must survive a closed tab"): 409 handoff_pending while a row naming
// the current key remains for a group the caller still administers,
// rotation_in_progress for a group whose newest key the caller's own entry has
// not reached, and handoff_required for any administered group without a row
// naming the new key at that group's current generation. After it commits, it
// sweeps rows nothing can use.
func (h *Handler) rotateKeys(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRotateKeysBodyBytes)
	var req rotateKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if req.ExpectedCredentialVersion <= 0 {
		WriteError(w, http.StatusBadRequest, "expectedCredentialVersion: must be positive")
		return
	}
	newSigning, err := decodeBase64Field(req.NewSigningPublicKey, ed25519.PublicKeySize, ed25519.PublicKeySize)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "newSigningPublicKey: "+err.Error())
		return
	}
	newWrapping, err := decodeBase64Field(req.NewWrappingPublicKey, x25519PublicKeySize, x25519PublicKeySize)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "newWrappingPublicKey: "+err.Error())
		return
	}
	oldSig, err := decodeBase64Field(req.OldSignature, ed25519.SignatureSize, ed25519.SignatureSize)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "oldSignature: "+err.Error())
		return
	}
	newSig, err := decodeBase64Field(req.NewSignature, ed25519.SignatureSize, ed25519.SignatureSize)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "newSignature: "+err.Error())
		return
	}
	if len(req.Roster) > maxRosterEntries {
		WriteError(w, http.StatusBadRequest, "roster: too many entries")
		return
	}
	roster := make([][]byte, 0, len(req.Roster))
	seenRoster := make(map[string]bool, len(req.Roster))
	for _, e := range req.Roster {
		b, err := decodeBase64Field(e, rosterEntrySize, rosterEntrySize)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "roster: each entry must be a base64 16-byte id")
			return
		}
		if seenRoster[string(b)] {
			WriteError(w, http.StatusBadRequest, "roster: duplicate entry")
			return
		}
		seenRoster[string(b)] = true
		roster = append(roster, b)
	}
	decoded, err := decodeCredentialRewrapFields(req.credentialRewrapFields)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	var prefs *models.WrappedBlob
	if req.PreferencesBlob != nil {
		blob, err := decodeWrappedBlob(*req.PreferencesBlob)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "preferencesBlob: "+err.Error())
			return
		}
		prefs = &blob
	}

	// Every read happens before the first answer that depends on it.
	user, err := h.db.GetUserByID(r.Context(), userID)
	if errors.Is(err, db.ErrUserNotFound) {
		WriteError(w, http.StatusNotFound, "account not found")
		return
	}
	if err != nil {
		WriteInternalError(w, r, err, "could not rotate keys")
		return
	}
	if user.DeletedAt != "" {
		WriteError(w, http.StatusNotFound, "account not found")
		return
	}
	if !validSignedDay(req.SignedDay) {
		// A day that has passed is coded: it never becomes valid again, so a
		// client can stop resending the request. It does NOT prove an earlier
		// send of it cannot still commit (that send may have passed this check
		// just before the window closed and be mid-transaction), so the client
		// confirms with a session read after the longest a send can stay in
		// flight. A future day stays uncoded: it becomes valid later.
		if signedDayPassed(req.SignedDay) {
			WriteErrorWithCode(w, http.StatusBadRequest, "signedDay: must be today's UTC date (YYYY-MM-DD)", "signed_day_stale")
			return
		}
		WriteError(w, http.StatusBadRequest, "signedDay: must be today's UTC date (YYYY-MM-DD)")
		return
	}
	if req.ExpectedKeyEpoch != user.KeyEpoch {
		WriteErrorWithCode(w, http.StatusConflict, "your keys were rotated by another request; reload and try again", "key_epoch_stale")
		return
	}
	if user.PreferencesBlob != nil && prefs == nil {
		WriteError(w, http.StatusBadRequest, "preferencesBlob: required, re-seal your preferences under the new key")
		return
	}
	// A reused key would blur the interval history (a superseded key's interval
	// is when it was current) and a "rotation" to the same wrapping key would
	// leave the old private key reading everything.
	if bytes.Equal(newWrapping, user.WrappingPublicKey) {
		WriteError(w, http.StatusBadRequest, "newWrappingPublicKey: must differ from your current key")
		return
	}
	if bytes.Equal(newSigning, user.SigningPublicKey) {
		WriteError(w, http.StatusBadRequest, "newSigningPublicKey: must differ from your current key")
		return
	}
	for _, old := range user.SupersededSigningKeys {
		if bytes.Equal(newSigning, old.PublicKey) {
			WriteError(w, http.StatusBadRequest, "newSigningPublicKey: must not be a key you used before")
			return
		}
	}
	digest := crypto.RosterDigest(roster)
	payload := crypto.KeyRotationPayload(userID, user.SigningPublicKey, user.WrappingPublicKey, newSigning, newWrapping, req.SignedDay, user.KeyEpoch, digest)
	if !crypto.Verify(user.SigningPublicKey, crypto.ContextKeyRotation, payload, oldSig) {
		WriteError(w, http.StatusBadRequest, "oldSignature: does not verify under your current key")
		return
	}
	if !crypto.Verify(newSigning, crypto.ContextKeyRotation, payload, newSig) {
		WriteError(w, http.StatusBadRequest, "newSignature: does not verify under the new key")
		return
	}

	handoffSeq, ok := h.checkHandoffs(w, r, userID, user, newWrapping)
	if !ok {
		return
	}

	day, _ := time.Parse("2006-01-02", req.SignedDay)
	from := time.Unix(0, 0).UTC().Format(time.RFC3339)
	if n := len(user.SupersededSigningKeys); n > 0 {
		// The key being retired became current when the one before it ended.
		from = user.SupersededSigningKeys[n-1].Until
	}
	newVersion := req.ExpectedCredentialVersion + 1
	creds := db.RewrapCredentialsInput{
		UserID:                    userID,
		ExpectedCredentialVersion: req.ExpectedCredentialVersion,
		NewCredentialVersion:      newVersion,

		Salt:               decoded.Salt,
		Argon2Params:       decoded.Argon2Params,
		WrappedPrivateKeys: decoded.WrappedPrivateKeys,

		RecoverySalt:               decoded.RecoverySalt,
		RecoveryArgon2Params:       decoded.RecoveryArgon2Params,
		RecoveryWrappedPrivateKeys: decoded.RecoveryWrappedPrivateKeys,

		RecoveryVerifierSalt:   decoded.RecoveryVerifierSalt,
		RecoveryVerifierParams: decoded.RecoveryVerifierParams,
		RecoveryVerifier:       decoded.RecoveryVerifier,
	}
	err = h.db.RotateKeys(r.Context(), db.RotateKeysInput{
		Credentials:        creds,
		ExpectedKeyEpoch:   user.KeyEpoch,
		ExpectedHandoffSeq: handoffSeq,

		OldSigningPublicKey:  user.SigningPublicKey,
		OldWrappingPublicKey: user.WrappingPublicKey,
		NewSigningPublicKey:  newSigning,
		NewWrappingPublicKey: newWrapping,

		// Day resolution on purpose: keysOnDay accepts both keys on the day of
		// the rotation, and nothing stores when in the day it happened (#147).
		SupersededFrom:  from,
		SupersededUntil: day.UTC().Format(time.RFC3339),

		PreferencesBlob: prefs,
		KeyChange: models.KeyChange{
			Day:                  req.SignedDay,
			OldSigningPublicKey:  user.SigningPublicKey,
			OldWrappingPublicKey: user.WrappingPublicKey,
			NewSigningPublicKey:  newSigning,
			NewWrappingPublicKey: newWrapping,
			RosterDigest:         digest,
			Roster:               roster,
			OldSignature:         oldSig,
			NewSignature:         newSig,
		},

		Cooldown: h.cfg.KeyRotationCooldown,
		Now:      time.Now(),
	})
	switch {
	case err == nil:
	case errors.Is(err, db.ErrRotationCooldown):
		WriteErrorWithCode(w, http.StatusTooManyRequests, "you rotated your keys recently; try again later", "rotation_cooldown")
		return
	case errors.Is(err, db.ErrKeyEpochStale):
		WriteErrorWithCode(w, http.StatusConflict, "your keys were rotated by another request; reload and try again", "key_epoch_stale")
		return
	case errors.Is(err, db.ErrCredentialVersionStale):
		WriteError(w, http.StatusConflict, errCredentialVersionStale)
		return
	case errors.Is(err, db.ErrHandoffChanged):
		WriteErrorWithCode(w, http.StatusConflict, "your handoffs changed while the rotation was being checked; try again", "handoff_changed")
		return
	case errors.Is(err, db.ErrUserNotFound):
		WriteError(w, http.StatusNotFound, "account not found")
		return
	default:
		WriteInternalError(w, r, err, "could not rotate keys")
		return
	}

	// The commit is done, so nothing below can turn this into an error. A failed
	// sweep leaves rows that the next rotation's sweep deletes; they name a key
	// that is not the account's current one or a group it no longer administers.
	if err := h.db.SweepHandoffs(r.Context(), userID, newWrapping); err != nil {
		log.Printf("%s %s: sweeping handoff rows after rotation: %v", r.Method, r.URL.Path, err)
	}
	// SessionGeneration moved with the commit and ended every session, this
	// one included. Give the caller a fresh token, as a password change does.
	gen, err := h.db.GetSessionGeneration(r.Context(), userID)
	if err != nil {
		log.Printf("%s %s: session generation after key rotation: %v", r.Method, r.URL.Path, err)
		clearSessionCookie(w)
	} else {
		setSessionCookie(w, h.sessions.Issue(userID, gen, h.cfg.SessionTTL), h.cfg.SessionTTL)
	}
	WriteJSON(w, http.StatusOK, rotateKeysResponse{KeyEpoch: user.KeyEpoch + 1, CredentialVersion: newVersion})
}

// checkHandoffs applies the pre-commit handoff rules and writes the 409 itself
// when one fails. It returns the HANDOFFSEQ value read before the rows, which
// RotateKeys' transaction checks is unchanged, so a row written or deleted after
// this read fails the rotation instead of leaving it committed without one.
func (h *Handler) checkHandoffs(w http.ResponseWriter, r *http.Request, userID string, user *models.User, newWrapping []byte) (int64, bool) {
	seq, err := h.db.GetHandoffSeq(r.Context(), userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not rotate keys")
		return 0, false
	}
	rows, err := h.db.ListHandoffs(r.Context(), userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not rotate keys")
		return 0, false
	}
	admin, err := h.db.ListAdminGroups(r.Context(), userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not rotate keys")
		return 0, false
	}
	administered := make(map[string]bool, len(admin))
	for _, g := range admin {
		administered[g.GroupID] = true
	}
	byGroup := make(map[string]models.Handoff, len(rows))
	var pending []string
	for _, row := range rows {
		gid := row.SK[len("HANDOFF#"):]
		byGroup[gid] = row
		// A row naming the current key is a committed rotation's self re-key
		// that has not run. It only blocks while the caller still administers
		// the group: otherwise nothing can use it, and the sweep after this
		// rotation removes it.
		if bytes.Equal(row.NewWrappingPublicKey, user.WrappingPublicKey) && administered[gid] {
			pending = append(pending, gid)
		}
	}
	if len(pending) > 0 {
		writeGroupsConflict(w, "finish the key changes already under way in these groups before rotating again", "handoff_pending", pending)
		return 0, false
	}

	var behind, missing []string
	for _, g := range admin {
		cur, err := h.db.GroupCurrentGeneration(r.Context(), g.GroupID)
		if err != nil {
			WriteInternalError(w, r, err, "could not rotate keys")
			return 0, false
		}
		if g.Generation != cur {
			behind = append(behind, g.GroupID)
			continue
		}
		row, has := byGroup[g.GroupID]
		if !has || !bytes.Equal(row.NewWrappingPublicKey, newWrapping) || row.Generation != cur {
			missing = append(missing, g.GroupID)
		}
	}
	if len(behind) > 0 {
		writeGroupsConflict(w, "a key rotation is under way in these groups and has not reached you yet; wait for it to finish", "rotation_in_progress", behind)
		return 0, false
	}
	if len(missing) > 0 {
		writeGroupsConflict(w, "write a handoff for these groups first", "handoff_required", missing)
		return 0, false
	}
	return seq, true
}

// handoffRequest is the wire shape of PUT /api/account/rotation-handoff/{groupId}:
// the group's current key (at Generation) wrapped to the NEW X25519 key with
// crypto.HandoffWrapAAD.
type handoffRequest struct {
	Generation           int64      `json:"generation"`
	NewWrappingPublicKey string     `json:"newWrappingPublicKey"`
	WrappedGroupKey      wrappedKey `json:"wrappedGroupKey"`
}

type handoffEntry struct {
	GroupID              string     `json:"groupId"`
	Generation           int64      `json:"generation"`
	NewWrappingPublicKey string     `json:"newWrappingPublicKey"`
	WrappedGroupKey      wrappedKey `json:"wrappedGroupKey"`
}

type listHandoffsResponse struct {
	Handoffs []handoffEntry `json:"handoffs"`
}

// putHandoff implements PUT /api/account/rotation-handoff/{groupId}. It is
// authenticated by the OLD session, before rotate-keys, and is an ordinary
// write so the number of administered groups never meets a transaction limit.
//
// It refuses: a group the caller is not an admin of, or whose current
// generation is not Generation or whose own entry is not at it (409
// handoff_stale); a row naming the account's current key (409
// handoff_pending, the committed rotation's only copy); a key equal to the
// current one (400).
func (h *Handler) putHandoff(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	groupID := r.PathValue("groupId")
	if !idgen.ValidUUID(groupID) {
		WriteError(w, http.StatusNotFound, "group not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxHandoffBodyBytes)
	var req handoffRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if req.Generation < 0 {
		WriteError(w, http.StatusBadRequest, "generation: must not be negative")
		return
	}
	newWrapping, err := decodeBase64Field(req.NewWrappingPublicKey, x25519PublicKeySize, x25519PublicKeySize)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "newWrappingPublicKey: "+err.Error())
		return
	}
	wrapped, err := decodeWrappedKey(req.WrappedGroupKey)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "wrappedGroupKey: "+err.Error())
		return
	}
	user, err := h.db.GetUserByID(r.Context(), userID)
	if errors.Is(err, db.ErrUserNotFound) {
		WriteError(w, http.StatusNotFound, "account not found")
		return
	}
	if err != nil {
		WriteInternalError(w, r, err, "could not save handoff")
		return
	}
	if user.DeletedAt != "" {
		WriteError(w, http.StatusNotFound, "account not found")
		return
	}
	if bytes.Equal(newWrapping, user.WrappingPublicKey) {
		WriteError(w, http.StatusBadRequest, "newWrappingPublicKey: must differ from your current key")
		return
	}
	cur, err := h.db.GroupCurrentGeneration(r.Context(), groupID)
	if err != nil {
		WriteInternalError(w, r, err, "could not save handoff")
		return
	}
	if req.Generation != cur {
		WriteErrorWithCode(w, http.StatusConflict, "the group's key moved; wrap the current one", "handoff_stale")
		return
	}
	err = h.db.PutHandoff(r.Context(), db.PutHandoffInput{
		UserID:               userID,
		GroupID:              groupID,
		Generation:           req.Generation,
		NewWrappingPublicKey: newWrapping,
		WrappedGroupKey:      wrapped,
		CurrentWrappingKey:   user.WrappingPublicKey,
	})
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, db.ErrHandoffNotAdmin):
		WriteErrorWithCode(w, http.StatusConflict, "you are not an admin of this group at its current key", "handoff_stale")
	case errors.Is(err, db.ErrHandoffPending):
		WriteErrorWithCode(w, http.StatusConflict, "a handoff for your current key is waiting to be used; finish it first", "handoff_pending")
	case errors.Is(err, db.ErrHandoffAccountChanged):
		WriteErrorWithCode(w, http.StatusConflict, "your keys changed; reload and try again", "key_epoch_stale")
	default:
		WriteInternalError(w, r, err, "could not save handoff")
	}
}

// deleteHandoff implements DELETE /api/account/rotation-handoff/{groupId}: the
// client's cleanup for a row whose start was refused because the generation
// moved or the caller is no longer an admin or a member. Deleting a row that
// is not there is a success.
func (h *Handler) deleteHandoff(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	groupID := r.PathValue("groupId")
	if !idgen.ValidUUID(groupID) {
		WriteError(w, http.StatusNotFound, "group not found")
		return
	}
	if err := h.db.DeleteHandoff(r.Context(), userID, groupID); err != nil {
		WriteInternalError(w, r, err, "could not delete handoff")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listHandoffs implements GET /api/account/rotation-handoff: the caller's own
// rows, ciphertext only.
func (h *Handler) listHandoffs(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	rows, err := h.db.ListHandoffs(r.Context(), userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not list handoffs")
		return
	}
	enc := base64.StdEncoding.EncodeToString
	out := make([]handoffEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, handoffEntry{
			GroupID:              row.GroupID,
			Generation:           row.Generation,
			NewWrappingPublicKey: enc(row.NewWrappingPublicKey),
			WrappedGroupKey: wrappedKey{
				EphemeralPub: enc(row.WrappedGroupKey.EphemeralPub),
				Nonce:        enc(row.WrappedGroupKey.Nonce),
				Ciphertext:   enc(row.WrappedGroupKey.Ciphertext),
			},
		})
	}
	WriteJSON(w, http.StatusOK, listHandoffsResponse{Handoffs: out})
}

// signedDayPassed reports whether a well-formed signed day is past the window
// validSignedDay accepts, as opposed to ahead of it.
func signedDayPassed(s string) bool {
	day, err := time.Parse("2006-01-02", s)
	if err != nil || day.Format("2006-01-02") != s {
		return false
	}
	return time.Since(day.UTC()) > 24*time.Hour+grantDaySkewTolerance
}
