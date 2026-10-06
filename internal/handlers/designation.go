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
	"github.com/pwntato/undergroundbb/internal/models"
)

const (
	// minDesignationPeriodDays and maxDesignationPeriodDays bound the
	// inactivity period an admin may sign (docs/DESIGN.md, "Inactivity").
	minDesignationPeriodDays = 30
	maxDesignationPeriodDays = 365

	maxDesignationBodyBytes = 8 * 1024
)

// putDesignationRequest is the wire shape of PUT /api/groups/{id}/designation.
// The client signs crypto.SuccessorDesignationPayload(groupID, callerID,
// successorUserID, periodDays, designationSortKey, adminGrantRef) under
// crypto.ContextSuccessorDesignation with its own current signing key. An
// empty successorUserId revokes. AdminGrantRef is the sort key of the
// caller's OWN current grant, as for a role change.
type putDesignationRequest struct {
	DesignationSortKey string `json:"designationSortKey"`
	SuccessorUserID    string `json:"successorUserId"`
	PeriodDays         int    `json:"periodDays"`
	AdminGrantRef      string `json:"adminGrantRef"`
	Signature          string `json:"signature"`
}

type putDesignationResponse struct {
	SortKey string `json:"sortKey"`
}

// putDesignation implements PUT /api/groups/{groupId}/designation -- #161,
// docs/DESIGN.md, "Inactivity: the admin pre-signs a successor". Admin only. It
// appends a signed designation (or, with no successor, a revocation); nothing is
// ever overwritten. Nothing here activates a designation: the claim endpoint and
// the verifier rule that make it count are separate.
func (h *Handler) putDesignation(w http.ResponseWriter, r *http.Request) {
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
	r.Body = http.MaxBytesReader(w, r.Body, maxDesignationBodyBytes)
	var req putDesignationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}

	// Same rule as getGroup: every read happens before any 404 branch.
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not save designation")
		return
	}
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not save designation")
		return
	}
	if caller == nil || group == nil {
		groupNotFound(w)
		return
	}
	if caller.Role != models.RoleAdmin {
		WriteError(w, http.StatusForbidden, "only a group admin can designate a successor")
		return
	}
	if group.GroupType == "dm" {
		WriteError(w, http.StatusBadRequest, "a direct message has no roles")
		return
	}

	if req.PeriodDays < minDesignationPeriodDays || req.PeriodDays > maxDesignationPeriodDays {
		WriteError(w, http.StatusBadRequest, "periodDays: must be between "+strconv.Itoa(minDesignationPeriodDays)+" and "+strconv.Itoa(maxDesignationPeriodDays))
		return
	}
	if req.SuccessorUserID != "" {
		if !idgen.ValidUUID(req.SuccessorUserID) {
			WriteError(w, http.StatusBadRequest, "successorUserId: must be a uuid, or empty to revoke")
			return
		}
		if req.SuccessorUserID == userID {
			WriteError(w, http.StatusBadRequest, "you cannot designate yourself")
			return
		}
	}

	currentRef, hasStored := currentGrantRef(caller, group, userID)
	if currentRef == "" {
		WriteErrorWithCode(w, http.StatusConflict, "your own admin grant is not on record", "grantor_grant_missing")
		return
	}
	if req.AdminGrantRef != currentRef {
		WriteErrorWithCode(w, http.StatusConflict, "adminGrantRef is not your current grant; reload and re-sign", "grantor_ref_stale")
		return
	}

	day, ok := idgen.ValidDesignationSortKey(req.DesignationSortKey, userID)
	if !ok {
		WriteError(w, http.StatusBadRequest, "designationSortKey: must be a well-formed DESIGNATION# sort key for your uuid")
		return
	}
	if skew := time.Since(day.UTC()); skew < -grantDaySkewTolerance || skew > 24*time.Hour+grantDaySkewTolerance {
		WriteError(w, http.StatusBadRequest, "designationSortKey: day is not within tolerance of the current UTC day")
		return
	}
	// Strictly the same rule as a role change: the admin's own grant must be
	// dated strictly earlier, or the verifier would reject the designation.
	if msg, refused := grantorDatedTooLate(day, currentRef, userID, "this designation"); refused {
		WriteErrorWithCode(w, http.StatusConflict, msg, "grantor_granted_today")
		return
	}
	sig, err := decodeBase64Field(req.Signature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "signature: "+err.Error())
		return
	}

	// The signing key is the caller's own, read from their PROFILE, never from
	// the request (see createGroup).
	admin, err := h.db.GetUserByID(r.Context(), userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not save designation")
		return
	}
	payload := crypto.SuccessorDesignationPayload(groupID, userID, req.SuccessorUserID, req.PeriodDays, req.DesignationSortKey, req.AdminGrantRef)
	if !crypto.Verify(admin.SigningPublicKey, crypto.ContextSuccessorDesignation, payload, sig) {
		WriteError(w, http.StatusBadRequest, "signature: does not verify against the caller's current signing key")
		return
	}

	// Order within a day is unknowable, so a second designation by one admin on
	// one day is refused; they designate again tomorrow.
	taken, err := h.db.HasDesignationOnDay(r.Context(), groupID, userID, day.UTC().Format("2006-01-02"))
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not save designation")
		return
	}
	if taken {
		WriteErrorWithCode(w, http.StatusConflict, "you already designated today; order within a day cannot be told apart, so try again after 00:00 UTC", "designation_today")
		return
	}

	err = h.db.PutDesignation(r.Context(), db.PutDesignationInput{
		GroupID:             groupID,
		AdminUserID:         userID,
		SortKey:             req.DesignationSortKey,
		SuccessorUserID:     req.SuccessorUserID,
		PeriodDays:          req.PeriodDays,
		AdminGrantRef:       req.AdminGrantRef,
		AdminHasStoredGrant: hasStored,
		Signature:           sig,
	})
	if err != nil {
		switch {
		case errors.Is(err, db.ErrDesignationAdminChanged):
			WriteErrorWithCode(w, http.StatusConflict, "your own role changed; reload and re-sign", "grantor_changed")
		case errors.Is(err, db.ErrDesignationSuccessorGone):
			WriteError(w, http.StatusBadRequest, "successorUserId: not a member of this group")
		case errors.Is(err, db.ErrDesignationSuccessorDeleted):
			WriteErrorWithCode(w, http.StatusGone, "that member's account was deleted, so they cannot be designated", "subject_deleted")
		case errors.Is(err, db.ErrDesignationKeyTaken):
			WriteErrorWithCode(w, http.StatusConflict, "designationSortKey is taken; generate a new one and re-sign", "designation_key_taken")
		case errors.Is(err, db.ErrDesignationConflict):
			WriteErrorWithCode(w, http.StatusConflict, "another change was in progress; retry", "conflict_retry")
		default:
			WriteError(w, http.StatusInternalServerError, "could not save designation")
		}
		return
	}
	WriteJSON(w, http.StatusOK, putDesignationResponse{SortKey: req.DesignationSortKey})
}

// designationEntry is one DESIGNATION# row as served. Like a grant entry, it
// carries everything a verifier needs to rebuild the signed bytes
// (crypto.SuccessorDesignationPayload) and no signing key: nothing signed
// binds one, so a verifier resolves the admin's key for the row's day from
// their key history.
type designationEntry struct {
	SortKey         string `json:"sortKey"`
	AdminUserID     string `json:"adminUserId"`
	SuccessorUserID string `json:"successorUserId,omitempty"`
	PeriodDays      int    `json:"periodDays"`
	AdminGrantRef   string `json:"adminGrantRef"`
	Signature       string `json:"signature"`
}

type listDesignationsResponse struct {
	Designations []designationEntry `json:"designations"`
	NextCursor   string             `json:"nextCursor,omitempty"`
}

// listDesignations implements GET /api/groups/{groupId}/designations -- #161.
// Members only, with the roster's 404 for anyone else. Serves the signed rows
// and verifies nothing, like listGrants.
func (h *Handler) listDesignations(w http.ResponseWriter, r *http.Request) {
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
	limit := defaultGrantPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxGrantPageSize {
			WriteError(w, http.StatusBadRequest, "limit: must be between 1 and "+strconv.Itoa(maxGrantPageSize))
			return
		}
		limit = n
	}
	cursor := r.URL.Query().Get("cursor")
	if cursor != "" {
		const start, end = len("DESIGNATION#"), len("DESIGNATION#") + 36
		if len(cursor) < end {
			WriteError(w, http.StatusBadRequest, "cursor: malformed")
			return
		}
		// Any admin in this group is a valid cursor owner, so only the shape check
		// does work; the PK is fixed to groupID below.
		if _, ok := idgen.ValidDesignationSortKey(cursor, cursor[start:end]); !ok {
			WriteError(w, http.StatusBadRequest, "cursor: malformed")
			return
		}
	}

	m, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not list designations")
		return
	}
	if m == nil {
		groupNotFound(w)
		return
	}
	rows, next, err := h.db.ListDesignations(r.Context(), groupID, cursor, limit)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not list designations")
		return
	}
	enc := base64.StdEncoding.EncodeToString
	entries := make([]designationEntry, 0, len(rows))
	for _, d := range rows {
		entries = append(entries, designationEntry{
			SortKey:         d.SK,
			AdminUserID:     d.AdminUserID,
			SuccessorUserID: d.SuccessorUserID,
			PeriodDays:      d.PeriodDays,
			AdminGrantRef:   d.AdminGrantRef,
			Signature:       enc(d.Signature),
		})
	}
	WriteJSON(w, http.StatusOK, listDesignationsResponse{Designations: entries, NextCursor: next})
}
