package handlers

import (
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

const maxClaimBodyBytes = 8 * 1024

const dayLayout = "2006-01-02"

// claimDesignationRequest is the wire shape of POST
// /api/groups/{id}/designation/claim. The caller is the designated successor
// and signs crypto.SuccessorClaimPayload(groupID, callerID, designationSortKey,
// claimSortKey) under crypto.ContextSuccessorClaim with their own current key.
// The claim day is the day in claimSortKey, chosen and signed by the caller.
type claimDesignationRequest struct {
	DesignationSortKey string `json:"designationSortKey"`
	ClaimSortKey       string `json:"claimSortKey"`
	Signature          string `json:"signature"`
}

type claimDesignationResponse struct {
	Role         string `json:"role"`
	GrantSortKey string `json:"grantSortKey"`
}

// claimDesignation implements POST /api/groups/{groupId}/designation/claim --
// #161, docs/DESIGN.md, "Inactivity: the admin pre-signs a successor". The
// designated successor claims the admin role the admin pre-signed for them.
// Every check here is the server's honest-path gate; the client verifier
// (web/src/lib/crypto/grant-chain.ts) re-checks what it can from signed rows
// and does not rely on the ones that need the server's clock or login record.
//
// Checks that need only signed rows (and are repeated by the verifier): the
// designation names the caller and is not a revocation; it is the admin's only
// designation dated from its own day to the claim day (a later or same-day
// one, which cancels it, voids it); the admin received no grant in that window
// (a demotion, removal or re-promotion lapses it); no earlier activation cites
// it; and the claim day is at least periodDays after the designation. Checks
// only the server can make: the admin's current grant is still the one the
// designation signed, the caller is a live member who was already one on the
// designation's day, and neither the admin nor any other admin has logged in
// within the period, all measured from the later of their last login and the
// designation's day, to the claim's signed day.
func (h *Handler) claimDesignation(w http.ResponseWriter, r *http.Request) {
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
	r.Body = http.MaxBytesReader(w, r.Body, maxClaimBodyBytes)
	var req claimDesignationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	const fail = "could not claim the designation"

	// Same rule as getGroup: every read happens before any 404 branch.
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, fail)
		return
	}
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, fail)
		return
	}
	if caller == nil || group == nil {
		groupNotFound(w)
		return
	}
	if group.GroupType == "dm" {
		WriteError(w, http.StatusBadRequest, "a direct message has no roles")
		return
	}
	if caller.Role == models.RoleAdmin {
		WriteErrorWithCode(w, http.StatusConflict, "you are already an admin of this group", "already_admin")
		return
	}

	adminID, designationDay, ok := idgen.DesignationAdmin(req.DesignationSortKey)
	if !ok {
		WriteError(w, http.StatusBadRequest, "designationSortKey: must be a well-formed DESIGNATION# sort key")
		return
	}
	claimDay, ok := idgen.ValidGrantSortKey(req.ClaimSortKey, userID)
	if !ok {
		WriteError(w, http.StatusBadRequest, "claimSortKey: must be a well-formed GRANT# sort key for your uuid")
		return
	}
	if skew := time.Since(claimDay.UTC()); skew < -grantDaySkewTolerance || skew > 24*time.Hour+grantDaySkewTolerance {
		WriteError(w, http.StatusBadRequest, "claimSortKey: day is not within tolerance of the current UTC day")
		return
	}
	sig, err := decodeBase64Field(req.Signature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "signature: "+err.Error())
		return
	}

	// The signing key is the caller's own, read from their PROFILE, never from
	// the request (see createGroup).
	successor, err := h.db.GetUserByID(r.Context(), userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, fail)
		return
	}
	payload := crypto.SuccessorClaimPayload(groupID, userID, req.DesignationSortKey, req.ClaimSortKey)
	if !crypto.Verify(successor.SigningPublicKey, crypto.ContextSuccessorClaim, payload, sig) {
		WriteError(w, http.StatusBadRequest, "signature: does not verify against the caller's current signing key")
		return
	}

	designation, err := h.db.GetDesignation(r.Context(), groupID, req.DesignationSortKey)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, fail)
		return
	}
	if designation == nil {
		WriteErrorWithCode(w, http.StatusNotFound, "no such designation", "designation_not_found")
		return
	}
	if designation.SuccessorUserID != userID {
		// A revocation has no successor, so it lands here too.
		WriteErrorWithCode(w, http.StatusConflict, "this designation does not name you", "designation_not_yours")
		return
	}

	// Signed-row checks, in the verifier's order.
	period := time.Duration(designation.PeriodDays) * 24 * time.Hour
	if designation.PeriodDays < minDesignationPeriodDays || designation.PeriodDays > maxDesignationPeriodDays {
		WriteErrorWithCode(w, http.StatusConflict, "this designation's period is out of range", "designation_invalid")
		return
	}
	others, err := h.db.ListAdminDesignations(r.Context(), groupID, adminID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, fail)
		return
	}
	for _, o := range others {
		if o.SK == designation.SK {
			continue
		}
		if _, d, ok := idgen.DesignationAdmin(o.SK); ok && !d.Before(designationDay) && !d.After(claimDay) {
			WriteErrorWithCode(w, http.StatusConflict, "the admin signed another designation since this one, which replaces or cancels it", "designation_superseded")
			return
		}
	}
	toAdmin, err := h.db.ListGrantsTo(r.Context(), groupID, adminID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, fail)
		return
	}
	for _, g := range toAdmin {
		if d, ok := idgen.ValidGrantSortKey(g.SK, adminID); ok && !d.Before(designationDay) && !d.After(claimDay) {
			WriteErrorWithCode(w, http.StatusConflict, "the admin's own role changed since this designation was signed", "designation_lapsed")
			return
		}
	}
	earlier, err := h.db.ListGrantsCiting(r.Context(), groupID, designation.SK)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, fail)
		return
	}
	if len(earlier) > 0 {
		WriteErrorWithCode(w, http.StatusConflict, "this designation was already used", "already_claimed")
		return
	}

	// Server-only checks.
	adminMember, err := h.db.GetMembership(r.Context(), groupID, adminID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, fail)
		return
	}
	if adminMember == nil || adminMember.Role != models.RoleAdmin {
		WriteErrorWithCode(w, http.StatusConflict, "the admin who designated you is no longer an admin of this group", "admin_changed")
		return
	}
	currentRef, hasStored := currentGrantRef(adminMember, group, adminID)
	if currentRef == "" || currentRef != designation.AdminGrantRef {
		WriteErrorWithCode(w, http.StatusConflict, "the admin's role changed since they designated you", "admin_changed")
		return
	}
	joined, err := time.Parse(time.RFC3339, caller.CreatedAt)
	if err != nil || designationDay.Before(joined.UTC().Truncate(24*time.Hour)) {
		WriteErrorWithCode(w, http.StatusConflict, "you were not a member of this group when this designation was signed", "designation_before_join")
		return
	}

	// Inactivity, for the designating admin and every other admin alike, from
	// the later of their last login and the designation's day to the claim's
	// signed day.
	admins, err := h.db.ListAdminMembers(r.Context(), groupID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, fail)
		return
	}
	// Every admin is checked, not just the first that fails: the retry date is
	// the latest day any of them becomes inactive, so it does not depend on
	// the order the admins are listed in.
	var retryFrom time.Time
	for _, a := range admins {
		aid := a.SK[len("MEMBER#"):]
		lastLogin := ""
		profile, err := h.db.GetUserByID(r.Context(), aid)
		switch {
		case errors.Is(err, db.ErrUserNotFound):
		case err != nil:
			WriteError(w, http.StatusInternalServerError, fail)
			return
		default:
			lastLogin = profile.LastLoginDay
		}
		if !inactiveFor(claimDay, designationDay, lastLogin, period) {
			if from := inactiveFrom(designationDay, lastLogin, period); from.After(retryFrom) {
				retryFrom = from
			}
		}
	}
	if !retryFrom.IsZero() {
		msg := "an admin has been active within the last " + strconv.Itoa(designation.PeriodDays) +
			" days; you can try again from " + retryFrom.Format(dayLayout) +
			" (UTC) if no admin logs in before then"
		WriteErrorWithCode(w, http.StatusConflict, msg, "not_inactive")
		return
	}

	err = h.db.ClaimDesignation(r.Context(), db.ClaimDesignationInput{
		GroupID:             groupID,
		AdminUserID:         adminID,
		AdminGrantRef:       designation.AdminGrantRef,
		AdminHasStoredGrant: hasStored,
		SuccessorUserID:     userID,
		SuccessorOldRole:    caller.Role,
		DesignationSortKey:  designation.SK,
		ClaimSortKey:        req.ClaimSortKey,
		Signature:           sig,
	})
	if err != nil {
		switch {
		case errors.Is(err, db.ErrClaimAdminChanged):
			WriteErrorWithCode(w, http.StatusConflict, "the admin's role changed since they designated you", "admin_changed")
		case errors.Is(err, db.ErrClaimRoleChanged):
			WriteErrorWithCode(w, http.StatusConflict, "your role changed; reload and retry", "subject_role_changed")
		case errors.Is(err, db.ErrClaimSuccessorDeleted):
			WriteErrorWithCode(w, http.StatusGone, "your account was deleted", "subject_deleted")
		case errors.Is(err, db.ErrClaimKeyTaken):
			WriteErrorWithCode(w, http.StatusConflict, "claimSortKey is taken; generate a new one and re-sign", "grant_key_taken")
		case errors.Is(err, db.ErrClaimConflict):
			WriteErrorWithCode(w, http.StatusConflict, "another change was in progress; retry", "conflict_retry")
		default:
			WriteError(w, http.StatusInternalServerError, fail)
		}
		return
	}
	WriteJSON(w, http.StatusOK, claimDesignationResponse{Role: models.RoleAdmin, GrantSortKey: req.ClaimSortKey})
}

// inactiveFor reports whether an admin counts as inactive on claimDay for a
// designation signed on designationDay with the given period: at least period
// has passed since the LATER of their last login day (empty or unparseable
// means never) and the designation's day. Measuring to claimDay, the day the
// successor signed, and not to the server's today, keeps this gate from
// passing a claim the verifier's floor would reject (docs/DESIGN.md,
// "Inactivity"). The later start keeps it from rejecting an honest one: a
// session can outlast the day of its login (up to config.MaxSessionTTL), so
// the admin's last login can fall days before the designation they signed.
func inactiveFor(claimDay, designationDay time.Time, lastLoginDay string, period time.Duration) bool {
	return !claimDay.Before(inactiveFrom(designationDay, lastLoginDay, period))
}

// inactiveFrom is the first day inactiveFor accepts for an admin, assuming
// they do not log in again before then.
func inactiveFrom(designationDay time.Time, lastLoginDay string, period time.Duration) time.Time {
	base := designationDay
	if d, err := time.Parse(dayLayout, lastLoginDay); err == nil && d.After(base) {
		base = d
	}
	return base.Add(period)
}
