package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

const (
	defaultMemberPageSize = 100
	maxMemberPageSize     = 200
)

// memberEntry is one row of the roster. It carries ids and roles only: a
// member's username and public keys come from the users projection
// (docs/DESIGN.md, "GET /api/users/:id"), not from here, so the roster read
// stays one Query.
type memberEntry struct {
	UserID     string `json:"userId"`
	Role       string `json:"role"`
	Generation int64  `json:"generation"`
}

// listMembersResponse is the wire shape of GET /api/groups/{id}/members.
// NextCursor is empty on the last page; pass it back as ?cursor=.
type listMembersResponse struct {
	Members    []memberEntry `json:"members"`
	NextCursor string        `json:"nextCursor,omitempty"`
}

// listMembers implements GET /api/groups/{groupId}/members -- issue #37.
// Members only, always: no configuration option, and a public group does not
// expose its roster. A non-member gets the same 404 whether or not the group
// exists, and the membership read is the only read either way.
func (h *Handler) listMembers(w http.ResponseWriter, r *http.Request) {
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

	limit := defaultMemberPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxMemberPageSize {
			WriteError(w, http.StatusBadRequest, "limit: must be between 1 and "+strconv.Itoa(maxMemberPageSize))
			return
		}
		limit = n
	}
	cursor := r.URL.Query().Get("cursor")
	if cursor != "" && !idgen.ValidUUID(cursor) {
		WriteError(w, http.StatusBadRequest, "cursor: malformed")
		return
	}

	m, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not list members")
		return
	}
	if m == nil {
		groupNotFound(w)
		return
	}

	members, next, err := h.db.ListMembers(r.Context(), groupID, cursor, limit)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not list members")
		return
	}
	entries := make([]memberEntry, 0, len(members))
	for _, mem := range members {
		entries = append(entries, memberEntry{
			UserID:     strings.TrimPrefix(mem.SK, "MEMBER#"),
			Role:       mem.Role,
			Generation: mem.Generation,
		})
	}
	WriteJSON(w, http.StatusOK, listMembersResponse{Members: entries, NextCursor: next})
}

const maxChangeRoleBodyBytes = 8 * 1024

// changeRoleRequest is the wire shape of PUT /api/groups/{id}/members/{uid}/role.
// The client signs crypto.RoleGrantPayload(groupID, subjectUserID, role,
// grantSortKey, grantorGrantRef) under crypto.ContextRoleGrant with its own
// current signing key, exactly as it does for the root grant at creation.
// GrantorGrantRef is the sort key of the caller's OWN current grant (the
// GrantSortKey on their membership, or the group's root grant for a creator
// on a group that predates that field); the server rejects a stale one so a
// signature can never anchor to a grant the caller no longer stands on.
type changeRoleRequest struct {
	Role            string `json:"role"`
	GrantSortKey    string `json:"grantSortKey"`
	GrantorGrantRef string `json:"grantorGrantRef"`
	Signature       string `json:"signature"`
}

type changeRoleResponse struct {
	Role         string `json:"role"`
	GrantSortKey string `json:"grantSortKey"`
}

// changeMemberRole implements PUT /api/groups/{groupId}/members/{userId}/role
// -- issue #37. Admin only; emits a signed role grant and applies it in one
// transaction (db.ChangeMemberRole). Promotion and demotion are both just
// grants: history is append-only, and nothing here deletes anything.
// Revocation semantics beyond that (#56), removal and key rotation (#58) and
// a server-side role-enforcement audit (#57) are not part of this issue.
//
// An admin cannot change their own role. That single rule is what guarantees
// a group never ends up with no admin: every change is made by an admin who
// remains one.
func (h *Handler) changeMemberRole(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	groupID := r.PathValue("groupId")
	subjectID := r.PathValue("userId")
	if !idgen.ValidUUID(groupID) {
		groupNotFound(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxChangeRoleBodyBytes)
	var req changeRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}

	// Same rule as getGroup: every read happens before any 404 branch.
	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not change role")
		return
	}
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not change role")
		return
	}
	if caller == nil || group == nil {
		groupNotFound(w)
		return
	}
	if caller.Role != models.RoleAdmin {
		WriteError(w, http.StatusForbidden, "only a group admin can change roles")
		return
	}
	if group.GroupType == "dm" {
		WriteError(w, http.StatusBadRequest, "a direct message has no roles")
		return
	}

	if !idgen.ValidUUID(subjectID) {
		WriteError(w, http.StatusNotFound, "member not found")
		return
	}
	if subjectID == userID {
		WriteError(w, http.StatusBadRequest, "you cannot change your own role")
		return
	}
	subject, err := h.db.GetMembership(r.Context(), groupID, subjectID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not change role")
		return
	}
	if subject == nil {
		WriteError(w, http.StatusNotFound, "member not found")
		return
	}

	switch req.Role {
	case models.RoleAdmin, models.RoleAmbassador, models.RoleMember:
	default:
		WriteError(w, http.StatusBadRequest, "role: must be \"admin\", \"ambassador\" or \"member\"")
		return
	}
	if req.Role == subject.Role {
		WriteError(w, http.StatusBadRequest, "role: member already has this role")
		return
	}

	// The caller's own current grant: recorded on their membership, or for a
	// creator on a group made before that field existed, the root grant.
	currentRef, hasStored := caller.GrantSortKey, caller.GrantSortKey != ""
	if !hasStored && group.CreatorUserID == userID {
		currentRef = group.RootGrantSortKey
	}
	if currentRef == "" {
		WriteErrorWithCode(w, http.StatusConflict, "your own admin grant is not on record", "grantor_grant_missing")
		return
	}
	if req.GrantorGrantRef != currentRef {
		WriteErrorWithCode(w, http.StatusConflict, "grantorGrantRef is not your current grant; reload and re-sign", "grantor_ref_stale")
		return
	}

	day, ok := idgen.ValidGrantSortKey(req.GrantSortKey, subjectID)
	if !ok {
		WriteError(w, http.StatusBadRequest, "grantSortKey: must be a well-formed GRANT# sort key for the member's uuid")
		return
	}
	if skew := time.Since(day.UTC()); skew < -grantDaySkewTolerance || skew > 24*time.Hour+grantDaySkewTolerance {
		WriteError(w, http.StatusBadRequest, "grantSortKey: day is not within tolerance of the current UTC day")
		return
	}
	sig, err := decodeBase64Field(req.Signature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "signature: "+err.Error())
		return
	}

	// The signing key is the caller's own, read from their PROFILE -- never
	// from the request (see createGroup).
	grantor, err := h.db.GetUserByID(r.Context(), userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not change role")
		return
	}
	payload := crypto.RoleGrantPayload(groupID, subjectID, req.Role, req.GrantSortKey, req.GrantorGrantRef)
	if !crypto.Verify(grantor.SigningPublicKey, crypto.ContextRoleGrant, payload, sig) {
		WriteError(w, http.StatusBadRequest, "signature: does not verify against the caller's current signing key")
		return
	}

	err = h.db.ChangeMemberRole(r.Context(), db.ChangeMemberRoleInput{
		GroupID:                 groupID,
		SubjectUserID:           subjectID,
		OldRole:                 subject.Role,
		NewRole:                 req.Role,
		GrantorUserID:           userID,
		GrantorSigningPublicKey: grantor.SigningPublicKey,
		GrantorGrantRef:         req.GrantorGrantRef,
		GrantorHasStoredGrant:   hasStored,
		GrantSortKey:            req.GrantSortKey,
		Signature:               sig,
	})
	if err != nil {
		switch {
		case errors.Is(err, db.ErrGrantorChanged):
			WriteErrorWithCode(w, http.StatusConflict, "your own role changed; reload and re-sign", "grantor_changed")
		case errors.Is(err, db.ErrSubjectRoleChanged):
			WriteErrorWithCode(w, http.StatusConflict, "the member's role changed; reload and retry", "subject_role_changed")
		case errors.Is(err, db.ErrRoleChangeConflict):
			WriteErrorWithCode(w, http.StatusConflict, "another change was in progress; retry", "conflict_retry")
		case errors.Is(err, db.ErrGrantKeyTaken):
			WriteErrorWithCode(w, http.StatusConflict, "grantSortKey is taken; generate a new one and re-sign", "grant_key_taken")
		default:
			WriteError(w, http.StatusInternalServerError, "could not change role")
		}
		return
	}
	WriteJSON(w, http.StatusOK, changeRoleResponse{Role: req.Role, GrantSortKey: req.GrantSortKey})
}
