package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
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
	currentRef, hasStored := currentGrantRef(caller, group, userID)
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

type leaveGroupResponse struct {
	// GroupDeleted is true when the caller was the only member, so leaving
	// deleted the group.
	GroupDeleted bool `json:"groupDeleted"`
}

// leaveGroupRequest carries the signed self-demotion an admin or ambassador
// must attach to leaving (issue #55): a role grant to "member" with the
// leaver as both grantor and subject, signed exactly like changeRoleRequest
// with the subject set to the caller. A plain member sends an empty body.
type leaveGroupRequest struct {
	GrantSortKey    string `json:"grantSortKey"`
	GrantorGrantRef string `json:"grantorGrantRef"`
	Signature       string `json:"signature"`
}

func (r leaveGroupRequest) empty() bool {
	return r.GrantSortKey == "" && r.GrantorGrantRef == "" && r.Signature == ""
}

// leaveGroup implements POST /api/groups/{groupId}/leave -- issues #66, #55.
// Any member may leave, with one exception: the last Admin of a group that
// still has other members gets 409 last_admin and must promote a successor
// first (the departing admin knows who should take over better than any
// heuristic). The only member leaving deletes the group. A non-member gets
// the same 404 whether or not the group exists.
//
// An Admin or Ambassador leaving a group that survives must also send a
// signed demotion to member (400 demotion_required otherwise), which is
// appended as a grant in the same transaction as the membership delete.
// Leaving used to append nothing, so a departed admin's last grant still said
// admin and a rejoin looked forged to the chain verifier. The leaver signs it
// themselves: leaving needs no one else's authority, and a demotion cannot
// raise anyone's standing.
//
// The involuntary cases (removal, account deletion, inactivity) and their
// automatic successor choice are not here: they need a signed grant from
// someone other than the departing admin, so they belong with removal (#58)
// and account deletion (#77).
func (h *Handler) leaveGroup(w http.ResponseWriter, r *http.Request) {
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

	r.Body = http.MaxBytesReader(w, r.Body, maxChangeRoleBodyBytes)
	var req leaveGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}

	caller, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not leave group")
		return
	}
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not leave group")
		return
	}
	if caller == nil || group == nil {
		groupNotFound(w)
		return
	}

	var demotion *db.LeaveDemotion
	switch {
	case caller.Role == models.RoleMember:
		if !req.empty() {
			WriteError(w, http.StatusBadRequest, "a plain member leaves without a grant")
			return
		}
	case req.empty():
		// db decides: the only member of a group leaves without one.
	default:
		d, status, code, msg := h.buildLeaveDemotion(r.Context(), groupID, userID, caller, group, req)
		if msg != "" {
			if code != "" {
				WriteErrorWithCode(w, status, msg, code)
			} else {
				WriteError(w, status, msg)
			}
			return
		}
		demotion = d
	}

	deleted, err := h.db.LeaveGroup(r.Context(), groupID, userID, demotion)
	switch {
	case errors.Is(err, db.ErrNotMember):
		groupNotFound(w)
	case errors.Is(err, db.ErrLastAdmin):
		WriteErrorWithCode(w, http.StatusConflict, "you are the last admin; promote a successor before leaving", "last_admin")
	case errors.Is(err, db.ErrDemotionRequired):
		WriteErrorWithCode(w, http.StatusBadRequest, "leaving as an admin or ambassador needs a signed demotion", "demotion_required")
	case errors.Is(err, db.ErrLeaveGrantKeyTaken):
		WriteErrorWithCode(w, http.StatusConflict, "grantSortKey is taken; generate a new one and re-sign", "grant_key_taken")
	case errors.Is(err, db.ErrLeaveConflict):
		WriteErrorWithCode(w, http.StatusConflict, "the group changed; reload and retry", "conflict_retry")
	case errors.Is(err, db.ErrGroupSweepIncomplete), errors.Is(err, db.ErrInviteCleanupIncomplete):
		// The leave itself committed; only unreachable or expiring rows remain.
		log.Printf("leave group %s: %v", groupID, err)
		WriteJSON(w, http.StatusOK, leaveGroupResponse{GroupDeleted: deleted})
	case err != nil:
		WriteError(w, http.StatusInternalServerError, "could not leave group")
	default:
		WriteJSON(w, http.StatusOK, leaveGroupResponse{GroupDeleted: deleted})
	}
}

// buildLeaveDemotion validates a leave request's signed self-demotion the way
// changeMemberRole validates a grant: the grantor ref must be the caller's own
// current grant, the sort key must be a well-formed address for the caller and
// dated near now, and the signature must verify under the caller's CURRENT
// signing key (read from their PROFILE, never the request). A non-empty msg
// is the error to send.
func (h *Handler) buildLeaveDemotion(
	ctx context.Context, groupID, userID string, caller *models.Membership, group *models.Group, req leaveGroupRequest,
) (d *db.LeaveDemotion, status int, code, msg string) {
	currentRef, hasStored := currentGrantRef(caller, group, userID)
	if currentRef == "" {
		return nil, http.StatusConflict, "grantor_grant_missing", "your own grant is not on record"
	}
	if req.GrantorGrantRef != currentRef {
		return nil, http.StatusConflict, "grantor_ref_stale", "grantorGrantRef is not your current grant; reload and re-sign"
	}
	day, ok := idgen.ValidGrantSortKey(req.GrantSortKey, userID)
	if !ok {
		return nil, http.StatusBadRequest, "", "grantSortKey: must be a well-formed GRANT# sort key for your uuid"
	}
	if skew := time.Since(day.UTC()); skew < -grantDaySkewTolerance || skew > 24*time.Hour+grantDaySkewTolerance {
		return nil, http.StatusBadRequest, "", "grantSortKey: day is not within tolerance of the current UTC day"
	}
	sig, err := decodeBase64Field(req.Signature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		return nil, http.StatusBadRequest, "", "signature: " + err.Error()
	}
	self, err := h.db.GetUserByID(ctx, userID)
	if err != nil {
		return nil, http.StatusInternalServerError, "", "could not leave group"
	}
	payload := crypto.RoleGrantPayload(groupID, userID, models.RoleMember, req.GrantSortKey, req.GrantorGrantRef)
	if !crypto.Verify(self.SigningPublicKey, crypto.ContextRoleGrant, payload, sig) {
		return nil, http.StatusBadRequest, "", "signature: does not verify against the caller's current signing key"
	}
	return &db.LeaveDemotion{
		GrantSortKey:     req.GrantSortKey,
		GrantorGrantRef:  req.GrantorGrantRef,
		HasStoredGrant:   hasStored,
		SigningPublicKey: self.SigningPublicKey,
		Signature:        sig,
	}, 0, "", ""
}

const (
	defaultGrantPageSize = 100
	maxGrantPageSize     = 200
)

// grantAnchor is the group's stored chain anchor: the creator's uuid and the
// Ed25519 key that was current at creation, with the creator's signature over
// them (crypto.TrustAnchorPayload). The signature is over the contextualized
// message: verify it under crypto.ContextTrustAnchor, not as a plain Ed25519
// check over the payload, which rejects every row. A verifier checks it before
// trusting either field, and that the root grant is self-signed by this key.
type grantAnchor struct {
	CreatorUserID           string `json:"creatorUserId"`
	CreatorSigningPublicKey string `json:"creatorSigningPublicKey"`
	TrustAnchorSignature    string `json:"trustAnchorSignature"`
	RootGrantSortKey        string `json:"rootGrantSortKey"`
}

// grantEntry is one signed role grant, with everything a verifier needs to
// rebuild the signed bytes (crypto.RoleGrantPayload) and check the signature
// under crypto.ContextRoleGrant (the signature is over the contextualized
// message, not the bare payload).
//
// "Needs" is not "can trust". GrantorSigningPublicKey is the server's own row
// and nothing in RoleGrantPayload binds it, so a verifier that checks Signature
// against it alone accepts anything the server writes. It is safe only for the
// root grant, whose key the anchor pins. For every other grant, resolve the
// grantor's key for the grant's day from their key history (superseded keys)
// and treat this field as a hint at most.
type grantEntry struct {
	SortKey                 string `json:"sortKey"`
	SubjectUserID           string `json:"subjectUserId"`
	GrantedRole             string `json:"grantedRole"`
	GrantorUserID           string `json:"grantorUserId"`
	GrantorSigningPublicKey string `json:"grantorSigningPublicKey"`
	GrantorGrantRef         string `json:"grantorGrantRef,omitempty"`
	Signature               string `json:"signature"`
}

// listGrantsResponse is the wire shape of GET /api/groups/{id}/grants. The
// anchor is on every page so a client can verify any page it holds.
type listGrantsResponse struct {
	Anchor     grantAnchor  `json:"anchor"`
	Grants     []grantEntry `json:"grants"`
	NextCursor string       `json:"nextCursor,omitempty"`
}

// listGrants implements GET /api/groups/{groupId}/grants -- issue #55. Members
// only, with the same 404 as the roster for anyone else. This serves the
// history a client needs to verify the chain of trust itself: the server is
// the party grants protect against, so it hands over the signed rows and the
// stored anchor and does no verification of its own here.
func (h *Handler) listGrants(w http.ResponseWriter, r *http.Request) {
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
		const subjectStart, subjectEnd = len("GRANT#"), len("GRANT#") + 36
		if len(cursor) < subjectEnd {
			WriteError(w, http.StatusBadRequest, "cursor: malformed")
			return
		}
		// Passing the cursor's own uuid as the subject makes the subject check
		// vacuous on purpose: any subject in this group is a valid cursor, so
		// only the shape check does work. The PK is fixed to groupID below.
		if _, ok := idgen.ValidGrantSortKey(cursor, cursor[subjectStart:subjectEnd]); !ok {
			WriteError(w, http.StatusBadRequest, "cursor: malformed")
			return
		}
	}

	m, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not list grants")
		return
	}
	if m == nil {
		groupNotFound(w)
		return
	}
	group, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not list grants")
		return
	}
	if group == nil {
		// Deleted between the membership read and now (the last member left).
		groupNotFound(w)
		return
	}
	grants, next, err := h.db.ListGrants(r.Context(), groupID, cursor, limit)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not list grants")
		return
	}
	enc := base64.StdEncoding.EncodeToString
	entries := make([]grantEntry, 0, len(grants))
	for _, g := range grants {
		entries = append(entries, grantEntry{
			SortKey:                 g.SK,
			SubjectUserID:           g.SubjectUserID,
			GrantedRole:             g.GrantedRole,
			GrantorUserID:           g.GrantorUserID,
			GrantorSigningPublicKey: enc(g.GrantorSigningPublicKey),
			GrantorGrantRef:         g.GrantorGrantRef,
			Signature:               enc(g.Signature),
		})
	}
	WriteJSON(w, http.StatusOK, listGrantsResponse{
		Anchor: grantAnchor{
			CreatorUserID:           group.CreatorUserID,
			CreatorSigningPublicKey: enc(group.CreatorSigningPublicKey),
			TrustAnchorSignature:    enc(group.TrustAnchorSignature),
			RootGrantSortKey:        group.RootGrantSortKey,
		},
		Grants:     entries,
		NextCursor: next,
	})
}
