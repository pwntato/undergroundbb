package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// encodeBase64 is base64.StdEncoding.EncodeToString under a shorter name --
// this file has enough outbound-encoding call sites (getInvite and
// pendingInviteCompletions both hand back several public keys/signatures at
// once) that spelling it out each time would be noisier than everywhere
// else in this package that only does it once or twice inline.
func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// maxInviteBodyBytes and maxCompleteInviteBodyBytes bound their respective
// request bodies -- same reasoning as maxCreateGroupBodyBytes/
// maxRegisterBodyBytes, sized generously above the largest legitimate
// payload.
const (
	maxInviteBodyBytes         = 8 * 1024
	maxCompleteInviteBodyBytes = 8 * 1024
)

// minInviteTTL and maxInviteTTL bound an invite's requested lifetime -- a
// server-side policy choice, like maxGroupNameLen, rather than a protocol
// requirement. A floor rules out a link that expires before it could
// plausibly reach the invitee (an email, a chat message); a ceiling matches
// completionDeadlineDuration's own order of magnitude, since a much longer
// unaccepted-link lifetime would extend the invite disclosure window
// THREAT_MODEL treats as the more sensitive half for no real benefit.
//
// maxInviteTTL is 31 days, not a flat 30 -- PR #146 round-2 review's own
// catch: expiresAt must now be exactly the end of a UTC day
// ("...T23:59:59Z", this file's own createInvite doc comment), and
// CreateInviteScreen.tsx's "30 days" option means "the end of the UTC day
// 30 DAYS FROM NOW," which is itself up to just under 24h MORE than a flat
// 30*24h away depending on what time of day the invite is created. A
// literal 30*24h cap rejected that option on every submission except one
// created at exactly 23:59:59Z. The extra day of slack absorbs exactly
// that rounding, without meaningfully loosening the policy the ceiling
// exists to enforce.
const (
	minInviteTTL = 1 * time.Hour
	maxInviteTTL = 31 * 24 * time.Hour
)

// createInviteRequest is the wire shape of POST /api/groups/{groupId}/invites
// -- issue #38. See docs/DESIGN.md, "Invites -- the signed handshake," step
// 1. The client signs crypto.InviteCreationPayload(inviteId, groupId,
// inviterSigningPublicKey, expiresAt) under crypto.ContextInvite --
// InviterSigningPublicKey is NOT a request field, the same reasoning
// createGroupRequest's own doc comment gives for CreatorSigningPublicKey:
// it is re-derived from the caller's own session-authenticated PROFILE, and
// verifying against a key the caller supplied would only prove they control
// whatever key they feel like sending.
type createInviteRequest struct {
	// InviteID is client-generated, exactly like createGroupRequest.GroupID
	// and for the identical reason: the signed payload binds the invite id,
	// so the client must know the real one before it signs, before this
	// request is ever sent.
	InviteID string `json:"inviteId"`
	// ExpiresAt is the RFC 3339 deadline the client signed -- validated
	// against minInviteTTL/maxInviteTTL below, and used to derive the
	// stored TTL (db.CreateInvite rounds it to the end of its UTC day).
	ExpiresAt string `json:"expiresAt"`
	// CreationSignature is crypto.Sign(inviterPriv, ContextInvite,
	// crypto.InviteCreationPayload(inviteId, groupId, inviterSigningPublicKey,
	// expiresAt)).
	CreationSignature string `json:"creationSignature"`
}

type createInviteResponse struct {
	InviteID string `json:"inviteId"`
}

// createInvite implements POST /api/groups/{groupId}/invites -- issue #38.
// Authenticated by requireSession; additionally requires the caller hold
// Admin or Ambassador in the target group (docs/DESIGN.md: "Admin or
// Ambassador only"), checked via a plain GetItem on their own MEMBER# item
// -- the same hot-path role check every other role-gated write in this
// schema uses.
func (h *Handler) createInvite(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	groupID := r.PathValue("groupId")
	if !idgen.ValidUUID(groupID) {
		WriteError(w, http.StatusBadRequest, "groupId: must be a well-formed, lowercase UUIDv4")
		return
	}

	membership, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not create invite")
		return
	}
	if membership == nil || (membership.Role != models.RoleAdmin && membership.Role != models.RoleAmbassador) {
		// Same shape for "not a member at all" and "a member, but only a
		// plain Member" -- neither may invite, and distinguishing the two
		// to the caller would confirm group membership to someone who
		// might not have any, an unnecessary enumeration channel this
		// endpoint has no reason to open.
		WriteError(w, http.StatusForbidden, "must be an admin or ambassador of this group to create an invite")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxInviteBodyBytes)
	var req createInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}

	if !idgen.ValidUUID(req.InviteID) {
		WriteError(w, http.StatusBadRequest, "inviteId: must be a well-formed, lowercase UUIDv4")
		return
	}

	expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "expiresAt: must be a valid RFC 3339 timestamp")
		return
	}
	// Enforced server-side, not merely suggested to the client: expiresAt
	// must be exactly the end of a UTC day ("...T23:59:59Z", no
	// milliseconds, no non-UTC offset). Without this, expiresAt (stored
	// in plaintext next to InviterUserID and, after acceptance, the
	// invitee) dates invite creation to the millisecond -- Date.now() + N
	// hours then toISOString() always carries milliseconds in a real
	// browser, and rounding only the stored TTL (RoundUpToEndOfUTCDay)
	// does not help, since the signed string sits right next to it with
	// its own, sharper precision. Forcing exactly this format also
	// permanently forecloses the verbatim-string/millisecond mismatch bug
	// this PR's own db.CreateInviteInput.ExpiresAt doc comment describes:
	// a value with no milliseconds in the first place cannot suffer from
	// a reformatting that silently drops them.
	if !strings.HasSuffix(req.ExpiresAt, "T23:59:59Z") {
		WriteError(w, http.StatusBadRequest, "expiresAt: must be exactly the end of a UTC day (\"...T23:59:59Z\")")
		return
	}
	if ttl := time.Until(expiresAt); ttl < minInviteTTL || ttl > maxInviteTTL {
		WriteError(w, http.StatusBadRequest, "expiresAt: must be between 1 hour and 31 days from now")
		return
	}

	creationSig, err := decodeBase64Field(req.CreationSignature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "creationSignature: "+err.Error())
		return
	}

	// The inviter's signing key is read from their OWN session-authenticated
	// PROFILE, never trusted from the request body -- see createGroup's own
	// doc comment for the identical reasoning applied to a group's creator.
	inviter, err := h.db.GetUserByID(r.Context(), userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not create invite")
		return
	}

	payload := crypto.InviteCreationPayload(req.InviteID, groupID, inviter.SigningPublicKey, req.ExpiresAt)
	if !crypto.Verify(inviter.SigningPublicKey, crypto.ContextInvite, payload, creationSig) {
		WriteError(w, http.StatusBadRequest, "creationSignature: does not verify against the caller's current signing key")
		return
	}

	in := db.CreateInviteInput{
		InviteID:                req.InviteID,
		GroupID:                 groupID,
		InviterUserID:           userID,
		InviterSigningPublicKey: inviter.SigningPublicKey,
		CreationSignature:       creationSig,
		// The exact wire string, not a reformatted one -- see
		// db.CreateInviteInput.ExpiresAt's own doc comment: this is what
		// CreationSignature actually covers (crypto.InviteCreationPayload
		// signs req.ExpiresAt's bytes directly, two lines above), and
		// re-deriving it from expiresAt.Format() would silently produce a
		// different string whenever the client's original timestamp
		// carried sub-second precision (every real JS toISOString() call).
		ExpiresAt:       req.ExpiresAt,
		ExpiresAtParsed: expiresAt,
	}
	if err := h.db.CreateInvite(r.Context(), in); err != nil {
		if errors.Is(err, db.ErrInviteIDTaken) {
			WriteErrorWithCode(w, http.StatusConflict, "inviteId is taken", "invite_id_taken")
			return
		}
		WriteError(w, http.StatusInternalServerError, "could not create invite")
		return
	}

	WriteJSON(w, http.StatusCreated, createInviteResponse{InviteID: req.InviteID})
}

// getInviteResponse is the wire shape of GET /api/invites/{id} -- issue #39,
// step 2's prerequisite read. Unauthenticated by design: an invite is a
// link handed to someone who may not have an account yet
// (models.Invite's own doc comment). Carries everything the invitee's
// client needs to independently verify the inviter's signature (never
// trusting that the server already checked it -- the same reasoning every
// other signature in this schema gets) before ever showing the invitee a
// "you've been invited" screen or letting them accept.
//
// InviterWrappingPublicKey is NOT part of the signed step-1 payload (only
// InviterSigningPublicKey is -- crypto.InviteCreationPayload) and is not
// stored on the INVITE# row at all; it is read fresh from the inviter's own
// current PROFILE for exactly one purpose: docs/DESIGN.md's fingerprint
// verification ("invite links additionally carry the inviter's fingerprint
// in the URL fragment... so the invitee's client can check it against a
// value the server never saw"). A fingerprint needs BOTH of a user's
// current public keys (fingerprint.ts/crypto.Fingerprint), so the invitee's
// client cannot recompute -- and therefore cannot check -- the fingerprint
// without this field, even though the cryptographic handshake itself never
// touches it. This is a live read of current state, not the value that was
// true at invite-creation time -- acceptable because verification is a
// human, out-of-band affordance ("available rather than mandatory"), not a
// signed claim: if the inviter has since rotated keys, the fragment
// (captured at creation time) and this live value will simply, correctly,
// no longer match, which is exactly what should happen.
type getInviteResponse struct {
	GroupID                  string `json:"groupId"`
	InviterUserID            string `json:"inviterUserId"`
	InviterSigningPublicKey  string `json:"inviterSigningPublicKey"`
	InviterWrappingPublicKey string `json:"inviterWrappingPublicKey"`
	ExpiresAt                string `json:"expiresAt"`
	CreationSignature        string `json:"creationSignature"`
	// Accepted reports whether this invite has already been claimed --
	// present so a client following a stale or already-used link gets an
	// honest "already accepted" state rather than being invited to sign
	// step 2 against a row that will just reject it with
	// ErrInviteAlreadyAccepted.
	Accepted bool `json:"accepted"`
}

// getInvite implements GET /api/invites/{id} -- issue #39. Does not itself
// check ExpiresAt -- see acceptInvite's own doc comment for why this read
// does not enforce the security-relevant expiry check itself (an
// unauthenticated GET has no side effect to protect); the invitee's client
// should still surface an obviously-expired ExpiresAt as a display
// convenience, but the read-time check that matters is on the accept path.
func (h *Handler) getInvite(w http.ResponseWriter, r *http.Request) {
	inviteID := r.PathValue("id")
	if !idgen.ValidUUID(inviteID) {
		WriteError(w, http.StatusBadRequest, "id: must be a well-formed, lowercase UUIDv4")
		return
	}

	invite, err := h.db.GetInvite(r.Context(), inviteID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not fetch invite")
		return
	}
	if invite == nil {
		WriteError(w, http.StatusNotFound, "invite not found or expired")
		return
	}

	// See getInviteResponse's own doc comment for why this second read
	// (the inviter's current PROFILE) exists solely to serve
	// InviterWrappingPublicKey. GetUserByID returns ErrUserNotFound (never
	// a nil user with a nil error) if the PROFILE is somehow missing -- the
	// inviter's own account cannot have been deleted (no delete-account
	// flow exists in this schema), so that would mean a data inconsistency
	// this handler cannot repair; either way it falls into the generic
	// 500 below rather than serving a response with a silently empty key.
	inviter, err := h.db.GetUserByID(r.Context(), invite.InviterUserID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not fetch invite")
		return
	}

	WriteJSON(w, http.StatusOK, getInviteResponse{
		GroupID:                  invite.GroupID,
		InviterUserID:            invite.InviterUserID,
		InviterSigningPublicKey:  encodeBase64(invite.InviterSigningPublicKey),
		InviterWrappingPublicKey: encodeBase64(inviter.WrappingPublicKey),
		ExpiresAt:                invite.ExpiresAt,
		CreationSignature:        encodeBase64(invite.CreationSignature),
		Accepted:                 invite.InvitedUserID != "",
	})
}

// revokeInvite implements DELETE /api/invites/{id} -- docs/DESIGN.md: "An
// invite can also be revoked, by deleting the INVITE# row: before
// acceptance that is the only remedy for a link sent to the wrong address
// or known to have leaked." Authenticated as the INVITER: this handler
// reads the invite first and checks invite.InviterUserID == the caller's
// own session userID BEFORE ever calling db.RevokeInvite, rather than
// letting a caller-supplied inviterUserID address the SENT# delete
// directly -- the same "second party must never name a row in the
// inviter's own partition directly" principle acceptInvite's own doc
// comment establishes.
//
// Pre-acceptance only -- see db.RevokeInvite's own doc comment for why:
// once step 2 has run, the invitee has already been told "you're in," and
// deleting the rows out from under them would silently strand them with
// no membership and no remaining record anything was ever accepted.
func (h *Handler) revokeInvite(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	inviteID := r.PathValue("id")
	if !idgen.ValidUUID(inviteID) {
		WriteError(w, http.StatusBadRequest, "id: must be a well-formed, lowercase UUIDv4")
		return
	}

	invite, err := h.db.GetInvite(r.Context(), inviteID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not revoke invite")
		return
	}
	if invite == nil {
		WriteError(w, http.StatusNotFound, "invite not found or expired")
		return
	}
	if invite.InviterUserID != userID {
		// Same shape as a not-found response -- confirming "this invite
		// exists, but you didn't create it" to a caller who is not its
		// inviter is an enumeration channel this endpoint has no reason to
		// open, the same reasoning createInvite's own 403 doc comment
		// gives for not distinguishing "not a member" from "a member, but
		// not admin/ambassador."
		WriteError(w, http.StatusNotFound, "invite not found or expired")
		return
	}
	if invite.InvitedUserID != "" {
		WriteErrorWithCode(w, http.StatusConflict, "this invite has already been accepted and can no longer be revoked", "invite_already_accepted")
		return
	}

	if err := h.db.RevokeInvite(r.Context(), inviteID, userID); err != nil {
		if errors.Is(err, db.ErrInviteAlreadyAcceptedForRevoke) {
			// A race between our GetInvite above and RevokeInvite's own
			// conditional delete (accepted, or already revoked, in
			// between) -- same response as the earlier pre-check.
			WriteErrorWithCode(w, http.StatusConflict, "this invite has already been accepted and can no longer be revoked", "invite_already_accepted")
			return
		}
		WriteError(w, http.StatusInternalServerError, "could not revoke invite")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// acceptInviteRequest is the wire shape of POST /api/invites/{id}/accept --
// issue #39, step 2. Authenticated: the invitee must have an account
// (freshly created or existing) and a session before accepting, since
// InvitedUserID names a real uuid the membership CompleteInvite later
// writes under -- unlike GET /api/invites/{id}, which is deliberately
// reachable before signup so the invite's content can be shown first.
type acceptInviteRequest struct {
	// AcceptanceSignature is crypto.Sign(inviteePriv, ContextInvite,
	// crypto.InviteAcceptancePayload(inviteId, ed25519Pub, x25519Pub)) --
	// ed25519Pub/x25519Pub are NOT separate request fields; they are read
	// from the caller's own session-authenticated PROFILE, the same
	// "re-derive from the session, never trust the request" split every
	// other signing key in this handler package gets.
	AcceptanceSignature string `json:"acceptanceSignature"`
	// InviteMAC is crypto.ComputeInviteMAC(k, the same payload
	// AcceptanceSignature covers), k being the per-invite secret carried
	// in the invite link's own URL fragment. This server cannot verify it
	// -- it never sees k, and never will -- and does not try to. It is
	// stored opaquely and served back at
	// GET /api/invites/pending-completions purely so the INVITER's own
	// client, the one party who can re-derive k, can verify it there
	// before ever trusting the keys above. See
	// crypto.DeriveInviteMACKey's own doc comment for what this closes:
	// without it, this handler's own signature check alone lets a
	// malicious server mint its own keypair, sign its own payload, and
	// pass -- proving only that a keypair is self-consistent, never that
	// it belongs to the real invitee.
	InviteMAC string `json:"inviteMAC"`
}

// acceptInvite implements POST /api/invites/{id}/accept -- issue #39, step
// 2. Order of checks matches the issue's own requirement exactly:
//  1. Look up the invite. Missing -> ErrInviteNotFound (covers both "never
//     existed" and "already TTL-swept").
//  2. Verify the INVITER's signature over the step-1 payload (defense in
//     depth: the invitee's client already had to do this before showing an
//     accept button per getInvite's own doc comment, but the server does
//     not trust that happened).
//  3. THEN check ExpiresAt against now -- "verify the inviter's signature
//     first, then check expires_at... An unverified expires_at is a value
//     the server could have altered, so checking it before verifying the
//     signature is checking the attacker's number."
//  4. Verify the INVITEE's own signature over the step-2 payload.
//  5. AcceptInvite's own conditional write enforces single-use.
func (h *Handler) acceptInvite(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	inviteID := r.PathValue("id")
	if !idgen.ValidUUID(inviteID) {
		WriteError(w, http.StatusBadRequest, "id: must be a well-formed, lowercase UUIDv4")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxInviteBodyBytes)
	var req acceptInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	acceptanceSig, err := decodeBase64Field(req.AcceptanceSignature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "acceptanceSignature: "+err.Error())
		return
	}
	// This handler cannot verify inviteMAC (it never has k) -- only decodes
	// and length-checks it, then stores it opaquely for the inviter's own
	// client to check at step 3. See acceptInviteRequest.InviteMAC's own
	// doc comment.
	inviteMAC, err := decodeBase64Field(req.InviteMAC, inviteMACSize, inviteMACSize)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "inviteMAC: "+err.Error())
		return
	}

	invite, err := h.db.GetInvite(r.Context(), inviteID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not accept invite")
		return
	}
	if invite == nil {
		WriteError(w, http.StatusNotFound, "invite not found or expired")
		return
	}

	// Step 1's signature, checked BEFORE the expiry -- see this handler's
	// own doc comment for why the order is load-bearing, not stylistic.
	creationPayload := crypto.InviteCreationPayload(inviteID, invite.GroupID, invite.InviterSigningPublicKey, invite.ExpiresAt)
	if !crypto.Verify(invite.InviterSigningPublicKey, crypto.ContextInvite, creationPayload, invite.CreationSignature) {
		WriteError(w, http.StatusBadRequest, "invite's own creation signature does not verify -- this invite cannot be trusted")
		return
	}

	expiresAt, err := time.Parse(time.RFC3339, invite.ExpiresAt)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not accept invite")
		return
	}
	if time.Now().After(expiresAt) {
		WriteError(w, http.StatusGone, "invite has expired")
		return
	}

	invitee, err := h.db.GetUserByID(r.Context(), userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not accept invite")
		return
	}

	acceptancePayload := crypto.InviteAcceptancePayload(inviteID, invitee.SigningPublicKey, invitee.WrappingPublicKey)
	if !crypto.Verify(invitee.SigningPublicKey, crypto.ContextInvite, acceptancePayload, acceptanceSig) {
		WriteError(w, http.StatusBadRequest, "acceptanceSignature: does not verify against the caller's current keys")
		return
	}

	// Reject a caller who already holds a membership in this invite's own
	// group -- including the inviter accepting their own link. Without
	// this, AcceptInvite's single-use condition (attribute_not_exists on
	// InvitedUserID) still lets it through: an existing member, or the
	// inviter themselves, "uses up" an invite meant for someone else,
	// silently leaving the intended invitee's link dead with no
	// membership to show for it. Checked here rather than left to
	// CompleteInvite's own ErrAlreadyMember guard -- that guard fires only
	// at step 3, after this invite has already been consumed at step 2.
	existingMembership, err := h.db.GetMembership(r.Context(), invite.GroupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not accept invite")
		return
	}
	if existingMembership != nil {
		WriteErrorWithCode(w, http.StatusConflict, "you are already a member of this group", "already_member")
		return
	}

	err = h.db.AcceptInvite(r.Context(), db.AcceptInviteInput{
		InviteID:                inviteID,
		InvitedUserID:           userID,
		InvitedEd25519PublicKey: invitee.SigningPublicKey,
		InvitedX25519PublicKey:  invitee.WrappingPublicKey,
		AcceptanceSignature:     acceptanceSig,
		InviteMAC:               inviteMAC,
	})
	if err != nil {
		if errors.Is(err, db.ErrInviteAlreadyAccepted) {
			WriteErrorWithCode(w, http.StatusConflict, "this invite has already been accepted", "invite_already_accepted")
			return
		}
		if errors.Is(err, db.ErrInviteNotFound) {
			// A race between our GetInvite above and the conditional write
			// (e.g. TTL-swept in between) -- same response as the earlier
			// not-found check.
			WriteError(w, http.StatusNotFound, "invite not found or expired")
			return
		}
		WriteError(w, http.StatusInternalServerError, "could not accept invite")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]string{"groupId": invite.GroupID})
}

// pendingInviteCompletionEntry is one invite in
// GET /api/invites/pending-completions's response -- issue #40, step 3.
// Carries everything the inviter's own client needs to wrap the group key
// to the invitee's signed keys and re-verify AcceptanceSignature itself
// (never trusting that the server already checked it -- the same
// defense-in-depth reasoning getInviteResponse's own doc comment gives).
type pendingInviteCompletionEntry struct {
	InviteID                string `json:"inviteId"`
	GroupID                 string `json:"groupId"`
	InvitedUserID           string `json:"invitedUserId"`
	InvitedEd25519PublicKey string `json:"invitedEd25519PublicKey"`
	InvitedX25519PublicKey  string `json:"invitedX25519PublicKey"`
	AcceptanceSignature     string `json:"acceptanceSignature"`
	// InviteMAC is served back opaquely -- see
	// acceptInviteRequest.InviteMAC's own doc comment. The inviter's own
	// client re-derives k from its own long-term signing seed and verifies
	// this before ever wrapping the group key to InvitedX25519PublicKey.
	InviteMAC string `json:"inviteMAC"`
}

type pendingInviteCompletionsResponse struct {
	Invites []pendingInviteCompletionEntry `json:"invites"`
}

// pendingInviteCompletions implements GET /api/invites/pending-completions
// -- issue #40, step 3's discovery query: "the next time the inviter's
// client is online," this is what that client calls (on login, per
// docs/DESIGN.md: "completion is driven by that query on login, not by the
// notification path") to find its own invites that have been accepted and
// are awaiting completion.
func (h *Handler) pendingInviteCompletions(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	pending, err := h.db.PendingInviteCompletions(r.Context(), userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not list pending invite completions")
		return
	}

	entries := make([]pendingInviteCompletionEntry, 0, len(pending))
	for _, p := range pending {
		entries = append(entries, pendingInviteCompletionEntry{
			InviteID:                p.InviteID,
			GroupID:                 p.GroupID,
			InvitedUserID:           p.InvitedUserID,
			InvitedEd25519PublicKey: encodeBase64(p.InvitedEd25519PublicKey),
			InvitedX25519PublicKey:  encodeBase64(p.InvitedX25519PublicKey),
			AcceptanceSignature:     encodeBase64(p.AcceptanceSignature),
			InviteMAC:               encodeBase64(p.InviteMAC),
		})
	}
	WriteJSON(w, http.StatusOK, pendingInviteCompletionsResponse{Invites: entries})
}

// completeInviteRequest is the wire shape of
// POST /api/invites/{id}/complete -- issue #40, step 3. The inviter's own
// client wraps the group key to the invitee's signed X25519 key (from
// GET /api/invites/pending-completions, re-verified client-side before
// this call is ever made) and posts the result here.
type completeInviteRequest struct {
	WrappedGroupKey wrappedKey `json:"wrappedGroupKey"`
	// Generation is the group-key generation this wrap is under -- always 0
	// today (no key rotation exists yet, #78), carried as a real field
	// rather than hardcoded so completing against a rotated group needs no
	// wire-shape change later.
	Generation int64 `json:"generation"`
}

// completeInvite implements POST /api/invites/{id}/complete -- issue #40,
// step 3. Authenticated as the INVITER (never the invitee -- the invitee
// has no part in step 3 at all, per docs/DESIGN.md: "step 3 happens
// automatically the next time the inviter's client is online").
//
// This handler does not itself verify AcceptanceSignature -- the inviter's
// own client is the party whose verification of it actually protects the
// handshake (docs/DESIGN.md: "wraps the group key to the X25519 key that
// was signed in step 2 -- never to a key the server offers unilaterally"),
// matching db.CompleteInvite's own doc comment. What this handler DOES
// check is that the caller is genuinely this invite's inviter, by reading
// PendingInviteCompletions.INVITE#<iid>'s own row scoped to the caller's
// own USER# partition rather than trusting a groupId/invitedUserId the
// request body might otherwise supply -- the same "second party must never
// name a row in the inviter's own partition directly" principle #39's
// design comment establishes for acceptance.
func (h *Handler) completeInvite(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	inviteID := r.PathValue("id")
	if !idgen.ValidUUID(inviteID) {
		WriteError(w, http.StatusBadRequest, "id: must be a well-formed, lowercase UUIDv4")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxCompleteInviteBodyBytes)
	var req completeInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	wrappedGroupKey, err := decodeWrappedKey(req.WrappedGroupKey)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "wrappedGroupKey: "+err.Error())
		return
	}
	if req.Generation < 0 {
		WriteError(w, http.StatusBadRequest, "generation: must not be negative")
		return
	}

	// Find this exact invite among the caller's OWN pending completions --
	// this is what proves the caller is really this invite's inviter (their
	// own USER# partition is where the SENT# row lives) and, in the same
	// read, hands back the invitee's identity/keys this handler needs to
	// write the membership. A caller-supplied invitedUserId would let
	// anyone complete an invite as if it were theirs; there is deliberately
	// no such field on completeInviteRequest.
	pending, err := h.db.PendingInviteCompletions(r.Context(), userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not complete invite")
		return
	}
	var match *models.SentInvite
	for i := range pending {
		if pending[i].InviteID == inviteID {
			match = &pending[i]
			break
		}
	}
	if match == nil {
		WriteError(w, http.StatusNotFound, "no pending invite completion with this id for the caller")
		return
	}

	// The SENT# row alone only proves the caller WAS an admin or
	// ambassador at CREATE time, up to maxInviteTTL earlier, plus
	// the completion deadline and its grace week -- it says nothing about whether they
	// still hold that role now. Without this check, an inviter demoted to
	// Member or removed from the group entirely (#36/#37, next in M4)
	// could still complete a pending invite and have the server write a
	// MEMBER# for someone the group's CURRENT admins never approved.
	// createInvite's own check (the same GetMembership call, same
	// Admin/Ambassador requirement) is what this mirrors -- see
	// docs/DESIGN.md: "the current role... gates writes... with a plain
	// GetItem."
	inviterMembership, err := h.db.GetMembership(r.Context(), match.GroupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not complete invite")
		return
	}
	if inviterMembership == nil ||
		(inviterMembership.Role != models.RoleAdmin && inviterMembership.Role != models.RoleAmbassador) {
		WriteError(w, http.StatusForbidden, "must currently be an admin or ambassador of this group to complete an invite")
		return
	}
	// req.Generation is otherwise taken purely on the client's word --
	// harmless today (no key rotation exists yet, #78, so every
	// membership's generation is always 0), but DESIGN.md is explicit that
	// "the chain link must be committed before any membership item points
	// at the new generation." Requiring it to match the inviter's OWN
	// current generation (now already in hand from the role check above)
	// is a cheap guard against a stale or misbehaving client writing a
	// membership pointing at a superseded generation once rotation exists.
	if req.Generation != inviterMembership.Generation {
		WriteError(w, http.StatusBadRequest, "generation: does not match the caller's current generation")
		return
	}

	err = h.db.CompleteInvite(r.Context(), db.CompleteInviteInput{
		InviteID:        inviteID,
		GroupID:         match.GroupID,
		InviterUserID:   userID,
		InvitedUserID:   match.InvitedUserID,
		Generation:      req.Generation,
		WrappedGroupKey: wrappedGroupKey,
		Role:            models.RoleMember,
	})
	if err != nil {
		if errors.Is(err, db.ErrInviteAlreadyCompleted) {
			// Another of the inviter's own sessions (two tabs/devices)
			// completed this same invite first -- not an error the caller
			// needs to alarm about, the membership already exists.
			WriteJSON(w, http.StatusOK, map[string]string{"status": "already completed"})
			return
		}
		if errors.Is(err, db.ErrInviterNotEligible) {
			h.writeInviterNotEligible(w, r, match.GroupID, userID)
			return
		}
		if errors.Is(err, db.ErrGroupGone) {
			// Backstop for a narrow race: the inviter's membership read above
			// passed, then the last member left and deleted the group before
			// this write. LeaveGroup clears a leaver's own invites, so in the
			// ordinary case this is never reached (the membership check 403s
			// first); clear the two invite rows so a racing invite does not
			// linger in pending-completions.
			if cleanupErr := h.db.CleanupAlreadyMemberInvite(r.Context(), inviteID, userID); cleanupErr != nil {
				WriteError(w, http.StatusInternalServerError, "could not complete invite")
				return
			}
			WriteErrorWithCode(w, http.StatusGone, "this group no longer exists", "group_gone")
			return
		}
		if errors.Is(err, db.ErrInviteeDeleted) {
			// The invitee deleted their account after accepting (#77). The
			// invite can never complete, so clear its rows as the group-gone
			// branch does.
			if cleanupErr := h.db.CleanupAlreadyMemberInvite(r.Context(), inviteID, userID); cleanupErr != nil {
				WriteError(w, http.StatusInternalServerError, "could not complete invite")
				return
			}
			WriteErrorWithCode(w, http.StatusGone, "the invited account no longer exists", "invitee_deleted")
			return
		}
		if errors.Is(err, db.ErrAlreadyMember) {
			// The membership this call would have created already exists
			// some other way -- but the two invite rows are still there,
			// and would otherwise become a zombie: pending-completions
			// keeps returning this same invite, and every future login
			// re-unwraps, re-wraps, and hits this exact 409 again, until
			// the row's TTL (completion deadline plus a grace week) eventually sweeps it. Run
			// a follow-up cleanup transaction (no membership write, since
			// there is nothing left to write) so this invite stops
			// showing up as pending. CleanupAlreadyMemberInvite's own
			// deletes are unconditional (its own doc comment explains
			// why -- a racing second cleanup/completion attempt having
			// already cleared one or both rows first is simply a no-op,
			// never an error), so any error it does return here is a
			// genuine infra failure, not "already cleaned up."
			if cleanupErr := h.db.CleanupAlreadyMemberInvite(r.Context(), inviteID, userID); cleanupErr != nil {
				WriteError(w, http.StatusInternalServerError, "could not complete invite")
				return
			}
			WriteErrorWithCode(w, http.StatusConflict, "invitee is already a member of this group", "already_member")
			return
		}
		WriteError(w, http.StatusInternalServerError, "could not complete invite")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]string{"status": "completed"})
}

// sentInviteEntry is one invite in GET /api/invites/sent -- issue #41. The
// group is named by id only: a private group's name is ciphertext the
// server cannot render, so the client resolves it from its own group list.
type sentInviteEntry struct {
	InviteID  string `json:"inviteId"`
	GroupID   string `json:"groupId"`
	ExpiresAt string `json:"expiresAt"`
	// Accepted is true once an invitee has completed step 2 and the invite
	// is awaiting the inviter's own step 3 (#40). CompletionDeadline,
	// Overdue and RemovalDate are set only then. Overdue means the deadline
	// has passed with step 3 still not done (#83); the row stays visible
	// until RemovalDate, when DynamoDB's TTL may sweep it.
	Accepted           bool   `json:"accepted"`
	CompletionDeadline string `json:"completionDeadline,omitempty"`
	Overdue            bool   `json:"overdue,omitempty"`
	RemovalDate        string `json:"removalDate,omitempty"`
}

type sentInvitesResponse struct {
	Invites []sentInviteEntry `json:"invites"`
}

// sentInvites implements GET /api/invites/sent -- issue #41: the caller's
// own outstanding invites, so an inviter can see (and revoke, via DELETE
// /api/invites/{id}) links they have handed out.
func (h *Handler) sentInvites(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	now := time.Now()
	views, err := h.db.ListSentInvites(r.Context(), userID, now)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not list sent invites")
		return
	}

	entries := make([]sentInviteEntry, 0, len(views))
	for _, v := range views {
		e := sentInviteEntry{
			InviteID:  v.InviteID,
			GroupID:   v.GroupID,
			ExpiresAt: v.ExpiresAt,
			Accepted:  v.InvitedUserID != "",
		}
		if e.Accepted {
			deadline := v.EffectiveCompletionDeadline()
			e.CompletionDeadline = time.Unix(deadline, 0).UTC().Format(time.RFC3339)
			e.Overdue = now.Unix() > deadline
			e.RemovalDate = time.Unix(v.TTL, 0).UTC().Format(time.RFC3339)
		}
		entries = append(entries, e)
	}
	WriteJSON(w, http.StatusOK, sentInvitesResponse{Invites: entries})
}

// receivedInviteEntry is one invite in GET /api/invites/received -- issue
// #41. Every entry is one the caller has already accepted and that is
// waiting on its inviter, so the only state to report is the deadline.
type receivedInviteEntry struct {
	InviteID           string `json:"inviteId"`
	GroupID            string `json:"groupId"`
	InviterUserID      string `json:"inviterUserId"`
	CompletionDeadline string `json:"completionDeadline"`
	// Overdue and RemovalDate: see sentInviteEntry. An overdue entry is the
	// invitee's only signal that the inviter never completed, since the
	// acceptance was already reported to them as a success (#83).
	Overdue     bool   `json:"overdue,omitempty"`
	RemovalDate string `json:"removalDate"`
}

type receivedInvitesResponse struct {
	Invites []receivedInviteEntry `json:"invites"`
}

// receivedInvites implements GET /api/invites/received -- issue #41, and
// the invitee half of #83: an accepted invite stays visible as "waiting on
// the inviter" until step 3 completes.
func (h *Handler) receivedInvites(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	now := time.Now()
	invites, err := h.db.ListReceivedInvites(r.Context(), userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not list received invites")
		return
	}

	entries := make([]receivedInviteEntry, 0, len(invites))
	for _, inv := range invites {
		entries = append(entries, receivedInviteEntry{
			InviteID:           strings.TrimPrefix(inv.PK, "INVITE#"),
			GroupID:            inv.GroupID,
			InviterUserID:      inv.InviterUserID,
			CompletionDeadline: time.Unix(inv.EffectiveCompletionDeadline(), 0).UTC().Format(time.RFC3339),
			Overdue:            now.Unix() > inv.EffectiveCompletionDeadline(),
			RemovalDate:        time.Unix(inv.TTL, 0).UTC().Format(time.RFC3339),
		})
	}
	WriteJSON(w, http.StatusOK, receivedInvitesResponse{Invites: entries})
}

// writeInviterNotEligible answers a CompleteInvite whose inviter check failed.
// That check covers role AND key generation, so re-read to tell them apart:
// an inviter who is still admin or ambassador had their key moved under them
// (a rotation re-wrapped them), which is retryable (409), not a 403.
func (h *Handler) writeInviterNotEligible(w http.ResponseWriter, r *http.Request, groupID, inviterID string) {
	now, err := h.db.GetMembership(r.Context(), groupID, inviterID)
	if err == nil && now != nil && (now.Role == models.RoleAdmin || now.Role == models.RoleAmbassador) {
		WriteErrorWithCode(w, http.StatusConflict, "your group key changed; reload and retry", "conflict_retry")
		return
	}
	WriteError(w, http.StatusForbidden, "must currently be an admin or ambassador of this group")
}
