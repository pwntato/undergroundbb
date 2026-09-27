package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

func doJSON(t *testing.T, h *Handler, method, path string, cookie *http.Cookie, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest(method, path, reader)
	if cookie != nil {
		httpReq.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, httpReq)
	return rec
}

// signedCreateInviteRequest builds a genuinely-signed createInviteRequest
// for inviter, matching signedCreateGroupRequest's own reasoning: a real
// Ed25519 signature over the real payload, so acceptInvite/createInvite's
// crypto.Verify calls exercise real cryptography.
func signedCreateInviteRequest(t *testing.T, inviter registeredUser, groupID string, expiresAt time.Time) createInviteRequest {
	t.Helper()
	inviteID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
	expiresAtStr := expiresAt.UTC().Format(time.RFC3339)
	payload := crypto.InviteCreationPayload(inviteID, groupID, inviter.signPub, expiresAtStr)
	sig, err := crypto.Sign(inviter.signPriv, crypto.ContextInvite, payload)
	if err != nil {
		t.Fatalf("sign invite creation: %v", err)
	}
	return createInviteRequest{
		InviteID:          inviteID,
		ExpiresAt:         expiresAtStr,
		CreationSignature: base64.StdEncoding.EncodeToString(sig),
	}
}

// createTestGroupWithMembers registers a group with creator as its Admin
// (via the real createGroup endpoint) so invite tests have a genuine
// GROUP#<gid>/MEMBER#<creator> row to check the Admin/Ambassador gate
// against.
func createTestGroupWithMembers(t *testing.T, h *Handler, creator registeredUser, creatorCookie *http.Cookie) string {
	t.Helper()
	req := signedCreateGroupRequest(t, creator)
	rec := doCreateGroup(t, h, creatorCookie, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("createGroup status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var resp createGroupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding createGroup response: %v", err)
	}
	return resp.GroupID
}

func TestCreateInviteSuccess(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)

	req := signedCreateInviteRequest(t, creator, groupID, time.Now().Add(24*time.Hour))
	rec := doJSON(t, h, http.MethodPost, "/api/groups/"+groupID+"/invites", creatorCookie, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var resp createInviteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.InviteID != req.InviteID {
		t.Errorf("InviteID = %q, want %q", resp.InviteID, req.InviteID)
	}
}

// TestCreateInviteRequiresAdminOrAmbassador pins docs/DESIGN.md's "Admin or
// Ambassador only" -- a plain Member (or a non-member entirely) must be
// rejected before any signature is even checked.
func TestCreateInviteRequiresAdminOrAmbassador(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)

	outsider, outsiderCookie := loggedInUser(t, h)
	req := signedCreateInviteRequest(t, outsider, groupID, time.Now().Add(24*time.Hour))
	rec := doJSON(t, h, http.MethodPost, "/api/groups/"+groupID+"/invites", outsiderCookie, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestCreateInviteRejectsExpiryOutOfBounds(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)

	tooSoon := signedCreateInviteRequest(t, creator, groupID, time.Now().Add(1*time.Minute))
	rec := doJSON(t, h, http.MethodPost, "/api/groups/"+groupID+"/invites", creatorCookie, tooSoon)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("too-soon expiry: status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	tooFar := signedCreateInviteRequest(t, creator, groupID, time.Now().Add(365*24*time.Hour))
	rec = doJSON(t, h, http.MethodPost, "/api/groups/"+groupID+"/invites", creatorCookie, tooFar)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("too-far expiry: status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCreateInviteRejectsForgedSignature mutation-verifies that a signature
// which does not actually match the payload is rejected -- if this test
// passed with a tampered signature, createInvite's crypto.Verify call would
// not be doing its job.
func TestCreateInviteRejectsForgedSignature(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)

	req := signedCreateInviteRequest(t, creator, groupID, time.Now().Add(24*time.Hour))
	req.ExpiresAt = time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339) // tamper after signing
	rec := doJSON(t, h, http.MethodPost, "/api/groups/"+groupID+"/invites", creatorCookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func createTestInvite(t *testing.T, h *Handler, inviter registeredUser, inviterCookie *http.Cookie, groupID string, expiresAt time.Time) string {
	t.Helper()
	req := signedCreateInviteRequest(t, inviter, groupID, expiresAt)
	rec := doJSON(t, h, http.MethodPost, "/api/groups/"+groupID+"/invites", inviterCookie, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("createInvite status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	return req.InviteID
}

func TestGetInviteSuccess(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	// GET /api/invites/{id} is unauthenticated -- no cookie passed.
	rec := doJSON(t, h, http.MethodGet, "/api/invites/"+inviteID, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp getInviteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.GroupID != groupID {
		t.Errorf("GroupID = %q, want %q", resp.GroupID, groupID)
	}
	if resp.InviterUserID != creator.userID {
		t.Errorf("InviterUserID = %q, want %q", resp.InviterUserID, creator.userID)
	}
	// InviterWrappingPublicKey is read fresh from the inviter's own current
	// PROFILE (getInviteResponse's own doc comment) -- not part of the
	// signed step-1 payload at all, but required for the invitee's client
	// to ever recompute and check the fingerprint carried in the invite
	// link's URL fragment.
	wantWrapPub := base64.StdEncoding.EncodeToString(creator.wrapPub)
	if resp.InviterWrappingPublicKey != wantWrapPub {
		t.Errorf("InviterWrappingPublicKey = %q, want %q", resp.InviterWrappingPublicKey, wantWrapPub)
	}
	if resp.Accepted {
		t.Error("Accepted = true for a freshly created invite, want false")
	}
}

func TestGetInviteNotFound(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	inviteID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
	rec := doJSON(t, h, http.MethodGet, "/api/invites/"+inviteID, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// signedAcceptInviteRequest builds a genuinely-signed acceptInviteRequest
// for invitee, matching the real step-2 payload shape.
func signedAcceptInviteRequest(t *testing.T, invitee registeredUser, inviteID string) acceptInviteRequest {
	t.Helper()
	payload := crypto.InviteAcceptancePayload(inviteID, invitee.signPub, invitee.wrapPub)
	sig, err := crypto.Sign(invitee.signPriv, crypto.ContextInvite, payload)
	if err != nil {
		t.Fatalf("sign invite acceptance: %v", err)
	}
	return acceptInviteRequest{AcceptanceSignature: base64.StdEncoding.EncodeToString(sig)}
}

func TestAcceptInviteSuccess(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	invitee, inviteeCookie := loggedInUser(t, h)
	req := signedAcceptInviteRequest(t, invitee, inviteID)
	rec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", inviteeCookie, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// The invite must now report accepted=true.
	getRec := doJSON(t, h, http.MethodGet, "/api/invites/"+inviteID, nil, nil)
	var getResp getInviteResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decoding get response: %v", err)
	}
	if !getResp.Accepted {
		t.Error("Accepted = false after a successful accept, want true")
	}
}

// TestAcceptInviteWithMillisecondPrecisionExpiresAtSucceeds is a live
// regression test for a real bug caught in manual browser verification
// (not by any earlier unit test, all of which built expiresAtStr via Go's
// time.RFC3339 -- which has no fractional-seconds directive and so never
// produces a millisecond-bearing string in the first place, unlike a real
// browser's `new Date(...).toISOString()`, which always does).
//
// The bug: db.CreateInvite used to derive the STORED models.Invite.ExpiresAt
// by reformatting the parsed time.Time via .Format(time.RFC3339), which
// silently drops sub-second precision -- producing a stored string that
// DIFFERED from the exact bytes crypto.InviteCreationPayload actually
// signed whenever the client's original expiresAt carried milliseconds.
// acceptInvite's later re-verification of CreationSignature against the
// stored (reformatted) ExpiresAt then failed for every such invite, with a
// 400 masquerading as "this invite cannot be trusted." Fixed by storing
// ExpiresAt verbatim (CreateInviteInput.ExpiresAt) rather than re-deriving
// it from a parsed time.Time.
func TestAcceptInviteWithMillisecondPrecisionExpiresAtSucceeds(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)

	inviteID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
	// .123Z: milliseconds present, exactly like a real
	// `new Date(...).toISOString()` -- time.RFC3339 alone never produces
	// this, which is why every other test in this file accidentally
	// avoided the bug shape.
	expiresAtStr := time.Now().Add(24 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
	payload := crypto.InviteCreationPayload(inviteID, groupID, creator.signPub, expiresAtStr)
	sig, err := crypto.Sign(creator.signPriv, crypto.ContextInvite, payload)
	if err != nil {
		t.Fatalf("sign invite creation: %v", err)
	}
	req := createInviteRequest{
		InviteID:          inviteID,
		ExpiresAt:         expiresAtStr,
		CreationSignature: base64.StdEncoding.EncodeToString(sig),
	}
	createRec := doJSON(t, h, http.MethodPost, "/api/groups/"+groupID+"/invites", creatorCookie, req)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d, body: %s", createRec.Code, http.StatusCreated, createRec.Body.String())
	}

	// The critical assertion: GET must return the EXACT string that was
	// signed, byte-for-byte -- not a reformatted one.
	getRec := doJSON(t, h, http.MethodGet, "/api/invites/"+inviteID, nil, nil)
	var getResp getInviteResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decoding get response: %v", err)
	}
	if getResp.ExpiresAt != expiresAtStr {
		t.Fatalf("stored ExpiresAt = %q, want the exact signed string %q", getResp.ExpiresAt, expiresAtStr)
	}

	// The actual end-to-end proof: acceptInvite re-verifies
	// CreationSignature against the STORED ExpiresAt -- if storage had
	// reformatted it, this would fail with 400, not succeed.
	invitee, inviteeCookie := loggedInUser(t, h)
	acceptRec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", inviteeCookie, signedAcceptInviteRequest(t, invitee, inviteID))
	if acceptRec.Code != http.StatusOK {
		t.Fatalf("accept status = %d, want %d, body: %s", acceptRec.Code, http.StatusOK, acceptRec.Body.String())
	}
}

// TestAcceptInviteSecondAcceptorFails is the handler-level counterpart of
// db.TestAcceptInviteSecondAcceptorFails -- pins the single-use guarantee
// end to end, including the HTTP status code a real client would see.
func TestAcceptInviteSecondAcceptorFails(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	firstInvitee, firstCookie := loggedInUser(t, h)
	rec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", firstCookie, signedAcceptInviteRequest(t, firstInvitee, inviteID))
	if rec.Code != http.StatusOK {
		t.Fatalf("first accept status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	secondInvitee, secondCookie := loggedInUser(t, h)
	rec = doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", secondCookie, signedAcceptInviteRequest(t, secondInvitee, inviteID))
	if rec.Code != http.StatusConflict {
		t.Fatalf("second accept status = %d, want %d, body: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

// TestAcceptInviteExpiredFails pins the read-time expiry check -- "TTL
// deletion is eventual, so an accept path will encounter expired-but-not-
// yet-deleted invites and must refuse them." createInvite itself refuses to
// sign/accept a request whose ExpiresAt is already in the past
// (minInviteTTL's own floor), so a genuinely expired-but-not-yet-swept row
// is built directly against the db layer here, with a real signature over
// the real (already-past) ExpiresAt the inviter would have signed at
// creation time, exactly the shape TTL's eventual deletion can leave
// behind. This exercises acceptInvite's own expiry check in isolation from
// createInvite's floor, which is the actual security control under test.
func TestAcceptInviteExpiredFails(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)

	inviteID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
	pastExpiry := time.Now().Add(-1 * time.Hour)
	expiresAtStr := pastExpiry.UTC().Format(time.RFC3339)
	payload := crypto.InviteCreationPayload(inviteID, groupID, creator.signPub, expiresAtStr)
	sig, err := crypto.Sign(creator.signPriv, crypto.ContextInvite, payload)
	if err != nil {
		t.Fatalf("sign invite creation: %v", err)
	}
	if err := h.db.CreateInvite(t.Context(), db.CreateInviteInput{
		InviteID:                inviteID,
		GroupID:                 groupID,
		InviterUserID:           creator.userID,
		InviterSigningPublicKey: creator.signPub,
		CreationSignature:       sig,
		// Verbatim, matching what was actually signed above -- see
		// db.CreateInviteInput.ExpiresAt's own doc comment.
		ExpiresAt:       expiresAtStr,
		ExpiresAtParsed: pastExpiry,
	}); err != nil {
		t.Fatalf("db.CreateInvite: %v", err)
	}

	invitee, inviteeCookie := loggedInUser(t, h)
	rec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", inviteeCookie, signedAcceptInviteRequest(t, invitee, inviteID))
	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusGone, rec.Body.String())
	}
}

func TestPendingInviteCompletionsAndComplete(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	invitee, inviteeCookie := loggedInUser(t, h)
	acceptRec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", inviteeCookie, signedAcceptInviteRequest(t, invitee, inviteID))
	if acceptRec.Code != http.StatusOK {
		t.Fatalf("accept status = %d, want %d, body: %s", acceptRec.Code, http.StatusOK, acceptRec.Body.String())
	}

	pendingRec := doJSON(t, h, http.MethodGet, "/api/invites/pending-completions", creatorCookie, nil)
	if pendingRec.Code != http.StatusOK {
		t.Fatalf("pending status = %d, want %d, body: %s", pendingRec.Code, http.StatusOK, pendingRec.Body.String())
	}
	var pendingResp pendingInviteCompletionsResponse
	if err := json.Unmarshal(pendingRec.Body.Bytes(), &pendingResp); err != nil {
		t.Fatalf("decoding pending response: %v", err)
	}
	if len(pendingResp.Invites) != 1 {
		t.Fatalf("pending invites = %d, want 1", len(pendingResp.Invites))
	}
	entry := pendingResp.Invites[0]
	if entry.InviteID != inviteID {
		t.Errorf("InviteID = %q, want %q", entry.InviteID, inviteID)
	}
	if entry.InvitedUserID != invitee.userID {
		t.Errorf("InvitedUserID = %q, want %q", entry.InvitedUserID, invitee.userID)
	}

	completeReq := completeInviteRequest{
		WrappedGroupKey: wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		Generation:      0,
	}
	completeRec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/complete", creatorCookie, completeReq)
	if completeRec.Code != http.StatusOK {
		t.Fatalf("complete status = %d, want %d, body: %s", completeRec.Code, http.StatusOK, completeRec.Body.String())
	}

	// The completed invite must no longer be pending.
	pendingRec2 := doJSON(t, h, http.MethodGet, "/api/invites/pending-completions", creatorCookie, nil)
	var pendingResp2 pendingInviteCompletionsResponse
	if err := json.Unmarshal(pendingRec2.Body.Bytes(), &pendingResp2); err != nil {
		t.Fatalf("decoding second pending response: %v", err)
	}
	if len(pendingResp2.Invites) != 0 {
		t.Errorf("pending invites after completion = %d, want 0", len(pendingResp2.Invites))
	}

	// The invitee must now actually be a member.
	inviteeGroupsRec := doJSON(t, h, http.MethodGet, "/api/groups", inviteeCookie, nil)
	if inviteeGroupsRec.Code != http.StatusOK {
		t.Fatalf("listGroups status = %d, want %d, body: %s", inviteeGroupsRec.Code, http.StatusOK, inviteeGroupsRec.Body.String())
	}
	var groupsResp listGroupsResponse
	if err := json.Unmarshal(inviteeGroupsRec.Body.Bytes(), &groupsResp); err != nil {
		t.Fatalf("decoding groups response: %v", err)
	}
	found := false
	for _, g := range groupsResp.Groups {
		if g.GroupID == groupID {
			found = true
			if g.Role != "member" {
				t.Errorf("invitee's role = %q, want %q", g.Role, "member")
			}
		}
	}
	if !found {
		t.Error("invitee's own GET /api/groups does not include the group they were invited to")
	}
}

// TestCompleteInviteRejectsNonInviter pins that only the actual inviter --
// never the invitee, never a third party -- can complete step 3. The
// completeInvite handler has no invitedUserId field on its request body at
// all; this proves an unrelated caller simply has no pending completion to
// find, rather than trusting a request-supplied identity.
func TestCompleteInviteRejectsNonInviter(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	invitee, inviteeCookie := loggedInUser(t, h)
	acceptRec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", inviteeCookie, signedAcceptInviteRequest(t, invitee, inviteID))
	if acceptRec.Code != http.StatusOK {
		t.Fatalf("accept status = %d, want %d, body: %s", acceptRec.Code, http.StatusOK, acceptRec.Body.String())
	}

	completeReq := completeInviteRequest{
		WrappedGroupKey: wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		Generation:      0,
	}
	// The invitee themselves tries to complete their own invite -- must fail.
	rec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/complete", inviteeCookie, completeReq)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}
