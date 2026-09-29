package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
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

// endOfUTCDayStr rounds t up to the end of its own UTC calendar day, exactly
// "...T23:59:59Z" -- matching the client's own endOfUTCDay
// (CreateInviteScreen.tsx) and createInvite's own new validation (see that
// handler's own doc comment). Every test in this file that expects a
// createInvite call to SUCCEED must build its ExpiresAt this way now --
// signedCreateInviteRequest below does this automatically, so tests that
// want to exercise a REJECTED shape (a non-day-end timestamp, a
// millisecond-bearing one, an already-past one) build their own request
// directly instead of going through this helper.
func endOfUTCDayStr(t time.Time) string {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 23, 59, 59, 0, time.UTC).Format(time.RFC3339)
}

// signedCreateInviteRequest builds a genuinely-signed createInviteRequest
// for inviter, matching signedCreateGroupRequest's own reasoning: a real
// Ed25519 signature over the real payload, so acceptInvite/createInvite's
// crypto.Verify calls exercise real cryptography. approxExpiresAt is rounded
// to the end of its own UTC day (endOfUTCDayStr) before signing -- callers
// pass roughly how far out they want the invite to expire, not the exact
// wire string, matching how CreateInviteScreen.tsx's own EXPIRY_OPTIONS work.
func signedCreateInviteRequest(t *testing.T, inviter registeredUser, groupID string, approxExpiresAt time.Time) createInviteRequest {
	t.Helper()
	inviteID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
	expiresAtStr := endOfUTCDayStr(approxExpiresAt)
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

// signedCreateInviteRequestExact builds a genuinely-signed
// createInviteRequest for an EXACT wire expiresAt string, bypassing
// signedCreateInviteRequest's own automatic end-of-UTC-day rounding --
// used by tests that need a specific, deliberately non-default shape (an
// out-of-bounds TTL that still passes the day-end check, a malformed
// string, an already-past timestamp).
func signedCreateInviteRequestExact(t *testing.T, inviter registeredUser, groupID, expiresAtStr string) createInviteRequest {
	t.Helper()
	inviteID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
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

func TestCreateInviteRejectsExpiryOutOfBounds(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)

	// A day-end timestamp that is not really "1 minute from now" (the
	// day-end format cannot express that literally), but is guaranteed to
	// fall under minInviteTTL: the day-end of a date already in the past.
	// This exercises the SAME check TestCreateInviteRejectsNonDayEndExpiresAt
	// does not (that test's rejection fires on the day-end suffix check,
	// before ttl := time.Until(expiresAt) is even reached) -- a string that
	// DOES pass the day-end shape check but still fails the TTL floor.
	tooSoon := signedCreateInviteRequestExact(t, creator, groupID, endOfUTCDayStr(time.Now().Add(-48*time.Hour)))
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

// TestCreateInviteAccepts30DayOption is the exact regression PR #146 round-2
// review caught: CreateInviteScreen.tsx's "30 days" option means "the end
// of the UTC day 30 days from now" (endOfUTCDayStr(time.Now().Add(30*24h))),
// which is itself up to just under 24h MORE than a flat 30*24h away
// depending on what time of day the invite is created -- a literal
// 30*24h maxInviteTTL rejected this option on every real submission except
// one made at exactly 23:59:59Z. Pinning this exact client-shaped value
// against the server's own bound is what keeps the two from drifting apart
// again, which a bound expressed only as "30 * 24 * time.Hour" cannot
// catch on its own.
func TestCreateInviteAccepts30DayOption(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)

	req := signedCreateInviteRequest(t, creator, groupID, time.Now().Add(30*24*time.Hour))
	rec := doJSON(t, h, http.MethodPost, "/api/groups/"+groupID+"/invites", creatorCookie, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("30-day option: status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
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
// for invitee, matching the real step-2 payload shape. inviteMAC is
// computed under a fixed test macKey -- this handler package cannot verify
// it (it never has k, crypto.DeriveInviteMACKey's own doc comment), only
// decode and length-check it, so any well-formed 32-byte value exercises
// every path this package's own tests care about; the real derivation
// end-to-end is covered by web/src/lib/crypto/credential-material.test.ts
// instead.
func signedAcceptInviteRequest(t *testing.T, invitee registeredUser, inviteID string) acceptInviteRequest {
	t.Helper()
	payload := crypto.InviteAcceptancePayload(inviteID, invitee.signPub, invitee.wrapPub)
	sig, err := crypto.Sign(invitee.signPriv, crypto.ContextInvite, payload)
	if err != nil {
		t.Fatalf("sign invite acceptance: %v", err)
	}
	testMACKey := bytes.Repeat([]byte{0x42}, 32)
	mac := crypto.ComputeInviteMAC(testMACKey, payload)
	return acceptInviteRequest{
		AcceptanceSignature: base64.StdEncoding.EncodeToString(sig),
		InviteMAC:           base64.StdEncoding.EncodeToString(mac),
	}
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

// TestCreateInviteRejectsMillisecondPrecisionExpiresAt pins PR #146 round-1
// review's fix for the finding TestAcceptInviteWithMillisecondPrecisionExpiresAtSucceeds
// used to regression-test in the OPPOSITE direction (accepting a
// millisecond-bearing expiresAt, because storing it verbatim rather than
// reformatting it was the only fix that PR shipped). This test replaces
// that one: createInviteRequest.ExpiresAt must now be REJECTED outright
// unless it is exactly "...T23:59:59Z" -- see createInvite's own doc
// comment for why. A millisecond-bearing string like a real
// `new Date(...).toISOString()` produces (".123Z", not exactly "T23:59:59Z")
// is exactly the shape this now refuses, which also makes the original
// verbatim-string/reformatting bug structurally impossible: a value that
// can never carry milliseconds in the first place cannot suffer from a
// reformatting that silently drops them.
func TestCreateInviteRejectsMillisecondPrecisionExpiresAt(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)

	inviteID, err := idgen.UUID()
	if err != nil {
		t.Fatalf("idgen.UUID: %v", err)
	}
	// .123Z: milliseconds present, exactly like a real
	// `new Date(...).toISOString()` -- time.RFC3339 alone never produces
	// this, which is why every other test in this file uses a plain
	// RFC3339 string instead.
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
	if createRec.Code != http.StatusBadRequest {
		t.Fatalf("create status = %d, want %d, body: %s", createRec.Code, http.StatusBadRequest, createRec.Body.String())
	}
}

// TestCreateInviteRejectsNonDayEndExpiresAt pins the other half of the same
// check: a well-formed, millisecond-free RFC 3339 timestamp that simply
// isn't the end of a UTC day (e.g. a plain "N hours from now") must also be
// rejected, not just a millisecond-bearing one. Built via
// signedCreateInviteRequestExact, not signedCreateInviteRequest -- that
// helper's own automatic end-of-UTC-day rounding would make it impossible
// to construct the very shape this test exists to reject.
func TestCreateInviteRejectsNonDayEndExpiresAt(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)

	// Noon UTC, not 23:59:59 -- deliberately not a boundary time, so this
	// can never accidentally coincide with a real day-end string.
	future := time.Now().UTC().Add(24 * time.Hour)
	nonDayEnd := time.Date(future.Year(), future.Month(), future.Day(), 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	req := signedCreateInviteRequestExact(t, creator, groupID, nonDayEnd)
	rec := doJSON(t, h, http.MethodPost, "/api/groups/"+groupID+"/invites", creatorCookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
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

// TestAcceptInviteStoresAndServesInviteMAC pins that AcceptInviteRequest's
// InviteMAC round-trips, byte-for-byte, all the way to
// pendingInviteCompletions -- this handler package cannot verify it (it
// never has k), but it must still carry it faithfully, since the inviter's
// own client is what actually checks it at step 3.
func TestAcceptInviteStoresAndServesInviteMAC(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	invitee, inviteeCookie := loggedInUser(t, h)
	acceptReq := signedAcceptInviteRequest(t, invitee, inviteID)
	acceptRec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", inviteeCookie, acceptReq)
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
	if pendingResp.Invites[0].InviteMAC != acceptReq.InviteMAC {
		t.Errorf("served InviteMAC = %q, want the exact value accepted = %q", pendingResp.Invites[0].InviteMAC, acceptReq.InviteMAC)
	}
}

// TestAcceptInviteRejectsMalformedInviteMAC pins that a wrong-length
// inviteMAC is rejected before ever reaching db.AcceptInvite -- HMAC-SHA256
// is always exactly 32 bytes, and decodeBase64Field's own wantLen check is
// what enforces that here.
func TestAcceptInviteRejectsMalformedInviteMAC(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	invitee, inviteeCookie := loggedInUser(t, h)
	req := signedAcceptInviteRequest(t, invitee, inviteID)
	req.InviteMAC = base64.StdEncoding.EncodeToString([]byte("too-short"))
	rec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", inviteeCookie, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestAcceptInviteRejectsExistingMember pins non-blocking review finding
// #4/#5 (round 1): a caller who already holds a membership in the invite's
// own group -- including the inviter accepting their own link -- must be
// rejected with 409 already_member, rather than silently "using up" an
// invite meant for someone else. Without this check, AcceptInvite's own
// single-use condition (attribute_not_exists on InvitedUserID) still lets
// it through.
func TestAcceptInviteRejectsExistingMember(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	// The inviter -- already an Admin member of this group -- tries to
	// accept their own invite link.
	rec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", creatorCookie, signedAcceptInviteRequest(t, creator, inviteID))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	var errResp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("decoding error response: %v", err)
	}
	if errResp.Code != "already_member" {
		t.Errorf("error code = %q, want %q", errResp.Code, "already_member")
	}

	// The invite must still be usable by someone who is NOT already a
	// member -- this check must not have consumed it.
	invitee, inviteeCookie := loggedInUser(t, h)
	rec = doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", inviteeCookie, signedAcceptInviteRequest(t, invitee, inviteID))
	if rec.Code != http.StatusOK {
		t.Fatalf("real invitee's accept status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// setMembershipRole directly overwrites a GROUP#<gid>/MEMBER#<uid> item's
// Role -- there is no demote/remove endpoint yet (#36/#37, next in M4), so
// a role change between accept and complete can only be simulated by
// writing the row directly, bypassing every application-level path, the
// same escape-hatch reasoning rawDDB's own doc comment gives.
func setMembershipRole(t *testing.T, groupID, userID, role string) {
	t.Helper()
	ddb := rawDDB(t)
	_, err := ddb.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + userID},
		},
		UpdateExpression:         aws.String("SET #R = :role"),
		ExpressionAttributeNames: map[string]string{"#R": "Role"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":role": &types.AttributeValueMemberS{Value: role},
		},
	})
	if err != nil {
		t.Fatalf("setMembershipRole UpdateItem: %v", err)
	}
}

// TestCompleteInviteRejectsDemotedInviter pins blocking review finding #3
// (round 1): completeInvite must re-check the caller's CURRENT role, not
// just that a SENT# row exists (granted up to 30 days earlier). Simulates
// the inviter being demoted to a plain Member between accept and complete
// -- the only way to produce that state today, since #36/#37 (demote/
// remove) have not shipped yet.
func TestCompleteInviteRejectsDemotedInviter(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	invitee, inviteeCookie := loggedInUser(t, h)
	acceptRec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", inviteeCookie, signedAcceptInviteRequest(t, invitee, inviteID))
	if acceptRec.Code != http.StatusOK {
		t.Fatalf("accept status = %d, want %d, body: %s", acceptRec.Code, http.StatusOK, acceptRec.Body.String())
	}

	// The inviter loses Admin between acceptance and completion.
	setMembershipRole(t, groupID, creator.userID, "member")

	completeReq := completeInviteRequest{
		WrappedGroupKey: wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		Generation:      0,
	}
	rec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/complete", creatorCookie, completeReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	// The pending completion must still be there -- a rejected attempt
	// must not have silently consumed it.
	pendingRec := doJSON(t, h, http.MethodGet, "/api/invites/pending-completions", creatorCookie, nil)
	var pendingResp pendingInviteCompletionsResponse
	if err := json.Unmarshal(pendingRec.Body.Bytes(), &pendingResp); err != nil {
		t.Fatalf("decoding pending response: %v", err)
	}
	if len(pendingResp.Invites) != 1 {
		t.Errorf("pending invites after rejected complete = %d, want 1 (must not be consumed)", len(pendingResp.Invites))
	}
}

// TestCompleteInviteRejectsGenerationMismatch pins non-blocking review
// finding #6: req.Generation must match the inviter's own current
// generation, not be taken purely on the client's word.
func TestCompleteInviteRejectsGenerationMismatch(t *testing.T) {
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
		Generation:      1, // the inviter's own real generation is 0
	}
	rec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/complete", creatorCookie, completeReq)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestCompleteInviteAlreadyMemberCleansUpInviteRows pins non-blocking
// review finding #4: an already_member conflict at complete time must not
// leave a zombie invite behind. Simulates the invitee joining the same
// group some other way between acceptance and completion by completing
// the SAME invite twice with two different "inviter" sessions is not
// possible (completeInvite is scoped to the caller's own pending
// completions) -- instead, this drives db.CompleteInvite's own
// ErrAlreadyMember path directly by pre-creating the invitee's membership
// before ever calling complete.
func TestCompleteInviteAlreadyMemberCleansUpInviteRows(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	invitee, inviteeCookie := loggedInUser(t, h)
	acceptRec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", inviteeCookie, signedAcceptInviteRequest(t, invitee, inviteID))
	if acceptRec.Code != http.StatusOK {
		t.Fatalf("accept status = %d, want %d, body: %s", acceptRec.Code, http.StatusOK, acceptRec.Body.String())
	}

	// The invitee becomes a member of this same group some other way
	// (simulated directly -- no such alternate path exists yet) before the
	// inviter's own client ever completes this invite.
	membership := models.Membership{
		Record: models.Record{
			PK:     "GROUP#" + groupID,
			SK:     "MEMBER#" + invitee.userID,
			Type:   "Membership",
			GSI1PK: "USER#" + invitee.userID,
			GSI1SK: "GROUP#" + groupID,
		},
		Role:       models.RoleMember,
		Generation: 0,
	}
	av, err := attributevalue.MarshalMap(membership)
	if err != nil {
		t.Fatalf("MarshalMap membership: %v", err)
	}
	ddb := rawDDB(t)
	if _, err := ddb.PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName: aws.String(testTableName()),
		Item:      av,
	}); err != nil {
		t.Fatalf("PutItem membership: %v", err)
	}

	completeReq := completeInviteRequest{
		WrappedGroupKey: wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		Generation:      0,
	}
	rec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/complete", creatorCookie, completeReq)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}

	// The zombie-invite fix: pending-completions must no longer return
	// this invite -- CleanupAlreadyMemberInvite must have deleted both
	// rows, rather than leaving them to keep reappearing on every future
	// login until the 7-day deadline TTL eventually sweeps them.
	pendingRec := doJSON(t, h, http.MethodGet, "/api/invites/pending-completions", creatorCookie, nil)
	var pendingResp pendingInviteCompletionsResponse
	if err := json.Unmarshal(pendingRec.Body.Bytes(), &pendingResp); err != nil {
		t.Fatalf("decoding pending response: %v", err)
	}
	if len(pendingResp.Invites) != 0 {
		t.Errorf("pending invites after already_member cleanup = %d, want 0", len(pendingResp.Invites))
	}
}

// TestRevokeInviteSuccess pins docs/DESIGN.md's revocation remedy: the
// inviter can DELETE an invite before acceptance, and it is genuinely gone
// afterward -- GET returns 404 and it no longer shows up anywhere.
func TestRevokeInviteSuccess(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	rec := doJSON(t, h, http.MethodDelete, "/api/invites/"+inviteID, creatorCookie, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	getRec := doJSON(t, h, http.MethodGet, "/api/invites/"+inviteID, nil, nil)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("get after revoke: status = %d, want %d, body: %s", getRec.Code, http.StatusNotFound, getRec.Body.String())
	}

	// The invite must also no longer be acceptable.
	invitee, inviteeCookie := loggedInUser(t, h)
	acceptRec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", inviteeCookie, signedAcceptInviteRequest(t, invitee, inviteID))
	if acceptRec.Code != http.StatusNotFound {
		t.Fatalf("accept after revoke: status = %d, want %d, body: %s", acceptRec.Code, http.StatusNotFound, acceptRec.Body.String())
	}
}

// TestRevokeInviteRejectsNonInviter pins that only the actual inviter can
// revoke -- a third party (even a fellow admin of the same group) gets the
// same 404 a nonexistent invite would, never a confirmation that this
// invite exists but isn't theirs.
func TestRevokeInviteRejectsNonInviter(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	_, outsiderCookie := loggedInUser(t, h)
	rec := doJSON(t, h, http.MethodDelete, "/api/invites/"+inviteID, outsiderCookie, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}

	// The invite must be untouched -- still fetchable and acceptable.
	getRec := doJSON(t, h, http.MethodGet, "/api/invites/"+inviteID, nil, nil)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get after rejected revoke: status = %d, want %d, body: %s", getRec.Code, http.StatusOK, getRec.Body.String())
	}
}

// TestRevokeInviteRejectsAfterAcceptance pins that revocation is
// pre-acceptance only -- docs/DESIGN.md: deleting the rows out from under
// an invitee who was already told "you're in" would silently strand them.
func TestRevokeInviteRejectsAfterAcceptance(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	invitee, inviteeCookie := loggedInUser(t, h)
	acceptRec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", inviteeCookie, signedAcceptInviteRequest(t, invitee, inviteID))
	if acceptRec.Code != http.StatusOK {
		t.Fatalf("accept status = %d, want %d, body: %s", acceptRec.Code, http.StatusOK, acceptRec.Body.String())
	}

	rec := doJSON(t, h, http.MethodDelete, "/api/invites/"+inviteID, creatorCookie, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}

	// The pending completion must still be there -- the rejected revoke
	// must not have touched either row.
	pendingRec := doJSON(t, h, http.MethodGet, "/api/invites/pending-completions", creatorCookie, nil)
	var pendingResp pendingInviteCompletionsResponse
	if err := json.Unmarshal(pendingRec.Body.Bytes(), &pendingResp); err != nil {
		t.Fatalf("decoding pending response: %v", err)
	}
	if len(pendingResp.Invites) != 1 {
		t.Errorf("pending invites after rejected revoke = %d, want 1", len(pendingResp.Invites))
	}
}

// TestRevokeInviteRequiresSession pins that DELETE /api/invites/{id} is
// authenticated -- an invite is otherwise a bearer token anyone holding the
// link can act on for GET, but revocation is inviter-only and therefore
// requires a real session.
func TestRevokeInviteRequiresSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	rec := doJSON(t, h, http.MethodDelete, "/api/invites/"+inviteID, nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestSentAndReceivedInvitesLifecycle(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	pendingID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))
	acceptedID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))

	invitee, inviteeCookie := loggedInUser(t, h)
	if rec := doJSON(t, h, http.MethodPost, "/api/invites/"+acceptedID+"/accept", inviteeCookie, signedAcceptInviteRequest(t, invitee, acceptedID)); rec.Code != http.StatusOK {
		t.Fatalf("accept status = %d, body: %s", rec.Code, rec.Body.String())
	}

	sentRec := doJSON(t, h, http.MethodGet, "/api/invites/sent", creatorCookie, nil)
	if sentRec.Code != http.StatusOK {
		t.Fatalf("sent status = %d, body: %s", sentRec.Code, sentRec.Body.String())
	}
	var sent sentInvitesResponse
	if err := json.Unmarshal(sentRec.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decoding sent: %v", err)
	}
	byID := map[string]sentInviteEntry{}
	for _, e := range sent.Invites {
		byID[e.InviteID] = e
	}
	if len(byID) != 2 {
		t.Fatalf("sent invites = %d, want 2", len(byID))
	}
	if e := byID[pendingID]; e.Accepted || e.CompletionDeadline != "" || e.GroupID != groupID || e.ExpiresAt == "" {
		t.Errorf("pending entry = %+v", e)
	}
	if e := byID[acceptedID]; !e.Accepted || e.CompletionDeadline == "" {
		t.Errorf("accepted entry = %+v, want accepted with a completion deadline", e)
	}

	// The invitee sees only the invite they accepted, not the inviter's other.
	recvRec := doJSON(t, h, http.MethodGet, "/api/invites/received", inviteeCookie, nil)
	if recvRec.Code != http.StatusOK {
		t.Fatalf("received status = %d, body: %s", recvRec.Code, recvRec.Body.String())
	}
	var recv receivedInvitesResponse
	if err := json.Unmarshal(recvRec.Body.Bytes(), &recv); err != nil {
		t.Fatalf("decoding received: %v", err)
	}
	if len(recv.Invites) != 1 || recv.Invites[0].InviteID != acceptedID || recv.Invites[0].InviterUserID != creator.userID || recv.Invites[0].CompletionDeadline == "" {
		t.Fatalf("received = %+v, want exactly the accepted invite", recv.Invites)
	}

	// The inviter has accepted nothing, so their received list is empty.
	creatorRecv := doJSON(t, h, http.MethodGet, "/api/invites/received", creatorCookie, nil)
	var creatorRecvResp receivedInvitesResponse
	if err := json.Unmarshal(creatorRecv.Body.Bytes(), &creatorRecvResp); err != nil {
		t.Fatalf("decoding creator received: %v", err)
	}
	if len(creatorRecvResp.Invites) != 0 {
		t.Errorf("inviter's received = %+v, want empty", creatorRecvResp.Invites)
	}

	// Revoking the pending one removes it from the sent list.
	if rec := doJSON(t, h, http.MethodDelete, "/api/invites/"+pendingID, creatorCookie, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d, body: %s", rec.Code, rec.Body.String())
	}
	sentRec2 := doJSON(t, h, http.MethodGet, "/api/invites/sent", creatorCookie, nil)
	var sent2 sentInvitesResponse
	if err := json.Unmarshal(sentRec2.Body.Bytes(), &sent2); err != nil {
		t.Fatalf("decoding sent after revoke: %v", err)
	}
	if len(sent2.Invites) != 1 || sent2.Invites[0].InviteID != acceptedID {
		t.Errorf("sent after revoke = %+v, want only the accepted invite", sent2.Invites)
	}
}

func TestSentAndReceivedInvitesRequireSession(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	for _, path := range []string{"/api/invites/sent", "/api/invites/received"} {
		if rec := doJSON(t, h, http.MethodGet, path, nil, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s status = %d, want %d", path, rec.Code, http.StatusUnauthorized)
		}
	}
}

// setInviteDeadline rewrites an accepted invite's stored deadline on both
// rows, to simulate time passing. clearField drops CompletionDeadline to
// mimic a row written before that attribute existed (deadline then lives in
// TTL).
func setInviteDeadline(t *testing.T, inviterID, inviteID string, deadline time.Time, clearField bool) {
	t.Helper()
	ddb := rawDDB(t)
	expr := "SET CompletionDeadline = :d"
	if clearField {
		expr = "REMOVE CompletionDeadline SET #T = :d"
	}
	for _, key := range []struct{ pk, sk string }{
		{"INVITE#" + inviteID, "META"},
		{"USER#" + inviterID, "SENT#" + inviteID},
	} {
		in := &dynamodb.UpdateItemInput{
			TableName: aws.String(testTableName()),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: key.pk},
				"SK": &types.AttributeValueMemberS{Value: key.sk},
			},
			UpdateExpression: aws.String(expr),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":d": &types.AttributeValueMemberN{Value: strconv.FormatInt(deadline.Unix(), 10)},
			},
		}
		if clearField {
			in.ExpressionAttributeNames = map[string]string{"#T": "TTL"}
		}
		if _, err := ddb.UpdateItem(context.Background(), in); err != nil {
			t.Fatalf("setInviteDeadline %s: %v", key.pk, err)
		}
	}
}

// TestOverdueAcceptedInviteStaysVisibleToBothParties pins #83: an accepted
// invite whose completion deadline has passed is flagged overdue to the
// inviter and the invitee, and is still listed, not swept or hidden.
func TestOverdueAcceptedInviteStaysVisibleToBothParties(t *testing.T) {
	for _, tc := range []struct {
		name        string
		clearField  bool
		wantOverdue bool
		deadline    time.Duration
	}{
		{"fresh", false, false, 24 * time.Hour},
		{"overdue", false, true, -24 * time.Hour},
		{"overdue legacy row with deadline only in TTL", true, true, -24 * time.Hour},
		{"not-yet-due legacy row with deadline only in TTL", true, false, 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := New(config.FromEnv(), testDB(t))
			creator, creatorCookie := loggedInUser(t, h)
			groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
			inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))
			invitee, inviteeCookie := loggedInUser(t, h)
			if rec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", inviteeCookie, signedAcceptInviteRequest(t, invitee, inviteID)); rec.Code != http.StatusOK {
				t.Fatalf("accept status = %d, body: %s", rec.Code, rec.Body.String())
			}
			setInviteDeadline(t, creator.userID, inviteID, time.Now().Add(tc.deadline), tc.clearField)

			var sent sentInvitesResponse
			rec := doJSON(t, h, http.MethodGet, "/api/invites/sent", creatorCookie, nil)
			if err := json.Unmarshal(rec.Body.Bytes(), &sent); err != nil || len(sent.Invites) != 1 {
				t.Fatalf("sent = %s (err %v), want exactly the accepted invite", rec.Body.String(), err)
			}
			if e := sent.Invites[0]; !e.Accepted || e.Overdue != tc.wantOverdue || e.RemovalDate == "" {
				t.Errorf("sent entry = %+v, want accepted, overdue=%v, removalDate set", e, tc.wantOverdue)
			}

			var recv receivedInvitesResponse
			rec = doJSON(t, h, http.MethodGet, "/api/invites/received", inviteeCookie, nil)
			if err := json.Unmarshal(rec.Body.Bytes(), &recv); err != nil || len(recv.Invites) != 1 {
				t.Fatalf("received = %s (err %v), want exactly the accepted invite", rec.Body.String(), err)
			}
			if e := recv.Invites[0]; e.Overdue != tc.wantOverdue || e.RemovalDate == "" {
				t.Errorf("received entry = %+v, want overdue=%v, removalDate set", e, tc.wantOverdue)
			}
		})
	}
}
