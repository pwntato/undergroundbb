package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// Join requests (#72). Every test builds its own users and group (unique ids), so none depends on
// what another left in the table.

func signedJoinRequest(t *testing.T, user registeredUser, groupID, requestID string) createJoinRequestRequest {
	t.Helper()
	payload := crypto.JoinRequestPayload(requestID, groupID, user.signPub, user.wrapPub)
	sig, err := crypto.Sign(user.signPriv, crypto.ContextJoinRequest, payload)
	if err != nil {
		t.Fatalf("sign join request: %v", err)
	}
	return createJoinRequestRequest{RequestID: requestID, Signature: base64.StdEncoding.EncodeToString(sig)}
}

func newRequestID(t *testing.T) string {
	t.Helper()
	id, err := idgen.UUID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// requestToJoin has user ask to join groupID and fails the test unless it is accepted.
func requestToJoin(t *testing.T, h *Handler, user registeredUser, cookie *http.Cookie, groupID string) string {
	t.Helper()
	id := newRequestID(t)
	rec := doJSON(t, h, http.MethodPost, "/api/groups/"+groupID+"/join-requests", cookie, signedJoinRequest(t, user, groupID, id))
	if rec.Code != http.StatusCreated {
		t.Fatalf("request to join: %d %s", rec.Code, rec.Body.String())
	}
	return id
}

func approveBodyFor(t *testing.T, h *Handler, approver registeredUser, groupID, requestID string, requester registeredUser) approveJoinRequestRequest {
	t.Helper()
	return approveJoinRequestRequest{
		RequestID:       requestID,
		WrappedGroupKey: wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		Generation:      0,
		Admission:       signedAdmission(t, h, approver, groupID, requestID, requester),
	}
}

func joinPath(groupID, rest string) string {
	return "/api/groups/" + groupID + "/join-requests" + rest
}

// setRequestRow rewrites fields of a request row directly, to put it in a state the API alone
// cannot (an expired TTL that DynamoDB has not swept yet).
func setRequestTTL(t *testing.T, groupID, userID string, ttl int64) {
	t.Helper()
	_, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID},
			"SK": &types.AttributeValueMemberS{Value: "REQ#" + userID},
		},
		UpdateExpression:         aws.String("SET #t = :t"),
		ExpressionAttributeNames: map[string]string{"#t": "TTL"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":t": &types.AttributeValueMemberN{Value: strconv.FormatInt(ttl, 10)},
		},
		ConditionExpression: aws.String("attribute_exists(PK)"),
	})
	if err != nil {
		t.Fatalf("setRequestTTL: %v", err)
	}
}

type joinFixture struct {
	h            *Handler
	admin        registeredUser
	adminCookie  *http.Cookie
	groupID      string
	requester    registeredUser
	requesterCkE *http.Cookie
}

func newJoinFixture(t *testing.T) joinFixture {
	t.Helper()
	h := New(config.FromEnv(), testDB(t))
	admin, adminCookie := loggedInUser(t, h)
	groupID := createPublicGroup(t, h, admin, adminCookie)
	requester, requesterCookie := loggedInUser(t, h)
	return joinFixture{h: h, admin: admin, adminCookie: adminCookie, groupID: groupID, requester: requester, requesterCkE: requesterCookie}
}

func TestCreateJoinRequestStoresPendingRowWithTheRequestersKeys(t *testing.T) {
	f := newJoinFixture(t)
	id := requestToJoin(t, f.h, f.requester, f.requesterCkE, f.groupID)

	jr, err := f.h.db.GetJoinRequest(t.Context(), f.groupID, f.requester.userID, time.Now())
	if err != nil || jr == nil {
		t.Fatalf("GetJoinRequest = %v, %v", jr, err)
	}
	if jr.Status != models.JoinRequestPending || jr.RequestID != id || jr.RequesterUserID != f.requester.userID {
		t.Errorf("row = %+v", jr)
	}
	if string(jr.Ed25519PublicKey) != string(f.requester.signPub) || string(jr.X25519PublicKey) != string(f.requester.wrapPub) {
		t.Error("the row holds keys other than the requester's own")
	}
	if jr.GSI1PK != "USER#"+f.requester.userID || !strings.HasPrefix(jr.GSI1SK, "REQ#"+time.Now().UTC().Format("2006-01-02")+"#") {
		t.Errorf("GSI1 entry = %q / %q, want USER#<requester> / REQ#<day>#<rand>", jr.GSI1PK, jr.GSI1SK)
	}
	// Pending lives about 90 days, rounded to the end of a UTC day.
	ttl := time.Unix(jr.TTL, 0).UTC()
	if d := time.Until(ttl); d < 89*24*time.Hour || d > 91*24*time.Hour || ttl.Format("15:04:05") != "23:59:59" {
		t.Errorf("TTL = %v", ttl)
	}
}

func TestCreateJoinRequestRefusals(t *testing.T) {
	f := newJoinFixture(t)
	private := createTestGroupWithMembers(t, f.h, f.admin, f.adminCookie)

	t.Run("a private group answers like a missing one", func(t *testing.T) {
		id := newRequestID(t)
		for _, gid := range []string{private, newRequestID(t)} {
			rec := doJSON(t, f.h, http.MethodPost, joinPath(gid, ""), f.requesterCkE, signedJoinRequest(t, f.requester, gid, id))
			if rec.Code != http.StatusNotFound {
				t.Errorf("group %s: status = %d, want 404, body %s", gid, rec.Code, rec.Body.String())
			}
		}
	})
	t.Run("not signed in", func(t *testing.T) {
		rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, ""), nil, signedJoinRequest(t, f.requester, f.groupID, newRequestID(t)))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
	t.Run("a signature over another group, request id or key", func(t *testing.T) {
		id := newRequestID(t)
		other, _ := loggedInUser(t, f.h)
		bad := map[string]createJoinRequestRequest{
			"other group":      signedJoinRequest(t, f.requester, newRequestID(t), id),
			"other request id": {RequestID: id, Signature: signedJoinRequest(t, f.requester, f.groupID, newRequestID(t)).Signature},
			"another user":     signedJoinRequest(t, other, f.groupID, id),
		}
		for name, body := range bad {
			rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, ""), f.requesterCkE, body)
			if rec.Code != http.StatusBadRequest || errCode(t, rec) != "bad_signature" {
				t.Errorf("%s: %d %s, want 400 bad_signature", name, rec.Code, rec.Body.String())
			}
		}
	})
	t.Run("malformed fields", func(t *testing.T) {
		good := signedJoinRequest(t, f.requester, f.groupID, newRequestID(t))
		for name, body := range map[string]createJoinRequestRequest{
			"request id not a uuid": {RequestID: "nope", Signature: good.Signature},
			"signature not base64":  {RequestID: good.RequestID, Signature: "***"},
			"signature wrong size":  {RequestID: good.RequestID, Signature: base64.StdEncoding.EncodeToString([]byte("short"))},
		} {
			if rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, ""), f.requesterCkE, body); rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", name, rec.Code)
			}
		}
		if rec := doJSON(t, f.h, http.MethodPost, joinPath("not-a-uuid", ""), f.requesterCkE, good); rec.Code != http.StatusBadRequest {
			t.Errorf("bad group id: status = %d, want 400", rec.Code)
		}
	})
	t.Run("a member cannot ask to join", func(t *testing.T) {
		rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, ""), f.adminCookie, signedJoinRequest(t, f.admin, f.groupID, newRequestID(t)))
		if rec.Code != http.StatusConflict || errCode(t, rec) != "already_member" {
			t.Errorf("%d %s, want 409 already_member", rec.Code, rec.Body.String())
		}
	})
	t.Run("nothing was written by any refusal", func(t *testing.T) {
		if jr, err := f.h.db.GetJoinRequest(t.Context(), f.groupID, f.requester.userID, time.Now()); err != nil || jr != nil {
			t.Errorf("a refused request left a row: %v, %v", jr, err)
		}
	})
}

func TestCreateJoinRequestOneSlotPerUserAndTheCoolOffFreesIt(t *testing.T) {
	f := newJoinFixture(t)
	requestToJoin(t, f.h, f.requester, f.requesterCkE, f.groupID)

	rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, ""), f.requesterCkE, signedJoinRequest(t, f.requester, f.groupID, newRequestID(t)))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "request_pending" {
		t.Fatalf("second request: %d %s, want 409 request_pending", rec.Code, rec.Body.String())
	}

	if rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+f.requester.userID+"/deny"), f.adminCookie, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, ""), f.requesterCkE, signedJoinRequest(t, f.requester, f.groupID, newRequestID(t)))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "request_cooling_off" {
		t.Fatalf("request while cooling off: %d %s, want 409 request_cooling_off", rec.Code, rec.Body.String())
	}
	jr, _ := f.h.db.GetJoinRequest(t.Context(), f.groupID, f.requester.userID, time.Now())
	if !strings.Contains(rec.Body.String(), retryAfterDay(jr)) {
		t.Errorf("the refusal does not name the day the cool-off ends (%s): %s", retryAfterDay(jr), rec.Body.String())
	}

	// DynamoDB deletes expired rows late. A denied row whose TTL has passed must not block a new request.
	setRequestTTL(t, f.groupID, f.requester.userID, time.Now().Add(-time.Hour).Unix())
	id := requestToJoin(t, f.h, f.requester, f.requesterCkE, f.groupID)
	jr, _ = f.h.db.GetJoinRequest(t.Context(), f.groupID, f.requester.userID, time.Now())
	if jr == nil || jr.Status != models.JoinRequestPending || jr.RequestID != id {
		t.Errorf("after the cool-off the slot holds %+v, want the new pending request %s", jr, id)
	}
}

func TestDenyJoinRequestKeepsADeniedRowWithACoolOffTTL(t *testing.T) {
	f := newJoinFixture(t)
	requestToJoin(t, f.h, f.requester, f.requesterCkE, f.groupID)
	if rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+f.requester.userID+"/deny"), f.adminCookie, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body.String())
	}
	jr, err := f.h.db.GetJoinRequest(t.Context(), f.groupID, f.requester.userID, time.Now())
	if err != nil || jr == nil {
		t.Fatalf("a denied request vanished: %v, %v", jr, err)
	}
	if jr.Status != models.JoinRequestDenied {
		t.Errorf("status = %q, want denied", jr.Status)
	}
	ttl := time.Unix(jr.TTL, 0).UTC()
	if d := time.Until(ttl); d < 6*24*time.Hour || d > 8*24*time.Hour || ttl.Format("15:04:05") != "23:59:59" {
		t.Errorf("cool-off TTL = %v, want about 7 days out at the end of a UTC day", ttl)
	}
	// A denied request is no longer in the admin queue, and cannot be denied or approved again.
	list := doJSON(t, f.h, http.MethodGet, joinPath(f.groupID, ""), f.adminCookie, nil)
	if strings.Contains(list.Body.String(), f.requester.userID) {
		t.Errorf("the queue still lists a denied request: %s", list.Body.String())
	}
	if rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+f.requester.userID+"/deny"), f.adminCookie, nil); rec.Code != http.StatusNotFound {
		t.Errorf("denying twice: %d, want 404", rec.Code)
	}
	rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+f.requester.userID+"/approve"), f.adminCookie,
		approveBodyFor(t, f.h, f.admin, f.groupID, jr.RequestID, f.requester))
	if rec.Code != http.StatusNotFound {
		t.Errorf("approving a denied request: %d %s, want 404", rec.Code, rec.Body.String())
	}
	if m, _ := f.h.db.GetMembership(t.Context(), f.groupID, f.requester.userID); m != nil {
		t.Error("a denied request produced a membership")
	}
}

func TestOnlyAnAdminOrAmbassadorCanListAndDecide(t *testing.T) {
	f := newJoinFixture(t)
	requestToJoin(t, f.h, f.requester, f.requesterCkE, f.groupID)
	bystander, bystanderCookie := loggedInUser(t, f.h)

	for name, cookie := range map[string]*http.Cookie{"requester": f.requesterCkE, "stranger": bystanderCookie, "signed out": nil} {
		want := http.StatusForbidden
		if cookie == nil {
			want = http.StatusUnauthorized
		}
		for what, rec := range map[string]*httptest.ResponseRecorder{
			"list":    doJSON(t, f.h, http.MethodGet, joinPath(f.groupID, ""), cookie, nil),
			"deny":    doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+f.requester.userID+"/deny"), cookie, nil),
			"approve": doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+f.requester.userID+"/approve"), cookie, approveBodyFor(t, f.h, f.admin, f.groupID, newRequestID(t), f.requester)),
		} {
			if rec.Code != want {
				t.Errorf("%s %s: status = %d, want %d", name, what, rec.Code, want)
			}
		}
	}
	_ = bystander
	if jr, _ := f.h.db.GetJoinRequest(t.Context(), f.groupID, f.requester.userID, time.Now()); jr == nil || jr.Status != models.JoinRequestPending {
		t.Errorf("a refused decision changed the request: %+v", jr)
	}

	// A plain member is not enough either; an ambassador is.
	member, memberCookie := loggedInUser(t, f.h)
	addMember(t, f.groupID, member, models.RoleMember)
	if rec := doJSON(t, f.h, http.MethodGet, joinPath(f.groupID, ""), memberCookie, nil); rec.Code != http.StatusForbidden {
		t.Errorf("a plain member listing the queue: %d, want 403", rec.Code)
	}
	setMembershipRole(t, f.groupID, member.userID, models.RoleAmbassador)
	rec := doJSON(t, f.h, http.MethodGet, joinPath(f.groupID, ""), memberCookie, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), f.requester.userID) {
		t.Errorf("an ambassador listing the queue: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+f.requester.userID+"/deny"), memberCookie, nil); rec.Code != http.StatusNoContent {
		t.Errorf("an ambassador denying: %d %s", rec.Code, rec.Body.String())
	}
}

func TestListJoinRequestsReturnsPendingRequestsWithTheirSignedKeys(t *testing.T) {
	f := newJoinFixture(t)
	id := requestToJoin(t, f.h, f.requester, f.requesterCkE, f.groupID)
	denied, deniedCookie := loggedInUser(t, f.h)
	requestToJoin(t, f.h, denied, deniedCookie, f.groupID)
	if rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+denied.userID+"/deny"), f.adminCookie, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("deny: %d", rec.Code)
	}
	expired, expiredCookie := loggedInUser(t, f.h)
	requestToJoin(t, f.h, expired, expiredCookie, f.groupID)
	setRequestTTL(t, f.groupID, expired.userID, time.Now().Add(-time.Minute).Unix())

	rec := doJSON(t, f.h, http.MethodGet, joinPath(f.groupID, ""), f.adminCookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var resp listJoinRequestsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Requests) != 1 {
		t.Fatalf("queue = %+v, want only the one pending, unexpired request (not the denied or the expired)", resp.Requests)
	}
	e := resp.Requests[0]
	if e.UserID != f.requester.userID || e.RequestID != id {
		t.Errorf("entry = %+v", e)
	}
	if e.Ed25519PublicKey != base64.StdEncoding.EncodeToString(f.requester.signPub) || e.X25519PublicKey != base64.StdEncoding.EncodeToString(f.requester.wrapPub) {
		t.Errorf("the entry does not carry the requester's signed keys: %+v", e)
	}
	// The approver's client verifies this itself.
	sig, _ := base64.StdEncoding.DecodeString(e.Signature)
	if !crypto.Verify(f.requester.signPub, crypto.ContextJoinRequest, crypto.JoinRequestPayload(e.RequestID, f.groupID, f.requester.signPub, f.requester.wrapPub), sig) {
		t.Error("the listed signature does not verify against the listed request id, group and keys")
	}
	if e.Day != time.Now().UTC().Format("2006-01-02") {
		t.Errorf("day = %q", e.Day)
	}
}

func TestListJoinRequestsPages(t *testing.T) {
	f := newJoinFixture(t)
	want := map[string]bool{}
	for i := 0; i < 5; i++ {
		u, c := loggedInUser(t, f.h)
		requestToJoin(t, f.h, u, c, f.groupID)
		want[u.userID] = true
	}
	// Two denied rows between pending ones: a filtered read must still return full pages.
	for i := 0; i < 2; i++ {
		u, c := loggedInUser(t, f.h)
		requestToJoin(t, f.h, u, c, f.groupID)
		doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+u.userID+"/deny"), f.adminCookie, nil)
	}
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 10; page++ {
		path := joinPath(f.groupID, "?limit=2")
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		rec := doJSON(t, f.h, http.MethodGet, path, f.adminCookie, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("page %d: %d %s", page, rec.Code, rec.Body.String())
		}
		var resp listJoinRequestsResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if len(resp.Requests) > 2 {
			t.Fatalf("page %d has %d entries, limit was 2", page, len(resp.Requests))
		}
		for _, e := range resp.Requests {
			if seen[e.UserID] {
				t.Fatalf("%s listed twice", e.UserID)
			}
			seen[e.UserID] = true
		}
		if resp.NextCursor == "" {
			break
		}
		cursor = resp.NextCursor
	}
	if len(seen) != len(want) {
		t.Errorf("paging returned %d requests, want %d", len(seen), len(want))
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("request %s never listed", id)
		}
	}

	for name, q := range map[string]string{"limit 0": "?limit=0", "limit too big": "?limit=101", "limit not a number": "?limit=x", "cursor not issued": "?cursor=abc"} {
		if rec := doJSON(t, f.h, http.MethodGet, joinPath(f.groupID, q), f.adminCookie, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}
}

func TestMyJoinRequestsAndWithdraw(t *testing.T) {
	f := newJoinFixture(t)
	id := requestToJoin(t, f.h, f.requester, f.requesterCkE, f.groupID)

	rec := doJSON(t, f.h, http.MethodGet, "/api/join-requests", f.requesterCkE, nil)
	var mine struct {
		Requests []myJoinRequestEntry `json:"requests"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &mine); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("my requests: %d %s", rec.Code, rec.Body.String())
	}
	if len(mine.Requests) != 1 || mine.Requests[0].GroupID != f.groupID || mine.Requests[0].RequestID != id ||
		mine.Requests[0].Status != "pending" || mine.Requests[0].GroupName != "Book Club" || mine.Requests[0].RetryAfter != "" {
		t.Errorf("my requests = %+v", mine.Requests)
	}
	// Nobody else sees them.
	other, otherCookie := loggedInUser(t, f.h)
	_ = other
	rec = doJSON(t, f.h, http.MethodGet, "/api/join-requests", otherCookie, nil)
	if !strings.Contains(rec.Body.String(), `"requests":[]`) {
		t.Errorf("another user's list = %s, want empty", rec.Body.String())
	}

	if rec := doJSON(t, f.h, http.MethodDelete, joinPath(f.groupID, "/mine"), f.requesterCkE, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("withdraw: %d %s", rec.Code, rec.Body.String())
	}
	if jr, _ := f.h.db.GetJoinRequest(t.Context(), f.groupID, f.requester.userID, time.Now()); jr != nil {
		t.Error("the row survived a withdrawal")
	}
	if rec := doJSON(t, f.h, http.MethodDelete, joinPath(f.groupID, "/mine"), f.requesterCkE, nil); rec.Code != http.StatusNotFound {
		t.Errorf("withdrawing nothing: %d, want 404", rec.Code)
	}
	// The slot is free again at once.
	requestToJoin(t, f.h, f.requester, f.requesterCkE, f.groupID)

	// A denied request shows its retry day and cannot be withdrawn to skip the cool-off.
	doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+f.requester.userID+"/deny"), f.adminCookie, nil)
	rec = doJSON(t, f.h, http.MethodGet, "/api/join-requests", f.requesterCkE, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &mine)
	if len(mine.Requests) != 1 || mine.Requests[0].Status != "denied" || mine.Requests[0].RetryAfter == "" {
		t.Errorf("a denied request lists as %+v, want status denied with a retryAfter day", mine.Requests)
	}
	rec = doJSON(t, f.h, http.MethodDelete, joinPath(f.groupID, "/mine"), f.requesterCkE, nil)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "request_denied" {
		t.Errorf("withdrawing a denied request: %d %s, want 409 request_denied", rec.Code, rec.Body.String())
	}
	if jr, _ := f.h.db.GetJoinRequest(t.Context(), f.groupID, f.requester.userID, time.Now()); jr == nil || jr.Status != models.JoinRequestDenied {
		t.Errorf("the denied row after a refused withdrawal = %+v", jr)
	}
}

func TestApproveJoinRequestAdmitsTheRequesterAndStoresTheAdmission(t *testing.T) {
	f := newJoinFixture(t)
	id := requestToJoin(t, f.h, f.requester, f.requesterCkE, f.groupID)

	body := approveBodyFor(t, f.h, f.admin, f.groupID, id, f.requester)
	rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+f.requester.userID+"/approve"), f.adminCookie, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}

	m, err := f.h.db.GetMembership(t.Context(), f.groupID, f.requester.userID)
	if err != nil || m == nil {
		t.Fatalf("no membership after approval: %v, %v", m, err)
	}
	if m.Role != models.RoleMember || m.Generation != 0 {
		t.Errorf("membership = role %q generation %d", m.Role, m.Generation)
	}
	if got := base64.StdEncoding.EncodeToString(m.WrappedGroupKey.Ciphertext); got != body.WrappedGroupKey.Ciphertext {
		t.Errorf("the stored wrap is not the one the approver sent")
	}
	if jr, _ := f.h.db.GetJoinRequest(t.Context(), f.groupID, f.requester.userID, time.Now()); jr != nil {
		t.Error("the request row survived its approval")
	}
	// The approver's signed record lists the requester, with the REQUEST id in the invite slot.
	lr := doJSON(t, f.h, http.MethodGet, "/api/groups/"+f.groupID+"/admissions", f.requesterCkE, nil)
	if lr.Code != http.StatusOK || !strings.Contains(lr.Body.String(), f.requester.userID) || !strings.Contains(lr.Body.String(), id) {
		t.Errorf("admissions = %d %s, want a record for the requester citing request %s", lr.Code, lr.Body.String(), id)
	}
	// The approved user is now in the group's own listing.
	if rec := doJSON(t, f.h, http.MethodGet, "/api/groups/"+f.groupID, f.requesterCkE, nil); rec.Code != http.StatusOK {
		t.Errorf("the new member cannot read the group: %d %s", rec.Code, rec.Body.String())
	}
	// And the request cannot be approved twice.
	rec = doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+f.requester.userID+"/approve"), f.adminCookie, body)
	if rec.Code != http.StatusNotFound {
		t.Errorf("approving again: %d %s, want 404", rec.Code, rec.Body.String())
	}
}

func TestApproveJoinRequestRefusals(t *testing.T) {
	f := newJoinFixture(t)
	id := requestToJoin(t, f.h, f.requester, f.requesterCkE, f.groupID)
	path := joinPath(f.groupID, "/"+f.requester.userID+"/approve")
	assertStillPending := func(t *testing.T) {
		t.Helper()
		if m, _ := f.h.db.GetMembership(t.Context(), f.groupID, f.requester.userID); m != nil {
			t.Fatal("a refused approval produced a membership")
		}
	}

	t.Run("a request id other than the one the approver verified", func(t *testing.T) {
		body := approveBodyFor(t, f.h, f.admin, f.groupID, newRequestID(t), f.requester)
		rec := doJSON(t, f.h, http.MethodPost, path, f.adminCookie, body)
		if rec.Code != http.StatusConflict || errCode(t, rec) != "request_changed" {
			t.Errorf("%d %s, want 409 request_changed", rec.Code, rec.Body.String())
		}
		assertStillPending(t)
	})
	t.Run("no admission record", func(t *testing.T) {
		body := approveBodyFor(t, f.h, f.admin, f.groupID, id, f.requester)
		body.Admission = nil
		rec := doJSON(t, f.h, http.MethodPost, path, f.adminCookie, body)
		if rec.Code != http.StatusBadRequest || errCode(t, rec) != "admission_required" {
			t.Errorf("%d %s, want 400 admission_required", rec.Code, rec.Body.String())
		}
	})
	t.Run("an admission signed for other keys than the ones requested", func(t *testing.T) {
		other, _ := loggedInUser(t, f.h)
		body := approveBodyFor(t, f.h, f.admin, f.groupID, id, f.requester)
		body.Admission = signedAdmission(t, f.h, f.admin, f.groupID, id, other)
		rec := doJSON(t, f.h, http.MethodPost, path, f.adminCookie, body)
		if rec.Code != http.StatusBadRequest || errCode(t, rec) != "bad_signature" {
			t.Errorf("%d %s, want 400 bad_signature", rec.Code, rec.Body.String())
		}
		assertStillPending(t)
	})
	t.Run("an admission signed under someone else's key", func(t *testing.T) {
		body := approveBodyFor(t, f.h, f.admin, f.groupID, id, f.requester)
		payload := crypto.AdmissionPayload(f.groupID, f.admin.userID, f.requester.userID, f.requester.signPub, f.requester.wrapPub,
			id, body.Admission.InviterGrantRef, body.Admission.Day, 0)
		forged, err := crypto.Sign(f.requester.signPriv, crypto.ContextAdmission, payload)
		if err != nil {
			t.Fatal(err)
		}
		body.Admission.Signature = base64.StdEncoding.EncodeToString(forged)
		rec := doJSON(t, f.h, http.MethodPost, path, f.adminCookie, body)
		if rec.Code != http.StatusBadRequest || errCode(t, rec) != "bad_signature" {
			t.Errorf("%d %s, want 400 bad_signature", rec.Code, rec.Body.String())
		}
		assertStillPending(t)
	})
	t.Run("a stale grant reference", func(t *testing.T) {
		body := approveBodyFor(t, f.h, f.admin, f.groupID, id, f.requester)
		body.Admission = signedAdmissionWith(t, f.h, f.admin, f.groupID, id, f.requester, "GRANT#"+f.admin.userID+"#2000-01-01#00000000000000000000000000000000", time.Now().UTC().Format("2006-01-02"))
		rec := doJSON(t, f.h, http.MethodPost, path, f.adminCookie, body)
		if rec.Code != http.StatusConflict || errCode(t, rec) != "grantor_ref_stale" {
			t.Errorf("%d %s, want 409 grantor_ref_stale", rec.Code, rec.Body.String())
		}
	})
	t.Run("a day outside the clock tolerance", func(t *testing.T) {
		body := approveBodyFor(t, f.h, f.admin, f.groupID, id, f.requester)
		body.Admission = signedAdmissionWith(t, f.h, f.admin, f.groupID, id, f.requester, "", time.Now().UTC().AddDate(0, 0, -5).Format("2006-01-02"))
		rec := doJSON(t, f.h, http.MethodPost, path, f.adminCookie, body)
		if rec.Code != http.StatusBadRequest || errCode(t, rec) != "clock_skew" {
			t.Errorf("%d %s, want 400 clock_skew", rec.Code, rec.Body.String())
		}
	})
	t.Run("a generation that is not the approver's", func(t *testing.T) {
		body := approveBodyFor(t, f.h, f.admin, f.groupID, id, f.requester)
		body.Generation = 3
		if rec := doJSON(t, f.h, http.MethodPost, path, f.adminCookie, body); rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
	t.Run("a malformed wrap", func(t *testing.T) {
		body := approveBodyFor(t, f.h, f.admin, f.groupID, id, f.requester)
		body.WrappedGroupKey = wrappedKey{}
		if rec := doJSON(t, f.h, http.MethodPost, path, f.adminCookie, body); rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
	t.Run("an expired request that has not been swept yet", func(t *testing.T) {
		setRequestTTL(t, f.groupID, f.requester.userID, time.Now().Add(-time.Minute).Unix())
		rec := doJSON(t, f.h, http.MethodPost, path, f.adminCookie, approveBodyFor(t, f.h, f.admin, f.groupID, id, f.requester))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%d %s, want 404", rec.Code, rec.Body.String())
		}
		assertStillPending(t)
	})
}

func TestApproveJoinRequestWhenTheRequesterRotatedTheirKeysClearsTheRequest(t *testing.T) {
	f := newJoinFixture(t)
	id := requestToJoin(t, f.h, f.requester, f.requesterCkE, f.groupID)
	// The requester's keys change after they asked (#62): the wrap would be dormant on arrival.
	newPub := make([]byte, 32)
	newPub[0] = 0x77
	_, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + f.requester.userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		UpdateExpression:          aws.String("SET WrappingPublicKey = :k"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":k": &types.AttributeValueMemberB{Value: newPub}},
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+f.requester.userID+"/approve"), f.adminCookie,
		approveBodyFor(t, f.h, f.admin, f.groupID, id, f.requester))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "requester_keys_changed" {
		t.Fatalf("%d %s, want 409 requester_keys_changed", rec.Code, rec.Body.String())
	}
	if m, _ := f.h.db.GetMembership(t.Context(), f.groupID, f.requester.userID); m != nil {
		t.Error("the requester was admitted on keys they no longer hold")
	}
	if jr, _ := f.h.db.GetJoinRequest(t.Context(), f.groupID, f.requester.userID, time.Now()); jr != nil {
		t.Error("the unusable request was left in the queue")
	}
}

func TestApproveJoinRequestForAnExistingMemberClearsTheRequest(t *testing.T) {
	f := newJoinFixture(t)
	id := requestToJoin(t, f.h, f.requester, f.requesterCkE, f.groupID)
	// They join some other way between asking and approval.
	addMember(t, f.groupID, f.requester, models.RoleMember)
	rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+f.requester.userID+"/approve"), f.adminCookie,
		approveBodyFor(t, f.h, f.admin, f.groupID, id, f.requester))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "already_member" {
		t.Fatalf("%d %s, want 409 already_member", rec.Code, rec.Body.String())
	}
	if jr, _ := f.h.db.GetJoinRequest(t.Context(), f.groupID, f.requester.userID, time.Now()); jr != nil {
		t.Error("a request from a member was left in the queue")
	}
}

func TestApproveJoinRequestRefusesAnApproverDemotedAfterTheRead(t *testing.T) {
	f := newJoinFixture(t)
	id := requestToJoin(t, f.h, f.requester, f.requesterCkE, f.groupID)
	member, memberCookie := loggedInUser(t, f.h)
	addMember(t, f.groupID, member, models.RoleAmbassador)
	body := approveBodyFor(t, f.h, member, f.groupID, id, f.requester)
	setMembershipRole(t, f.groupID, member.userID, models.RoleMember)
	rec := doJSON(t, f.h, http.MethodPost, joinPath(f.groupID, "/"+f.requester.userID+"/approve"), memberCookie, body)
	if rec.Code != http.StatusForbidden {
		t.Errorf("a demoted approver: %d %s, want 403", rec.Code, rec.Body.String())
	}
	if m, _ := f.h.db.GetMembership(t.Context(), f.groupID, f.requester.userID); m != nil {
		t.Error("a demoted approver admitted someone")
	}
}
