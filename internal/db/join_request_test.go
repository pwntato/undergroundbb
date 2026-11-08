package db

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// Join requests (#72). Every test makes its own group and users with fresh ids and cleans up.

func putPublicGroup(t *testing.T, c *Client) string {
	t.Helper()
	gid := newUserID(t)
	putRaw(t, c, map[string]types.AttributeValue{
		"PK": s("GROUP#" + gid), "SK": s("META"), "Type": s("Group"), "Visibility": s(models.VisibilityPublic),
	})
	t.Cleanup(func() { removePartitions(t, c, "GROUP#"+gid) })
	return gid
}

func requesterOf(t *testing.T, c *Client) RegisterInput {
	t.Helper()
	return registerAccount(t, c, false)
}

func createReq(c *Client, gid string, user RegisterInput, requestID string) error {
	return c.CreateJoinRequest(context.Background(), CreateJoinRequestInput{
		GroupID: gid, RequesterUserID: user.UserID, RequestID: requestID,
		Ed25519PublicKey: user.SigningPublicKey, X25519PublicKey: user.WrappingPublicKey,
		Signature: make([]byte, 64), RequesterKeyEpoch: 0,
	})
}

func TestCreateJoinRequestChecksGroupMembershipAndAccount(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	user := requesterOf(t, c)

	private := newUserID(t)
	putGroupMeta(t, c, private) // no Visibility: not public
	t.Cleanup(func() { removePartitions(t, c, "GROUP#"+private) })
	if err := createReq(c, private, user, newUserID(t)); !errors.Is(err, ErrNotPublicGroup) {
		t.Errorf("private group: %v, want ErrNotPublicGroup", err)
	}
	if err := createReq(c, newUserID(t), user, newUserID(t)); !errors.Is(err, ErrNotPublicGroup) {
		t.Errorf("missing group: %v, want ErrNotPublicGroup", err)
	}

	gid := putPublicGroup(t, c)
	putTestMember(t, c, gid, user.UserID, models.RoleMember)
	if err := createReq(c, gid, user, newUserID(t)); !errors.Is(err, ErrAlreadyMember) {
		t.Errorf("a member: %v, want ErrAlreadyMember", err)
	}

	gid2 := putPublicGroup(t, c)
	stale := user
	err := c.CreateJoinRequest(ctx, CreateJoinRequestInput{
		GroupID: gid2, RequesterUserID: stale.UserID, RequestID: newUserID(t),
		Ed25519PublicKey: stale.SigningPublicKey, X25519PublicKey: stale.WrappingPublicKey,
		Signature: make([]byte, 64), RequesterKeyEpoch: 7,
	})
	if !errors.Is(err, ErrWrapEpochStale) {
		t.Errorf("keys read at an epoch that has moved: %v, want ErrWrapEpochStale", err)
	}

	gone := requesterOf(t, c)
	if err := c.DeleteAccount(ctx, gone.UserID); err != nil {
		t.Fatal(err)
	}
	if err := createReq(c, gid2, gone, newUserID(t)); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("a deleted account: %v, want ErrUserNotFound", err)
	}
	for _, g := range []string{private, gid2} {
		if itemExists(t, c, "GROUP#"+g, "REQ#"+user.UserID) || itemExists(t, c, "GROUP#"+g, "REQ#"+gone.UserID) {
			t.Errorf("a refused request left a row in %s", g)
		}
	}
}

func TestCreateJoinRequestConcurrentCallsLeaveExactlyOne(t *testing.T) {
	c := testClient(t)
	gid := putPublicGroup(t, c)
	user := requesterOf(t, c)

	const n = 8
	var wg sync.WaitGroup
	results := make([]error, n)
	ids := make([]string, n)
	for i := range results {
		ids[i] = newUserID(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = createReq(c, gid, user, ids[i])
		}()
	}
	wg.Wait()
	won := -1
	for i, err := range results {
		switch {
		case err == nil:
			if won != -1 {
				t.Fatalf("two concurrent requests both succeeded (%d and %d)", won, i)
			}
			won = i
		case errors.Is(err, ErrJoinRequestPending), isTransactionConflict(err):
		default:
			t.Errorf("request %d: unexpected error %v", i, err)
		}
	}
	if won == -1 {
		t.Fatal("no concurrent request succeeded")
	}
	jr, err := c.GetJoinRequest(context.Background(), gid, user.UserID, time.Now())
	if err != nil || jr == nil || jr.RequestID != ids[won] {
		t.Errorf("the slot holds %+v (%v), want the winner's request %s", jr, err, ids[won])
	}
}

func TestApproveJoinRequestOnlyApprovesTheRequestTheApproverSaw(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid := putPublicGroup(t, c)
	approver := requesterOf(t, c)
	putTestMember(t, c, gid, approver.UserID, models.RoleAdmin)
	user := requesterOf(t, c)

	first, second := newUserID(t), newUserID(t)
	if err := createReq(c, gid, user, first); err != nil {
		t.Fatal(err)
	}
	// Withdrawn and asked again while the approver was looking at the first one.
	if err := c.WithdrawJoinRequest(ctx, gid, user.UserID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := createReq(c, gid, user, second); err != nil {
		t.Fatal(err)
	}

	in := ApproveJoinRequestInput{
		GroupID: gid, RequesterUserID: user.UserID, RequestID: first, ApproverUserID: approver.UserID,
		Role:            models.RoleMember,
		WrappedGroupKey: models.WrappedKey{},
		Admission:       models.Admission{InviterUserID: approver.UserID, InviteID: first},
	}
	if err := c.ApproveJoinRequest(ctx, in); !errors.Is(err, ErrJoinRequestNotFound) {
		t.Fatalf("approving the superseded request: %v, want ErrJoinRequestNotFound", err)
	}
	if itemExists(t, c, "GROUP#"+gid, "MEMBER#"+user.UserID) || itemExists(t, c, "GROUP#"+gid, "ADMISSION#"+user.UserID) {
		t.Fatal("a refused approval wrote a membership or an admission")
	}
	if jr, _ := c.GetJoinRequest(ctx, gid, user.UserID, time.Now()); jr == nil || jr.RequestID != second {
		t.Fatalf("the newer request was disturbed: %+v", jr)
	}

	in.RequestID, in.Admission.InviteID = second, second
	if err := c.ApproveJoinRequest(ctx, in); err != nil {
		t.Fatalf("approving the live request: %v", err)
	}
	if !itemExists(t, c, "GROUP#"+gid, "MEMBER#"+user.UserID) || !itemExists(t, c, "GROUP#"+gid, "ADMISSION#"+user.UserID) {
		t.Error("an approval did not write the membership and the admission")
	}
	if itemExists(t, c, "GROUP#"+gid, "REQ#"+user.UserID) {
		t.Error("an approval left the request behind")
	}
}

func TestApproveAndDenyNeedALiveAdminOrAmbassador(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid := putPublicGroup(t, c)
	member := requesterOf(t, c)
	putTestMember(t, c, gid, member.UserID, models.RoleMember)
	user := requesterOf(t, c)
	id := newUserID(t)
	if err := createReq(c, gid, user, id); err != nil {
		t.Fatal(err)
	}

	if err := c.DenyJoinRequest(ctx, gid, user.UserID, member.UserID, time.Now()); !errors.Is(err, ErrApproverNotEligible) {
		t.Errorf("a plain member denying: %v, want ErrApproverNotEligible", err)
	}
	if err := c.DenyJoinRequest(ctx, gid, user.UserID, newUserID(t), time.Now()); !errors.Is(err, ErrApproverNotEligible) {
		t.Errorf("a non-member denying: %v, want ErrApproverNotEligible", err)
	}
	err := c.ApproveJoinRequest(ctx, ApproveJoinRequestInput{
		GroupID: gid, RequesterUserID: user.UserID, RequestID: id, ApproverUserID: member.UserID,
		Role: models.RoleMember, Admission: models.Admission{InviteID: id},
	})
	if !errors.Is(err, ErrApproverNotEligible) {
		t.Errorf("a plain member approving: %v, want ErrApproverNotEligible", err)
	}
	// An admin at another generation than the wrap is refused.
	admin := requesterOf(t, c)
	putTestMember(t, c, gid, admin.UserID, models.RoleAdmin)
	err = c.ApproveJoinRequest(ctx, ApproveJoinRequestInput{
		GroupID: gid, RequesterUserID: user.UserID, RequestID: id, ApproverUserID: admin.UserID,
		Generation: 4, Role: models.RoleMember, Admission: models.Admission{InviteID: id},
	})
	if !errors.Is(err, ErrApproverNotEligible) {
		t.Errorf("an approver wrapping under the wrong generation: %v, want ErrApproverNotEligible", err)
	}
	if jr, _ := c.GetJoinRequest(ctx, gid, user.UserID, time.Now()); jr == nil || jr.Status != models.JoinRequestPending {
		t.Errorf("a refused decision changed the request: %+v", jr)
	}
	if err := c.DenyJoinRequest(ctx, gid, user.UserID, admin.UserID, time.Now()); err != nil {
		t.Errorf("an admin denying: %v", err)
	}
}

func TestExpiredJoinRequestsAreAbsent(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid := putPublicGroup(t, c)
	admin := requesterOf(t, c)
	putTestMember(t, c, gid, admin.UserID, models.RoleAdmin)
	user := requesterOf(t, c)
	id := newUserID(t)
	if err := createReq(c, gid, user, id); err != nil {
		t.Fatal(err)
	}
	_, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table), Key: map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s("REQ#" + user.UserID)},
		UpdateExpression: aws.String("SET #t = :t"), ExpressionAttributeNames: map[string]string{"#t": "TTL"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":t": &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if jr, err := c.GetJoinRequest(ctx, gid, user.UserID, now); err != nil || jr != nil {
		t.Errorf("GetJoinRequest = %v, %v, want nil", jr, err)
	}
	if rows, _, err := c.ListPendingJoinRequests(ctx, gid, now, 10, ""); err != nil || len(rows) != 0 {
		t.Errorf("ListPendingJoinRequests = %v, %v, want none", rows, err)
	}
	if rows, _, err := c.ListJoinRequestsByUser(ctx, user.UserID, now, 50, ""); err != nil || len(rows) != 0 {
		t.Errorf("ListJoinRequestsByUser = %v, %v, want none", rows, err)
	}
	if err := c.WithdrawJoinRequest(ctx, gid, user.UserID, now); !errors.Is(err, ErrJoinRequestNotFound) {
		t.Errorf("withdraw: %v, want ErrJoinRequestNotFound", err)
	}
	if err := c.DenyJoinRequest(ctx, gid, user.UserID, admin.UserID, now); !errors.Is(err, ErrJoinRequestNotFound) {
		t.Errorf("deny: %v, want ErrJoinRequestNotFound", err)
	}
	err = c.ApproveJoinRequest(ctx, ApproveJoinRequestInput{
		GroupID: gid, RequesterUserID: user.UserID, RequestID: id, ApproverUserID: admin.UserID,
		Role: models.RoleMember, Admission: models.Admission{InviteID: id},
	})
	if !errors.Is(err, ErrJoinRequestNotFound) {
		t.Errorf("approve: %v, want ErrJoinRequestNotFound", err)
	}
}

func TestDeleteAccountSweepsOnlyThatUsersJoinRequests(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g1, g2 := putPublicGroup(t, c), putPublicGroup(t, c)
	gone, kept := requesterOf(t, c), requesterOf(t, c)
	for _, g := range []string{g1, g2} {
		if err := createReq(c, g, gone, newUserID(t)); err != nil {
			t.Fatal(err)
		}
	}
	if err := createReq(c, g1, kept, newUserID(t)); err != nil {
		t.Fatal(err)
	}

	if err := c.DeleteAccount(ctx, gone.UserID); err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{g1, g2} {
		if itemExists(t, c, "GROUP#"+g, "REQ#"+gone.UserID) {
			t.Errorf("a deleted account's request survives in %s", g)
		}
	}
	if !itemExists(t, c, "GROUP#"+g1, "REQ#"+kept.UserID) {
		t.Error("deleting one account removed another user's request")
	}
}

// putManyDenied seeds n denied rows in a group's REQ# range, sorted before everything the test
// adds later, with unique sort keys and a future TTL.
func putManyDenied(t *testing.T, c *Client, gid string, n int) {
	t.Helper()
	ttl := strconv.FormatInt(time.Now().Add(48*time.Hour).Unix(), 10)
	var reqs []types.WriteRequest
	flush := func() {
		if len(reqs) == 0 {
			return
		}
		for attempt := 0; len(reqs) > 0; attempt++ {
			if attempt == 8 {
				t.Fatal("unprocessed seed items")
			}
			out, err := c.ddb.BatchWriteItem(context.Background(), &dynamodb.BatchWriteItemInput{RequestItems: map[string][]types.WriteRequest{c.table: reqs}})
			if err != nil {
				t.Fatal(err)
			}
			reqs = out.UnprocessedItems[c.table]
		}
	}
	for i := 0; i < n; i++ {
		uid := fmt.Sprintf("%08d-0000-4000-8000-000000000000", i)
		reqs = append(reqs, types.WriteRequest{PutRequest: &types.PutRequest{Item: map[string]types.AttributeValue{
			"PK": s("GROUP#" + gid), "SK": s("REQ#" + uid), "Type": s("JoinRequest"),
			"GSI1PK": s("USER#" + uid), "GSI1SK": s("REQ#2026-11-07#" + uid),
			"TTL": &types.AttributeValueMemberN{Value: ttl}, "RequestID": s(uid), "GroupID": s(gid),
			"RequesterUserID": s(uid), "Status": s(models.JoinRequestDenied),
			"Ed25519PublicKey": &types.AttributeValueMemberB{Value: make([]byte, 32)},
			"X25519PublicKey":  &types.AttributeValueMemberB{Value: make([]byte, 32)},
			"Signature":        &types.AttributeValueMemberB{Value: make([]byte, 64)},
		}}})
		if len(reqs) == 25 {
			flush()
		}
	}
	flush()
}

func putPendingRow(t *testing.T, c *Client, gid, uid string) {
	t.Helper()
	putRaw(t, c, map[string]types.AttributeValue{
		"PK": s("GROUP#" + gid), "SK": s("REQ#" + uid), "Type": s("JoinRequest"),
		"GSI1PK": s("USER#" + uid), "GSI1SK": s("REQ#2026-11-07#" + uid),
		"TTL":       &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Add(48*time.Hour).Unix(), 10)},
		"RequestID": s(uid), "GroupID": s(gid), "RequesterUserID": s(uid), "Status": s(models.JoinRequestPending),
	})
}

func pendingUID(n int) string { return fmt.Sprintf("p%07d-0000-4000-8000-000000000000", n) }

// The queue is a filtered read: denied rows still cooling off are examined and dropped. A group with
// more of them than one pass examines must still get its pending requests, and a cursor must resume
// exactly where a read stopped, whether it stopped at a full page or at the pass bound.
func TestListPendingJoinRequestsReadsPastThePageOfExaminedRows(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid := putPublicGroup(t, c)
	// Sort order is by uuid: "0000..." denied rows first, then "p..." pending ones among later denied rows.
	putManyDenied(t, c, gid, 1200) // three passes of 500 examined rows
	// Two sort ahead of every denied row ("-" sorts before "0"), three behind them.
	pending := []string{"0000000-early-1", "0000000-early-2", pendingUID(1), pendingUID(2), pendingUID(3)}
	for _, uid := range pending {
		putPendingRow(t, c, gid, uid)
	}

	t.Run("one call walks past all the denied rows", func(t *testing.T) {
		rows, next, err := c.ListPendingJoinRequests(ctx, gid, time.Now(), 10, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != len(pending) || next != "" {
			t.Fatalf("got %d rows and cursor %q, want all %d pending and no cursor", len(rows), next, len(pending))
		}
		for i, r := range rows {
			if r.RequesterUserID != pending[i] {
				t.Errorf("row %d = %s, want %s", i, r.RequesterUserID, pending[i])
			}
		}
	})

	collect := func(t *testing.T, limit int) (got []string, pages int) {
		t.Helper()
		cursor := ""
		for pages = 0; pages < 50; pages++ {
			page, next, err := c.ListPendingJoinRequests(ctx, gid, time.Now(), limit, cursor)
			if err != nil {
				t.Fatal(err)
			}
			if len(page) > limit {
				t.Fatalf("page of %d rows, limit %d", len(page), limit)
			}
			for _, r := range page {
				got = append(got, r.RequesterUserID)
			}
			if next == "" {
				return got, pages + 1
			}
			cursor = next
		}
		t.Fatal("the cursor never ended")
		return nil, 0
	}
	assertAll := func(t *testing.T, got []string) {
		t.Helper()
		if fmt.Sprint(got) != fmt.Sprint(pending) {
			t.Errorf("walking the cursors found %v, want %v exactly once each, in order", got, pending)
		}
	}

	t.Run("a page of exactly limit with rows still to read hands back a cursor", func(t *testing.T) {
		got, pages := collect(t, 2)
		assertAll(t, got)
		if pages < 3 {
			t.Errorf("a limit of 2 over 5 pending rows took %d page(s), want at least 3", pages)
		}
	})
	t.Run("hitting the pass bound hands back a cursor that resumes", func(t *testing.T) {
		old := maxJoinRequestPasses
		maxJoinRequestPasses = 1
		t.Cleanup(func() { maxJoinRequestPasses = old })
		got, pages := collect(t, 10)
		assertAll(t, got)
		if pages < 3 {
			t.Errorf("one pass per call took %d call(s) over 1205 rows, want at least 3", pages)
		}
	})
}

func TestListJoinRequestsByUserReturnsEveryGroupsRequest(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	user, other := requesterOf(t, c), requesterOf(t, c)
	var groups []string
	for i := 0; i < 3; i++ {
		g := putPublicGroup(t, c)
		groups = append(groups, g)
		if err := createReq(c, g, user, newUserID(t)); err != nil {
			t.Fatal(err)
		}
	}
	if err := createReq(c, groups[0], other, newUserID(t)); err != nil {
		t.Fatal(err)
	}
	rows, _, err := c.ListJoinRequestsByUser(ctx, user.UserID, time.Now(), 50, "")
	if err != nil || len(rows) != 3 {
		t.Fatalf("got %d rows (%v), want 3", len(rows), err)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.GroupID] = true
		if r.RequesterUserID != user.UserID {
			t.Errorf("another user's request in the list: %+v", r)
		}
	}
	for _, g := range groups {
		if !seen[g] {
			t.Errorf("group %s missing", g)
		}
	}
}

// The wrap goes to the requester's keys as read; if their epoch moved since, the membership would be
// dormant on arrival, so the transaction refuses even when the keys in the request row still look right.
func TestApproveJoinRequestRefusesWhenTheRequestersKeyEpochMoved(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid := putPublicGroup(t, c)
	approver := requesterOf(t, c)
	putTestMember(t, c, gid, approver.UserID, models.RoleAdmin)
	user := requesterOf(t, c)
	id := newUserID(t)
	if err := createReq(c, gid, user, id); err != nil {
		t.Fatal(err)
	}
	err := c.ApproveJoinRequest(ctx, ApproveJoinRequestInput{
		GroupID: gid, RequesterUserID: user.UserID, RequestID: id, ApproverUserID: approver.UserID,
		RequesterKeyEpoch: 3, Role: models.RoleMember, Admission: models.Admission{InviteID: id},
	})
	if !errors.Is(err, ErrWrapEpochStale) {
		t.Fatalf("approving with an epoch that has moved: %v, want ErrWrapEpochStale", err)
	}
	if itemExists(t, c, "GROUP#"+gid, "MEMBER#"+user.UserID) || !itemExists(t, c, "GROUP#"+gid, "REQ#"+user.UserID) {
		t.Error("a refused approval changed the table")
	}

	gone := requesterOf(t, c)
	if err := createReq(c, gid, gone, id); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteAccount(ctx, gone.UserID); err != nil {
		t.Fatal(err)
	}
	// DeleteAccount sweeps the request, so put one back to prove approval itself refuses a deleted account.
	putRaw(t, c, map[string]types.AttributeValue{
		"PK": s("GROUP#" + gid), "SK": s("REQ#" + gone.UserID), "Type": s("JoinRequest"), "RequestID": s(id),
		"Status": s(models.JoinRequestPending), "TTL": &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)},
	})
	err = c.ApproveJoinRequest(ctx, ApproveJoinRequestInput{
		GroupID: gid, RequesterUserID: gone.UserID, RequestID: id, ApproverUserID: approver.UserID,
		Role: models.RoleMember, Admission: models.Admission{InviteID: id},
	})
	if !errors.Is(err, ErrInviteeDeleted) {
		t.Errorf("approving a deleted account: %v, want ErrInviteeDeleted", err)
	}
	if itemExists(t, c, "GROUP#"+gid, "MEMBER#"+gone.UserID) {
		t.Error("a deleted account was admitted")
	}
}

func TestRemoveJoinRequestOnlyRemovesTheRequestItNames(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid := putPublicGroup(t, c)
	user := requesterOf(t, c)
	id := newUserID(t)
	if err := createReq(c, gid, user, id); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveJoinRequest(ctx, gid, user.UserID, newUserID(t)); err != nil {
		t.Fatalf("removing another request id: %v", err)
	}
	if !itemExists(t, c, "GROUP#"+gid, "REQ#"+user.UserID) {
		t.Fatal("RemoveJoinRequest removed a request it did not name")
	}
	if err := c.RemoveJoinRequest(ctx, gid, user.UserID, id); err != nil {
		t.Fatal(err)
	}
	if itemExists(t, c, "GROUP#"+gid, "REQ#"+user.UserID) {
		t.Error("RemoveJoinRequest left the request it named")
	}
	if err := c.RemoveJoinRequest(ctx, gid, user.UserID, id); err != nil {
		t.Errorf("removing what is already gone: %v, want nil", err)
	}
}

func setKeyEpoch(t *testing.T, c *Client, userID string, epoch int) {
	t.Helper()
	_, err := c.ddb.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table), Key: map[string]types.AttributeValue{"PK": s("USER#" + userID), "SK": s("PROFILE")},
		UpdateExpression:          aws.String("SET KeyEpoch = :e"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":e": &types.AttributeValueMemberN{Value: strconv.Itoa(epoch)}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A decided request is not a request to approve: the decision is final until the cool-off ends, even
// for a caller that holds the old request id.
func TestApproveJoinRequestRefusesADeniedRequest(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid := putPublicGroup(t, c)
	approver := requesterOf(t, c)
	putTestMember(t, c, gid, approver.UserID, models.RoleAdmin)
	user := requesterOf(t, c)
	id := newUserID(t)
	if err := createReq(c, gid, user, id); err != nil {
		t.Fatal(err)
	}
	if err := c.DenyJoinRequest(ctx, gid, user.UserID, approver.UserID, time.Now()); err != nil {
		t.Fatal(err)
	}
	err := c.ApproveJoinRequest(ctx, ApproveJoinRequestInput{
		GroupID: gid, RequesterUserID: user.UserID, RequestID: id, ApproverUserID: approver.UserID,
		Role: models.RoleMember, Admission: models.Admission{InviteID: id},
	})
	if !errors.Is(err, ErrJoinRequestNotFound) {
		t.Fatalf("approving a denied request: %v, want ErrJoinRequestNotFound", err)
	}
	if itemExists(t, c, "GROUP#"+gid, "MEMBER#"+user.UserID) {
		t.Error("a denied request produced a membership")
	}
}

// The membership records the epoch the requester's keys were at, so a later rotation shows the entry as behind.
func TestApproveJoinRequestRecordsTheRequestersKeyEpoch(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid := putPublicGroup(t, c)
	approver := requesterOf(t, c)
	putTestMember(t, c, gid, approver.UserID, models.RoleAdmin)
	user := requesterOf(t, c)
	setKeyEpoch(t, c, user.UserID, 2)
	id := newUserID(t)
	if err := c.CreateJoinRequest(ctx, CreateJoinRequestInput{
		GroupID: gid, RequesterUserID: user.UserID, RequestID: id,
		Ed25519PublicKey: user.SigningPublicKey, X25519PublicKey: user.WrappingPublicKey,
		Signature: make([]byte, 64), RequesterKeyEpoch: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.ApproveJoinRequest(ctx, ApproveJoinRequestInput{
		GroupID: gid, RequesterUserID: user.UserID, RequestID: id, ApproverUserID: approver.UserID,
		RequesterKeyEpoch: 2, Role: models.RoleMember, Admission: models.Admission{InviteID: id},
	}); err != nil {
		t.Fatal(err)
	}
	m, err := c.GetMembership(ctx, gid, user.UserID)
	if err != nil || m == nil {
		t.Fatalf("membership: %v, %v", m, err)
	}
	if m.WrapEpoch != 2 {
		t.Errorf("WrapEpoch = %d, want 2", m.WrapEpoch)
	}
}

// ---- the Rotating member cap (#60), shared with invite completion ----

// capGroup is a public group with one admin and n users who have each asked to join.
type capGroup struct {
	gid      string
	admin    RegisterInput
	users    []RegisterInput
	requests []string
}

func newCapGroup(t *testing.T, c *Client, requesters int) capGroup {
	t.Helper()
	g := capGroup{gid: putPublicGroup(t, c), admin: requesterOf(t, c)}
	putTestMember(t, c, g.gid, g.admin.UserID, models.RoleAdmin)
	for i := 0; i < requesters; i++ {
		u := requesterOf(t, c)
		id := newUserID(t)
		if err := createReq(c, g.gid, u, id); err != nil {
			t.Fatal(err)
		}
		g.users, g.requests = append(g.users, u), append(g.requests, id)
	}
	return g
}

func (g capGroup) approve(c *Client, i, maxMembers int) error {
	return c.ApproveJoinRequest(context.Background(), ApproveJoinRequestInput{
		GroupID: g.gid, RequesterUserID: g.users[i].UserID, RequestID: g.requests[i], ApproverUserID: g.admin.UserID,
		Role: models.RoleMember, MaxMembers: maxMembers, Admission: models.Admission{InviteID: g.requests[i]},
	})
}

func TestApproveJoinRequestStopsAtTheCapAndLeavesTheRequestPending(t *testing.T) {
	c := testClient(t)
	g := newCapGroup(t, c, 2)
	if err := g.approve(c, 0, 2); err != nil { // the admin plus one: full
		t.Fatalf("first approval: %v", err)
	}
	if err := g.approve(c, 1, 2); !errors.Is(err, ErrGroupFull) {
		t.Fatalf("approval into a full group = %v, want ErrGroupFull", err)
	}
	if n := mustCount(t, c, g.gid); n != 2 {
		t.Errorf("group has %d members, want 2", n)
	}
	if !itemExists(t, c, "GROUP#"+g.gid, "REQ#"+g.users[1].UserID) {
		t.Error("the refused request was deleted; it should stay pending so a departure can free a slot")
	}
	// Room again (cap raised): the same request is approved.
	if err := g.approve(c, 1, 3); err != nil {
		t.Fatalf("approval after the cap allows: %v", err)
	}
}

func TestApproveJoinRequestWithoutACapIgnoresTheCount(t *testing.T) {
	c := testClient(t)
	g := newCapGroup(t, c, 3)
	for i := range g.users {
		if err := g.approve(c, i, 0); err != nil {
			t.Fatalf("approval %d: %v", i, err)
		}
	}
	if n := mustCount(t, c, g.gid); n != 4 {
		t.Errorf("group has %d members, want 4", n)
	}
}

func TestApproveJoinRequestBumpsJoinSeqOnCappedApprovals(t *testing.T) {
	c := testClient(t)
	g := newCapGroup(t, c, 3)
	for i := range g.users {
		if err := g.approve(c, i, 10); err != nil {
			t.Fatalf("approval %d: %v", i, err)
		}
		if seq, err := c.joinSeq(context.Background(), g.gid); err != nil || seq != int64(i+1) {
			t.Fatalf("joinSeq after approval %d = %d, %v, want %d", i, seq, err, i+1)
		}
	}
}

func TestApproveJoinRequestFullGroupStillReportsAlreadyMember(t *testing.T) {
	c := testClient(t)
	g := newCapGroup(t, c, 1)
	putTestMember(t, c, g.gid, g.users[0].UserID, models.RoleMember) // joined some other way; the group is full
	if err := g.approve(c, 0, 2); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("full group, existing member = %v, want ErrAlreadyMember", err)
	}
}

func TestApproveJoinRequestCappedGroupGone(t *testing.T) {
	c := testClient(t)
	g := newCapGroup(t, c, 1)
	if _, err := c.ddb.DeleteItem(context.Background(), deleteItemInput(c.table, "GROUP#"+g.gid, "META")); err != nil {
		t.Fatal(err)
	}
	if err := g.approve(c, 0, 5); !errors.Is(err, ErrGroupGone) {
		t.Fatalf("capped approval into a deleted group = %v, want ErrGroupGone", err)
	}
}

// Many approvals at once into a group with room for fewer of them. Without the JoinSeq guard each would
// count the same number of members, find room, and all succeed.
func TestApproveJoinRequestCapHoldsUnderConcurrentApprovals(t *testing.T) {
	const (
		rounds     = 4
		contenders = 6
		cap_       = 4 // the admin plus room for 3
	)
	c := testClient(t)
	for round := 0; round < rounds; round++ {
		g := newCapGroup(t, c, contenders)
		var wg sync.WaitGroup
		errs := make([]error, contenders)
		start := make(chan struct{})
		for i := 0; i < contenders; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				errs[i] = g.approve(c, i, cap_)
			}(i)
		}
		close(start)
		wg.Wait()
		ok, full := 0, 0
		for i, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrGroupFull):
				full++
			default:
				t.Fatalf("round %d contender %d: unexpected error %v", round, i, err)
			}
		}
		if n := mustCount(t, c, g.gid); n > cap_ || ok != cap_-1 || full != contenders-(cap_-1) {
			t.Fatalf("round %d: %d members (cap %d), ok=%d full=%d, want ok=%d full=%d", round, n, cap_, ok, full, cap_-1, contenders-(cap_-1))
		}
	}
}

// An invite's completion and a request's approval are two ways into one group and share one guard: with
// room for exactly one more, racing the two lets exactly one in.
func TestInviteCompletionAndApprovalShareTheCap(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	for round := 0; round < 6; round++ {
		g := newCapGroup(t, c, 1)
		// An accepted invite into the same group, completed by the same admin.
		inviteID, inviteeID := "test-invite-"+randomSuffix(t), "test-invitee-"+randomSuffix(t)
		if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, g.gid, g.admin.UserID, time.Now().Add(7*24*time.Hour))); err != nil {
			t.Fatal(err)
		}
		if err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, inviteeID)); err != nil {
			t.Fatal(err)
		}
		const cap_ = 2 // the admin plus one
		var wg sync.WaitGroup
		var invErr, reqErr error
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			in := testCompleteInviteInput(inviteID, g.gid, g.admin.UserID, inviteeID)
			in.MaxMembers = cap_
			invErr = c.CompleteInvite(ctx, in)
		}()
		go func() {
			defer wg.Done()
			<-start
			reqErr = g.approve(c, 0, cap_)
		}()
		close(start)
		wg.Wait()
		okCount := 0
		for _, err := range []error{invErr, reqErr} {
			switch {
			case err == nil:
				okCount++
			case errors.Is(err, ErrGroupFull):
			default:
				t.Fatalf("round %d: unexpected error %v", round, err)
			}
		}
		if n := mustCount(t, c, g.gid); okCount != 1 || n != cap_ {
			t.Fatalf("round %d: %d joined, group has %d members, want exactly one join and %d members (invite: %v, approval: %v)", round, okCount, n, cap_, invErr, reqErr)
		}
	}
}

func TestRemoveJoinRequestLeavesADeniedRequestToRunOutItsCoolOff(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid := putPublicGroup(t, c)
	approver := requesterOf(t, c)
	putTestMember(t, c, gid, approver.UserID, models.RoleAdmin)
	user := requesterOf(t, c)
	id := newUserID(t)
	if err := createReq(c, gid, user, id); err != nil {
		t.Fatal(err)
	}
	if err := c.DenyJoinRequest(ctx, gid, user.UserID, approver.UserID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveJoinRequest(ctx, gid, user.UserID, id); err != nil {
		t.Fatalf("RemoveJoinRequest on a denied request: %v", err)
	}
	jr, err := c.GetJoinRequest(ctx, gid, user.UserID, time.Now())
	if err != nil || jr == nil || jr.Status != models.JoinRequestDenied {
		t.Errorf("the denied request after RemoveJoinRequest = %+v (%v), want it kept with status denied", jr, err)
	}
}

func TestApproveJoinRequestUncappedGroupGone(t *testing.T) {
	c := testClient(t)
	g := newCapGroup(t, c, 1)
	if _, err := c.ddb.DeleteItem(context.Background(), deleteItemInput(c.table, "GROUP#"+g.gid, "META")); err != nil {
		t.Fatal(err)
	}
	if err := g.approve(c, 0, 0); !errors.Is(err, ErrGroupGone) {
		t.Fatalf("approval into a deleted group = %v, want ErrGroupGone", err)
	}
	if itemExists(t, c, "GROUP#"+g.gid, "MEMBER#"+g.users[0].UserID) {
		t.Error("a membership was written into a deleted group")
	}
}

// A user who asked to join and then joins by invite no longer has a use for the request. If it stayed, it
// would sit in the admin queue while they are a member and, once they leave, still be approvable: a
// deliberate leave would be undone on the strength of something they asked before they joined.
func TestCompletingAnInviteClearsThePendingJoinRequest(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid := putPublicGroup(t, c)
	admin := requesterOf(t, c)
	putTestMember(t, c, gid, admin.UserID, models.RoleAdmin)
	user := requesterOf(t, c)

	requestID := newUserID(t)
	if err := createReq(c, gid, user, requestID); err != nil {
		t.Fatal(err)
	}
	inviteID := "test-invite-" + randomSuffix(t)
	if err := c.CreateInvite(ctx, testCreateInviteInput(t, inviteID, gid, admin.UserID, time.Now().Add(7*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := c.AcceptInvite(ctx, testAcceptInviteInput(inviteID, user.UserID)); err != nil {
		t.Fatal(err)
	}
	if err := c.CompleteInvite(ctx, testCompleteInviteInput(inviteID, gid, admin.UserID, user.UserID)); err != nil {
		t.Fatalf("CompleteInvite: %v", err)
	}

	if itemExists(t, c, "GROUP#"+gid, "REQ#"+user.UserID) {
		t.Error("the member's pending join request survived their joining by invite")
	}
	if rows, _, err := c.ListPendingJoinRequests(ctx, gid, time.Now(), 10, ""); err != nil || len(rows) != 0 {
		t.Errorf("the admin queue lists %d request(s) from a member (%v)", len(rows), err)
	}
	if rows, _, err := c.ListJoinRequestsByUser(ctx, user.UserID, time.Now(), 50, ""); err != nil || len(rows) != 0 {
		t.Errorf("the member's own list holds %d request(s) (%v)", len(rows), err)
	}

	// They leave; the request they made before joining must not bring them back.
	if _, err := c.LeaveGroup(ctx, gid, user.UserID, nil, nil, false); err != nil {
		t.Fatalf("LeaveGroup: %v", err)
	}
	err := c.ApproveJoinRequest(ctx, ApproveJoinRequestInput{
		GroupID: gid, RequesterUserID: user.UserID, RequestID: requestID, ApproverUserID: admin.UserID,
		Role: models.RoleMember, Admission: models.Admission{InviteID: requestID},
	})
	if !errors.Is(err, ErrJoinRequestNotFound) {
		t.Errorf("approving after they left = %v, want ErrJoinRequestNotFound", err)
	}
	if itemExists(t, c, "GROUP#"+gid, "MEMBER#"+user.UserID) {
		t.Error("a user who left was put back in the group by an old request")
	}
}

func TestListJoinRequestsByUserPagesAndSkipsExpiredRows(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	user, other := requesterOf(t, c), requesterOf(t, c)
	var groups []string
	for i := 0; i < 6; i++ {
		g := putPublicGroup(t, c)
		groups = append(groups, g)
		if err := createReq(c, g, user, newUserID(t)); err != nil {
			t.Fatal(err)
		}
		// GSI1SK is day-plus-random, so within a day the order is not creation order: collect the
		// expected order from the index itself below.
	}
	if err := createReq(c, groups[0], other, newUserID(t)); err != nil {
		t.Fatal(err)
	}
	// Two rows expire before DynamoDB sweeps them.
	for _, g := range []string{groups[1], groups[3]} {
		_, err := c.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName: aws.String(c.table), Key: map[string]types.AttributeValue{"PK": s("GROUP#" + g), "SK": s("REQ#" + user.UserID)},
			UpdateExpression: aws.String("SET #t = :t"), ExpressionAttributeNames: map[string]string{"#t": "TTL"},
			ExpressionAttributeValues: map[string]types.AttributeValue{":t": &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	live := map[string]bool{groups[0]: true, groups[2]: true, groups[4]: true, groups[5]: true}

	walk := func(t *testing.T, limit int) (ids []string, pages int) {
		t.Helper()
		cursor := ""
		for pages = 1; pages <= 30; pages++ {
			rows, next, err := c.ListJoinRequestsByUser(ctx, user.UserID, time.Now(), limit, cursor)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) > limit {
				t.Fatalf("page of %d rows, limit %d", len(rows), limit)
			}
			for _, r := range rows {
				if r.RequesterUserID != user.UserID {
					t.Fatalf("another user's request in the list: %+v", r)
				}
				ids = append(ids, r.GroupID)
			}
			if next == "" {
				return ids, pages
			}
			cursor = next
		}
		t.Fatal("the cursor never ended")
		return nil, 0
	}
	check := func(t *testing.T, ids []string) {
		t.Helper()
		seen := map[string]bool{}
		for _, id := range ids {
			if seen[id] {
				t.Fatalf("%s listed twice", id)
			}
			if !live[id] {
				t.Errorf("group %s should not be listed (expired or not the user's)", id)
			}
			seen[id] = true
		}
		for id := range live {
			if !seen[id] {
				t.Errorf("group %s never listed", id)
			}
		}
	}

	t.Run("pages of two cover each live request once", func(t *testing.T) {
		ids, pages := walk(t, 2)
		check(t, ids)
		if pages < 2 {
			t.Errorf("4 live requests at a limit of 2 took %d page(s)", pages)
		}
	})
	t.Run("one big page", func(t *testing.T) {
		ids, pages := walk(t, 50)
		check(t, ids)
		if pages != 1 {
			t.Errorf("took %d pages", pages)
		}
	})
	t.Run("a pass bound hands back a cursor that resumes, expired rows included", func(t *testing.T) {
		old := maxJoinRequestPasses
		maxJoinRequestPasses = 1
		t.Cleanup(func() { maxJoinRequestPasses = old })
		ids, _ := walk(t, 1)
		check(t, ids)
	})
	t.Run("a malformed cursor is refused, not read", func(t *testing.T) {
		if _, _, err := c.ListJoinRequestsByUser(ctx, user.UserID, time.Now(), 5, "nonsense"); err == nil {
			t.Error("a cursor with no group part was accepted")
		}
	})
}

func TestPublicGroupNamesReturnsOnlyPublicGroupsAndBatches(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	if names, err := c.PublicGroupNames(ctx, nil); err != nil || len(names) != 0 {
		t.Fatalf("no ids: %v, %v", names, err)
	}
	pub := putPublicGroup(t, c)
	putRaw(t, c, map[string]types.AttributeValue{"PK": s("GROUP#" + pub), "SK": s("META"), "Type": s("Group"), "Visibility": s(models.VisibilityPublic), "NamePlaintext": s("Chess Club")})
	private := newUserID(t)
	putRaw(t, c, map[string]types.AttributeValue{"PK": s("GROUP#" + private), "SK": s("META"), "Type": s("Group"), "Visibility": s(models.VisibilityPrivate), "NamePlaintext": s("never shown")})
	t.Cleanup(func() { removePartitions(t, c, "GROUP#"+private) })
	ids := []string{pub, private, newUserID(t)}
	// More than one BatchGetItem's worth of ids.
	for i := 0; i < 120; i++ {
		ids = append(ids, newUserID(t))
	}
	names, err := c.PublicGroupNames(ctx, ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[pub] != "Chess Club" {
		t.Errorf("names = %v, want only the public group", names)
	}
}
