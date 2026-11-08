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
	if rows, err := c.ListJoinRequestsByUser(ctx, user.UserID, now); err != nil || len(rows) != 0 {
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

// A group whose denied requests fill more than one 1 MB page before the first pending one: the
// queue read must keep going past the page boundary, not stop at an empty first page.
func TestListPendingJoinRequestsReadsPastAMegabyteOfDeniedRows(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid := putPublicGroup(t, c)
	putManyDenied(t, c, gid, 7000) // about 2.8 MB of rows ahead of the pending ones
	var pending []string
	for _, uid := range []string{"zzzzzzz1-0000-4000-8000-000000000000", "zzzzzzz2-0000-4000-8000-000000000000", "zzzzzzz3-0000-4000-8000-000000000000"} {
		pending = append(pending, uid)
		putRaw(t, c, map[string]types.AttributeValue{
			"PK": s("GROUP#" + gid), "SK": s("REQ#" + uid), "Type": s("JoinRequest"),
			"GSI1PK": s("USER#" + uid), "GSI1SK": s("REQ#2026-11-07#" + uid),
			"TTL":       &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Add(48*time.Hour).Unix(), 10)},
			"RequestID": s(uid), "GroupID": s(gid), "RequesterUserID": s(uid), "Status": s(models.JoinRequestPending),
		})
	}

	rows, next, err := c.ListPendingJoinRequests(ctx, gid, time.Now(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || next != "" {
		t.Fatalf("got %d pending rows and cursor %q, want all 3 and no cursor (the denied rows ahead of them are more than one page)", len(rows), next)
	}
	for i, r := range rows {
		if r.RequesterUserID != pending[i] {
			t.Errorf("row %d = %s, want %s", i, r.RequesterUserID, pending[i])
		}
	}

	// With the pass bound lowered the read gives up early and hands back a cursor that resumes.
	old := maxJoinRequestPasses
	maxJoinRequestPasses = 1
	t.Cleanup(func() { maxJoinRequestPasses = old })
	got, cursor := []string(nil), ""
	for i := 0; i < 20; i++ {
		page, next, err := c.ListPendingJoinRequests(ctx, gid, time.Now(), 10, cursor)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range page {
			got = append(got, r.RequesterUserID)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(got) != 3 || got[0] != pending[0] || got[2] != pending[2] {
		t.Errorf("resuming from cursors found %v, want the 3 pending requests in order", got)
	}
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
	rows, err := c.ListJoinRequestsByUser(ctx, user.UserID, time.Now())
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
