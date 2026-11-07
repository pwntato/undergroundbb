package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type unreadEntry struct {
	GroupID    string `json:"groupId"`
	Unread     *int   `json:"unread"`
	UnreadMore bool   `json:"unreadMore"`
}

// n is the count, or -1 when the response carried none.
func (e unreadEntry) n() int {
	if e.Unread == nil {
		return -1
	}
	return *e.Unread
}

func unreadByGroup(t *testing.T, h *Handler, c *http.Cookie) map[string]unreadEntry {
	t.Helper()
	return unreadByGroupAt(t, h, c, "/api/groups?unread=1", http.StatusOK)
}

func unreadByGroupAt(t *testing.T, h *Handler, c *http.Cookie, path string, wantCode int) map[string]unreadEntry {
	t.Helper()
	rec := doNotifications(t, h, c, http.MethodGet, path, nil)
	if rec.Code != wantCode {
		t.Fatalf("list groups: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Groups []unreadEntry `json:"groups"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	out := map[string]unreadEntry{}
	for _, g := range resp.Groups {
		out[g.GroupID] = g
	}
	return out
}

func markRowRead(t *testing.T, userID, sk string) {
	t.Helper()
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:                 aws.String(testTableName()),
		Key:                       map[string]types.AttributeValue{"PK": s("USER#" + userID), "SK": s(sk)},
		UpdateExpression:          aws.String("SET #r = :t"),
		ExpressionAttributeNames:  map[string]string{"#r": "Read"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":t": &types.AttributeValueMemberBOOL{Value: true}},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestListGroupsCountsUnreadPerGroupAndOnlyWhatTheListShows(t *testing.T) {
	h, gid, owner, bob, c, pOld, pMid, _ := listFixture(t)
	gid2 := createPrivateGroup(t, h, owner, c)
	p2 := pidOf(gid2, "POST#2026-10-20#00112233445566b1")
	storePostAt(t, gid2, "POST#2026-10-20#00112233445566b1", owner.userID, 0)
	gone := pidOf(gid, "POST#2026-10-30#00112233445566a5")
	otherGid := "11111111-1111-4111-8111-111111111111"
	otherPid := pidOf(otherGid, "POST#2026-10-28#00112233445566a6")
	storePostAt(t, otherGid, "POST#2026-10-28#00112233445566a6", bob.userID, 0)

	putNotif(t, owner.userID, replySK("2026-10-20", 1), "reply", bob.userID, gid, pOld)
	putNotif(t, owner.userID, replySK("2026-10-21", 2), "reply", bob.userID, gid, pMid)
	putNotif(t, owner.userID, replySK("2026-10-22", 3), "reply", bob.userID, gid, pMid) // read below
	putNotif(t, owner.userID, reactSK(pOld, 1), "reaction", bob.userID, gid, pOld)
	putNotif(t, owner.userID, replySK("2026-10-23", 4), "reply", bob.userID, gid, gone)          // post gone
	putNotif(t, owner.userID, replySK("2026-10-24", 5), "reply", bob.userID, otherGid, otherPid) // not a member
	putNotif(t, owner.userID, replySK("2026-10-25", 6), "reply", bob.userID, gid2, p2)
	putNotif(t, bob.userID, replySK("2026-10-26", 7), "reply", owner.userID, gid, pOld) // someone else's
	markRowRead(t, owner.userID, replySK("2026-10-22", 3))

	got := unreadByGroup(t, h, c)
	if g := got[gid]; g.n() != 3 || g.UnreadMore {
		t.Fatalf("group 1: %+v, want 3 unread, not more", g)
	}
	if g := got[gid2]; g.n() != 1 || g.UnreadMore {
		t.Fatalf("group 2: %+v, want 1 unread, not more", g)
	}
	if len(got) != 2 {
		t.Fatalf("groups %v, want only the two the caller is in", got)
	}
}

func TestListGroupsUnreadStopsAtNinetyNineAndSaysThereAreMore(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, _ := listFixture(t)
	putManyReactions(t, owner.userID, bob.userID, gid, pOld, maxUnreadShown+1)
	g := unreadByGroup(t, h, c)[gid]
	if g.n() != maxUnreadShown || !g.UnreadMore {
		t.Fatalf("%+v, want %d and more", g, maxUnreadShown)
	}

	// Exactly 99 is a full count, not a lower bound.
	h2, gid2, owner2, bob2, c2, p2, _, _ := listFixture(t)
	putManyReactions(t, owner2.userID, bob2.userID, gid2, p2, maxUnreadShown)
	g = unreadByGroup(t, h2, c2)[gid2]
	if g.n() != maxUnreadShown || g.UnreadMore {
		t.Fatalf("%+v, want exactly %d and not more", g, maxUnreadShown)
	}
}

func TestListGroupsUnreadIsALowerBoundWhenTheReadRunsOutOfBudget(t *testing.T) {
	h, gid, owner, bob, c, _, _, pNew := listFixture(t)
	// The older post's rows are gone-post rows that fill the next batches; the live unread row on
	// the newest post comes first, so the first batch finds it and the spent budget stops there.
	gone := pidOf(gid, "POST#2026-09-01#00112233445566a5")
	putManyReactions(t, owner.userID, bob.userID, gid, gone, 2*notificationReadBatch)
	putNotif(t, owner.userID, reactSK(pNew, 0), "reaction", bob.userID, gid, pNew)

	old := notificationTimeBudget
	notificationTimeBudget = -1
	t.Cleanup(func() { notificationTimeBudget = old })
	g := unreadByGroup(t, h, c)[gid]
	if g.n() != 1 || !g.UnreadMore {
		t.Fatalf("%+v, want 1 and more when the read stopped before the end", g)
	}
}

// Past the row limit with everything read, a group has no badge: marking all read cannot clear a
// "0+", because the read rows are what fill the window (review of #346).
func TestListGroupsUnreadAllReadPastTheLimitIsZeroWithNoFlag(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, _ := listFixture(t)
	gid2 := createPrivateGroup(t, h, owner, c)
	putManyReactions(t, owner.userID, bob.userID, gid, pOld, notificationMaxPasses*notificationReadBatch+1)
	for i := 0; i < notificationMaxPasses*notificationReadBatch+1; i++ {
		markRowRead(t, owner.userID, reactSK(pOld, i))
	}
	got := unreadByGroup(t, h, c)
	for _, id := range []string{gid, gid2} {
		if g := got[id]; g.n() != 0 || g.UnreadMore {
			t.Fatalf("group %s: %+v, want 0 and no flag", id, g)
		}
	}
}

// Exactly the row limit with the unread row inside it is an exact count, not a lower bound.
func TestListGroupsUnreadExactlyAtTheRowLimitIsExact(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, pNew := listFixture(t)
	total := notificationMaxPasses * notificationReadBatch
	putManyReactions(t, owner.userID, bob.userID, gid, pOld, total-1)
	for i := 0; i < total-1; i++ {
		markRowRead(t, owner.userID, reactSK(pOld, i))
	}
	putNotif(t, owner.userID, reactSK(pNew, 0), "reaction", bob.userID, gid, pNew)
	if g := unreadByGroup(t, h, c)[gid]; g.n() != 1 || g.UnreadMore {
		t.Fatalf("%+v, want exactly 1 and no flag", g)
	}
	// Two rows more than the limit (1002), the unread one among the first 1001 read, is a lower
	// bound. At 1001 the whole range is read but the Query still reports a next key, so that one
	// row count is a known, harmless false plus and is not pinned here.
	for _, i := range []int{total, total + 1} {
		putNotif(t, owner.userID, reactSK(pOld, i), "reaction", bob.userID, gid, pOld)
		markRowRead(t, owner.userID, reactSK(pOld, i))
	}
	if g := unreadByGroup(t, h, c)[gid]; g.n() != 1 || !g.UnreadMore {
		t.Fatalf("%+v, want 1 and more past the limit (1002 rows)", g)
	}
}

func TestListGroupsWithoutTheParameterCarriesNoCount(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, _ := listFixture(t)
	putNotif(t, owner.userID, replySK("2026-10-20", 1), "reply", bob.userID, gid, pOld)
	g := unreadByGroupAt(t, h, c, "/api/groups", http.StatusOK)[gid]
	if g.n() != -1 || g.UnreadMore {
		t.Fatalf("%+v, want no count when not asked", g)
	}
}

func TestGroupDetailCarriesNoCount(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, _ := listFixture(t)
	putNotif(t, owner.userID, replySK("2026-10-20", 1), "reply", bob.userID, gid, pOld)
	rec := doNotifications(t, h, c, http.MethodGet, "/api/groups/"+gid, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"unread", "unreadMore"} {
		if _, ok := raw[k]; ok {
			t.Fatalf("group detail has %q", k)
		}
	}
}

// A count that fails must not fail the list (review of #346). A post row whose TTL is not a number
// fails to unmarshal when the count looks the post up.
// A count that runs out of time must not fail the list either (review of #346, round 3).
func TestListGroupsStillLoadsWhenTheCountTimesOut(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, _ := listFixture(t)
	putNotif(t, owner.userID, replySK("2026-10-20", 1), "reply", bob.userID, gid, pOld)
	old := unreadCountTimeout
	unreadCountTimeout = time.Nanosecond
	t.Cleanup(func() { unreadCountTimeout = old })
	g, ok := unreadByGroup(t, h, c)[gid]
	if !ok || g.n() != -1 {
		t.Fatalf("%+v ok=%v, want the group listed with no count", g, ok)
	}
}

func TestListGroupsStillLoadsWhenTheCountFails(t *testing.T) {
	h, gid, owner, bob, c, _, _, _ := listFixture(t)
	bad := pidOf(gid, "POST#2026-10-27#00112233445566a8")
	storePostAt(t, gid, "POST#2026-10-27#00112233445566a8", owner.userID, 0)
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:                 aws.String(testTableName()),
		Key:                       map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s("POST#2026-10-27#00112233445566a8")},
		UpdateExpression:          aws.String("SET #t = :s"),
		ExpressionAttributeNames:  map[string]string{"#t": "TTL"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":s": s("not a number")},
	}); err != nil {
		t.Fatal(err)
	}
	putNotif(t, owner.userID, replySK("2026-10-27", 1), "reply", bob.userID, gid, bad)
	g, ok := unreadByGroup(t, h, c)[gid]
	if !ok {
		t.Fatal("group missing from the list")
	}
	if g.n() != -1 || g.UnreadMore {
		t.Fatalf("%+v, want no count when the count failed", g)
	}
}

func TestListGroupsUnreadIsZeroWithoutNotifications(t *testing.T) {
	h, gid, _, _, c, _, _, _ := listFixture(t)
	if g := unreadByGroup(t, h, c)[gid]; g.n() != 0 || g.UnreadMore {
		t.Fatalf("%+v, want 0", g)
	}
}

type unreadTotalBody struct {
	Unread     int  `json:"unread"`
	UnreadMore bool `json:"unreadMore"`
}

func getUnreadTotal(t *testing.T, h *Handler, c *http.Cookie, wantCode int) unreadTotalBody {
	t.Helper()
	rec := doNotifications(t, h, c, http.MethodGet, "/api/notifications/unread", nil)
	if rec.Code != wantCode {
		t.Fatalf("unread total: %d %s", rec.Code, rec.Body.String())
	}
	var b unreadTotalBody
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	return b
}

func TestUnreadTotalRequiresASession(t *testing.T) {
	h, _, _, _, _, _, _, _ := listFixture(t)
	getUnreadTotal(t, h, nil, http.StatusUnauthorized)
}

func TestUnreadTotalSumsGroupsAndSkipsWhatTheListSkips(t *testing.T) {
	h, gid, owner, bob, c, pOld, pMid, _ := listFixture(t)
	gid2 := createPrivateGroup(t, h, owner, c)
	p2 := pidOf(gid2, "POST#2026-10-20#00112233445566b1")
	storePostAt(t, gid2, "POST#2026-10-20#00112233445566b1", owner.userID, 0)
	otherGid := "11111111-1111-4111-8111-111111111111"
	otherPid := pidOf(otherGid, "POST#2026-10-28#00112233445566a6")
	storePostAt(t, otherGid, "POST#2026-10-28#00112233445566a6", bob.userID, 0)

	putNotif(t, owner.userID, replySK("2026-10-20", 1), "reply", bob.userID, gid, pOld)
	putNotif(t, owner.userID, replySK("2026-10-21", 2), "reply", bob.userID, gid, pMid)
	putNotif(t, owner.userID, replySK("2026-10-22", 3), "reply", bob.userID, gid, pMid) // read below
	putNotif(t, owner.userID, replySK("2026-10-25", 6), "reply", bob.userID, gid2, p2)
	putNotif(t, owner.userID, replySK("2026-10-24", 5), "reply", bob.userID, otherGid, otherPid) // not a member
	putNotif(t, bob.userID, replySK("2026-10-26", 7), "reply", owner.userID, gid, pOld)          // someone else's
	markRowRead(t, owner.userID, replySK("2026-10-22", 3))

	if got := getUnreadTotal(t, h, c, http.StatusOK); got.Unread != 3 || got.UnreadMore {
		t.Fatalf("%+v, want 3 across both groups, not more", got)
	}
}

func TestUnreadTotalIsZeroWithNothingUnread(t *testing.T) {
	h, _, _, _, c, _, _, _ := listFixture(t)
	if got := getUnreadTotal(t, h, c, http.StatusOK); got.Unread != 0 || got.UnreadMore {
		t.Fatalf("%+v, want 0", got)
	}
}

// Two groups of 60 each are 120 in all: the total stops at 99 and says there are more.
func TestUnreadTotalStopsAtNinetyNineAcrossGroups(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, _ := listFixture(t)
	gid2 := createPrivateGroup(t, h, owner, c)
	p2 := pidOf(gid2, "POST#2026-10-20#00112233445566b1")
	storePostAt(t, gid2, "POST#2026-10-20#00112233445566b1", owner.userID, 0)
	putManyReactions(t, owner.userID, bob.userID, gid, pOld, 60)
	putManyReactions(t, owner.userID, bob.userID, gid2, p2, 60)
	if got := getUnreadTotal(t, h, c, http.StatusOK); got.Unread != maxUnreadShown || !got.UnreadMore {
		t.Fatalf("%+v, want %d and more", got, maxUnreadShown)
	}
}

func TestUnreadTotalIsAnErrorWhenTheCountTimesOut(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, _ := listFixture(t)
	putNotif(t, owner.userID, replySK("2026-10-20", 1), "reply", bob.userID, gid, pOld)
	old := unreadCountTimeout
	unreadCountTimeout = time.Nanosecond
	t.Cleanup(func() { unreadCountTimeout = old })
	getUnreadTotal(t, h, c, http.StatusInternalServerError)
}

// A group whose count is only a lower bound makes the total one, even well under 99.
func TestUnreadTotalIsALowerBoundWhenAGroupsCountIs(t *testing.T) {
	h, gid, owner, bob, c, _, _, pNew := listFixture(t)
	gone := pidOf(gid, "POST#2026-09-01#00112233445566a5")
	putManyReactions(t, owner.userID, bob.userID, gid, gone, 2*notificationReadBatch)
	putNotif(t, owner.userID, reactSK(pNew, 0), "reaction", bob.userID, gid, pNew)
	old := notificationTimeBudget
	notificationTimeBudget = -1
	t.Cleanup(func() { notificationTimeBudget = old })
	if got := getUnreadTotal(t, h, c, http.StatusOK); got.Unread != 1 || !got.UnreadMore {
		t.Fatalf("%+v, want 1 and more", got)
	}
}
