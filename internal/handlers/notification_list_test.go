package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/idgen"
)

func doNotifications(t *testing.T, h *Handler, cookie *http.Cookie, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// putNotif stores a notification row for the recipient. A reply's sk carries a real day, a
// reaction's the placeholder.
func putNotif(t *testing.T, recipient, sk, kind, actor, gid, pid string) {
	t.Helper()
	if _, err := rawDDB(t).PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName: aws.String(testTableName()),
		Item: map[string]types.AttributeValue{
			"PK": s("USER#" + recipient), "SK": s(sk), "Type": s("NOTIFICATION"),
			"Kind": s(kind), "ActorUserID": s(actor), "GroupID": s(gid), "PostID": s(pid),
			"CmtPath": s(cmtPathFor(kind)), "Read": &types.AttributeValueMemberBOOL{Value: false},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

// cmtPathFor is the path a real row of this kind carries: a reply's is its own (never 0000), a
// reaction on a post is 0000.
func cmtPathFor(kind string) string {
	if kind == "reply" {
		return "0001"
	}
	return "0000"
}

// putManyReactions stores n reaction notifications on pid, in 25-row batches so a test that needs
// hundreds of rows does not hammer DynamoDB Local with one request each.
func putManyReactions(t *testing.T, recipient, actor, gid, pid string, n int) {
	t.Helper()
	var reqs []types.WriteRequest
	flush := func() {
		if len(reqs) == 0 {
			return
		}
		if _, err := rawDDB(t).BatchWriteItem(context.Background(), &dynamodb.BatchWriteItemInput{
			RequestItems: map[string][]types.WriteRequest{testTableName(): reqs},
		}); err != nil {
			t.Fatal(err)
		}
		reqs = nil
	}
	for i := 0; i < n; i++ {
		reqs = append(reqs, types.WriteRequest{PutRequest: &types.PutRequest{Item: map[string]types.AttributeValue{
			"PK": s("USER#" + recipient), "SK": s(reactSK(pid, i)), "Type": s("NOTIFICATION"),
			"Kind": s("reaction"), "ActorUserID": s(actor), "GroupID": s(gid), "PostID": s(pid),
			"CmtPath": s("0000"), "Read": &types.AttributeValueMemberBOOL{Value: false},
		}}})
		if len(reqs) == 25 {
			flush()
		}
	}
	flush()
}

func replySK(day string, n int) string {
	return "NOTIF#" + day + "#" + strings.Repeat("0", 31) + string(rune('a'+n))
}

// reactSK is a reaction notification's key for a reaction on pid: the placeholder, the post's day,
// then a hash stand-in.
func reactSK(pid string, n int) string {
	_, sk, _ := idgen.ParsePostID(pid)
	return "NOTIF#" + idgen.UndatedNotificationDay + "#" + strings.Split(sk, "#")[1] + "#" + hexN(n)
}

// hexN is a 32-character hex id that sorts by n.
func hexN(n int) string { return fmt.Sprintf("%032x", n) }

type listed struct {
	Notifications []notificationEntry `json:"notifications"`
	NextCursor    string              `json:"nextCursor"`
}

func getList(t *testing.T, h *Handler, c *http.Cookie, query string) listed {
	t.Helper()
	rec := doNotifications(t, h, c, http.MethodGet, "/api/notifications"+query, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var l listed
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func ids(l listed) []string {
	var out []string
	for _, n := range l.Notifications {
		out = append(out, n.ID)
	}
	return out
}

func equalIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// listFixture: owner's group with three posts of different days, bob as actor.
func listFixture(t *testing.T) (h *Handler, gid string, owner, bob registeredUser, ownerCookie *http.Cookie, pidOld, pidMid, pidNew string) {
	t.Helper()
	h, gid, owner, ownerCookie = postFixture(t)
	bob, _ = loggedInUser(t, h)
	addMember(t, gid, bob, "member")
	mk := func(sk string) string { storePostAt(t, gid, sk, owner.userID, 0); return pidOf(gid, sk) }
	pidOld = mk("POST#2026-10-01#00112233445566a1")
	pidMid = mk("POST#2026-10-15#00112233445566a2")
	pidNew = mk("POST#2026-10-28#00112233445566a3")
	return
}

func TestListNotificationsRepliesNewestFirstThenReactionsNewestPostFirst(t *testing.T) {
	h, gid, owner, bob, c, pOld, pMid, pNew := listFixture(t)
	putNotif(t, owner.userID, replySK("2026-10-20", 1), "reply", bob.userID, gid, pOld)
	putNotif(t, owner.userID, replySK("2026-10-25", 2), "reply", bob.userID, gid, pOld)
	putNotif(t, owner.userID, reactSK(pOld, 1), "reaction", bob.userID, gid, pOld)
	putNotif(t, owner.userID, reactSK(pNew, 2), "reaction", bob.userID, gid, pNew)
	putNotif(t, owner.userID, reactSK(pMid, 3), "reaction", bob.userID, gid, pMid)
	got := ids(getList(t, h, c, ""))
	want := []string{replySK("2026-10-25", 2), replySK("2026-10-20", 1), reactSK(pNew, 2), reactSK(pMid, 3), reactSK(pOld, 1)}
	if !equalIDs(got, want) {
		t.Fatalf("order:\n got %v\nwant %v", got, want)
	}
}

func TestListNotificationsDropsLeftGroupsAndGonePosts(t *testing.T) {
	h, gid, owner, bob, c, pOld, pMid, pNew := listFixture(t)
	deleted := pidOf(gid, "POST#2026-10-29#00112233445566a4")
	storePostAt(t, gid, "POST#2026-10-29#00112233445566a4", owner.userID, 0)
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:        aws.String(testTableName()),
		Key:              map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s("POST#2026-10-29#00112233445566a4")},
		UpdateExpression: aws.String("SET Deleted = :t"), ExpressionAttributeValues: map[string]types.AttributeValue{":t": &types.AttributeValueMemberBOOL{Value: true}},
	}); err != nil {
		t.Fatal(err)
	}
	missing := pidOf(gid, "POST#2026-10-30#00112233445566a5")
	expired := pidOf(gid, "POST#2026-10-31#00112233445566a7")
	storePostAt(t, gid, "POST#2026-10-31#00112233445566a7", owner.userID, 1) // TTL long past, row not yet swept
	putNotif(t, owner.userID, replySK("2026-10-24", 5), "reply", bob.userID, gid, expired)
	putNotif(t, owner.userID, reactSK(expired, 4), "reaction", bob.userID, gid, expired)
	// A group the owner is not in (never joined): its notification must not show.
	otherGid := "11111111-1111-4111-8111-111111111111"
	otherPid := pidOf(otherGid, "POST#2026-10-28#00112233445566a6")
	storePostAt(t, otherGid, "POST#2026-10-28#00112233445566a6", bob.userID, 0)

	putNotif(t, owner.userID, replySK("2026-10-20", 1), "reply", bob.userID, gid, pOld)
	putNotif(t, owner.userID, replySK("2026-10-21", 2), "reply", bob.userID, gid, deleted)
	putNotif(t, owner.userID, replySK("2026-10-22", 3), "reply", bob.userID, gid, missing)
	putNotif(t, owner.userID, replySK("2026-10-23", 4), "reply", bob.userID, otherGid, otherPid)
	putNotif(t, owner.userID, reactSK(pMid, 1), "reaction", bob.userID, gid, pMid)
	putNotif(t, owner.userID, reactSK(deleted, 2), "reaction", bob.userID, gid, deleted)
	putNotif(t, owner.userID, reactSK(otherPid, 3), "reaction", bob.userID, otherGid, otherPid)
	_ = pNew
	got := ids(getList(t, h, c, ""))
	want := []string{replySK("2026-10-20", 1), reactSK(pMid, 1)}
	if !equalIDs(got, want) {
		t.Fatalf("kept:\n got %v\nwant %v", got, want)
	}
}

func TestListNotificationsPagesThroughRepliesThenReactions(t *testing.T) {
	h, gid, owner, bob, c, pOld, pMid, pNew := listFixture(t)
	for i := 0; i < 3; i++ {
		putNotif(t, owner.userID, replySK("2026-10-2"+string(rune('0'+i)), i), "reply", bob.userID, gid, pOld)
	}
	putNotif(t, owner.userID, reactSK(pOld, 1), "reaction", bob.userID, gid, pOld)
	putNotif(t, owner.userID, reactSK(pNew, 2), "reaction", bob.userID, gid, pNew)
	putNotif(t, owner.userID, reactSK(pMid, 3), "reaction", bob.userID, gid, pMid)
	var all []string
	cursor, pages := "", 0
	for {
		q := "?limit=2"
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		l := getList(t, h, c, q)
		if len(l.Notifications) > 2 {
			t.Fatalf("page over limit: %d", len(l.Notifications))
		}
		all = append(all, ids(l)...)
		pages++
		if l.NextCursor == "" {
			break
		}
		cursor = l.NextCursor
		if pages > 10 {
			t.Fatal("cursor never ends")
		}
	}
	want := []string{replySK("2026-10-22", 2), replySK("2026-10-21", 1), replySK("2026-10-20", 0), reactSK(pNew, 2), reactSK(pMid, 3), reactSK(pOld, 1)}
	if !equalIDs(all, want) {
		t.Fatalf("paged:\n got %v\nwant %v", all, want)
	}
}

func TestListNotificationsAFullPageOfDroppedRowsDoesNotEndTheList(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, _ := listFixture(t)
	gone := pidOf(gid, "POST#2026-10-30#00112233445566a5")
	for i := 0; i < 4; i++ {
		putNotif(t, owner.userID, replySK("2026-10-3"+string(rune('0'+i)), i), "reply", bob.userID, gid, gone)
	}
	putNotif(t, owner.userID, replySK("2026-10-10", 5), "reply", bob.userID, gid, pOld)
	got := ids(getList(t, h, c, "?limit=2"))
	if !equalIDs(got, []string{replySK("2026-10-10", 5)}) {
		t.Fatalf("got %v", got)
	}
}

func TestListNotificationsOnlyShowsTheCallersOwn(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, _ := listFixture(t)
	putNotif(t, bob.userID, replySK("2026-10-20", 1), "reply", owner.userID, gid, pOld)
	if got := ids(getList(t, h, c, "")); len(got) != 0 {
		t.Fatalf("saw someone else's: %v", got)
	}
}

func TestListNotificationsRejectsBadInput(t *testing.T) {
	h, _, _, _, c, _, _, _ := listFixture(t)
	if rec := doNotifications(t, h, nil, http.MethodGet, "/api/notifications", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d", rec.Code)
	}
	for _, q := range []string{"?limit=0", "?limit=51", "?limit=x", "?cursor=zzz", "?cursor=r:" + replySK("2026-10-20", 1)} {
		if rec := doNotifications(t, h, c, http.MethodGet, "/api/notifications"+q, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", q, rec.Code)
		}
	}
}

func TestMarkNotificationsReadSetsReadOnlyTheCallersOwnNamedRows(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, _ := listFixture(t)
	a, b := replySK("2026-10-20", 1), replySK("2026-10-21", 2)
	putNotif(t, owner.userID, a, "reply", bob.userID, gid, pOld)
	putNotif(t, owner.userID, b, "reply", bob.userID, gid, pOld)
	putNotif(t, bob.userID, a, "reply", owner.userID, gid, pOld) // same sk, someone else's partition
	gone := replySK("2026-10-22", 3)
	if rec := doNotifications(t, h, c, http.MethodPut, "/api/notifications/read", map[string]any{"ids": []string{a, gone}}); rec.Code != http.StatusNoContent {
		t.Fatalf("mark: %d %s", rec.Code, rec.Body.String())
	}
	read := map[string]bool{}
	for _, n := range getList(t, h, c, "").Notifications {
		read[n.ID] = n.Read
	}
	if !read[a] || read[b] {
		t.Fatalf("read flags %v", read)
	}
	if len(read) != 2 {
		t.Fatalf("marking a missing id created a row: %v", read)
	}
	if rows := notificationsOf(t, owner.userID); len(rows) != 2 {
		t.Fatalf("owner has %d rows, want 2 (marking a missing id must not create one)", len(rows))
	}
	for _, it := range notificationsOf(t, bob.userID) {
		if r, _ := it["Read"].(*types.AttributeValueMemberBOOL); r == nil || r.Value {
			t.Fatalf("bob's row was marked read by the owner")
		}
	}
}

func TestMarkNotificationsReadRejectsBadInput(t *testing.T) {
	h, _, _, _, c, _, _, _ := listFixture(t)
	many := make([]string, 26)
	for i := range many {
		many[i] = replySK("2026-10-20", 0)
	}
	cases := map[string]any{"empty": map[string]any{"ids": []string{}}, "bad id": map[string]any{"ids": []string{"NOTIF#x"}}, "too many": map[string]any{"ids": many}}
	for name, body := range cases {
		if rec := doNotifications(t, h, c, http.MethodPut, "/api/notifications/read", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", name, rec.Code)
		}
	}
	if rec := doNotifications(t, h, nil, http.MethodPut, "/api/notifications/read", map[string]any{"ids": []string{replySK("2026-10-20", 0)}}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d", rec.Code)
	}
}

// A reaction's sort key is a valid cursor: the list is one range, so a page can end inside the
// reaction rows.
func TestListNotificationsPagesAcrossTheReactionRows(t *testing.T) {
	h, gid, owner, bob, c, pOld, pMid, pNew := listFixture(t)
	for i, pid := range []string{pOld, pNew, pMid} {
		putNotif(t, owner.userID, reactSK(pid, i), "reaction", bob.userID, gid, pid)
	}
	first := getList(t, h, c, "?limit=1")
	second := getList(t, h, c, "?limit=1&cursor="+first.NextCursor)
	third := getList(t, h, c, "?limit=1&cursor="+second.NextCursor)
	got := append(append(ids(first), ids(second)...), ids(third)...)
	want := []string{reactSK(pNew, 1), reactSK(pMid, 2), reactSK(pOld, 0)}
	if !equalIDs(got, want) || third.NextCursor != "" {
		t.Fatalf("got %v (end cursor %q), want %v", got, third.NextCursor, want)
	}
}

// Past 500 reaction rows the list is still newest post first: nothing is capped or sampled.
func TestListNotificationsNewestReactionIsFirstPastFiveHundredRows(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, pNew := listFixture(t)
	putManyReactions(t, owner.userID, bob.userID, gid, pOld, 520)
	newest := reactSK(pNew, 0)
	putNotif(t, owner.userID, newest, "reaction", bob.userID, gid, pNew)
	if got := ids(getList(t, h, c, "?limit=1")); !equalIDs(got, []string{newest}) {
		t.Fatalf("first row %v, want the newest post's reaction", got)
	}
}

// Many dropped rows in a row do not hide a live one behind them.
func TestListNotificationsFindsALiveRowBehindManyDroppedOnes(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, _ := listFixture(t)
	gone := pidOf(gid, "POST#2026-10-30#00112233445566a5")
	putManyReactions(t, owner.userID, bob.userID, gid, gone, 500)
	live := reactSK(pOld, 0)
	putNotif(t, owner.userID, live, "reaction", bob.userID, gid, pOld)
	if got := ids(getList(t, h, c, "")); !equalIDs(got, []string{live}) {
		t.Fatalf("got %v, want the live row", got)
	}
}

// More dropped rows than one request examines: the page comes back short with a cursor, and
// following it reaches the live row.
func TestListNotificationsContinuesPastTheExaminedBound(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, _ := listFixture(t)
	gone := pidOf(gid, "POST#2026-10-30#00112233445566a5")
	putManyReactions(t, owner.userID, bob.userID, gid, gone, notificationReadBatch*notificationMaxPasses+5)
	live := reactSK(pOld, 0)
	putNotif(t, owner.userID, live, "reaction", bob.userID, gid, pOld)
	first := getList(t, h, c, "")
	if len(first.Notifications) != 0 || first.NextCursor == "" {
		t.Fatalf("first page %v cursor %q: want short with a cursor", ids(first), first.NextCursor)
	}
	if got := ids(getList(t, h, c, "?cursor="+first.NextCursor)); !equalIDs(got, []string{live}) {
		t.Fatalf("second page %v, want the live row", got)
	}
}

// A row removed from before the cursor between pages does not make the next page skip one.
func TestListNotificationsDeletingAnEarlierRowDoesNotSkipOne(t *testing.T) {
	h, gid, owner, bob, c, pOld, pMid, pNew := listFixture(t)
	for _, pid := range []string{pNew, pMid, pOld} {
		putNotif(t, owner.userID, reactSK(pid, 1), "reaction", bob.userID, gid, pid)
	}
	first := getList(t, h, c, "?limit=1")
	if _, err := rawDDB(t).DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
		TableName: aws.String(testTableName()),
		Key:       map[string]types.AttributeValue{"PK": s("USER#" + owner.userID), "SK": s(first.Notifications[0].ID)},
	}); err != nil {
		t.Fatal(err)
	}
	if got := ids(getList(t, h, c, "?limit=1&cursor="+first.NextCursor)); !equalIDs(got, []string{reactSK(pMid, 1)}) {
		t.Fatalf("second page %v, want the second row", got)
	}
}

// A request that has used its time budget returns the page it has, short, with a cursor, instead of
// reading on: a long run of dropped rows must not outlast the Lambda timeout.
func TestListNotificationsStopsReadingPastItsTimeBudget(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, _ := listFixture(t)
	gone := pidOf(gid, "POST#2026-10-30#00112233445566a5")
	putManyReactions(t, owner.userID, bob.userID, gid, gone, 2*notificationReadBatch)
	live := reactSK(pOld, 0)
	putNotif(t, owner.userID, live, "reaction", bob.userID, gid, pOld)

	// The live row sorts after the 200 dropped ones (older post day). With a spent budget the first
	// request reads one batch and stops; following the cursors still reaches the row.
	old := notificationTimeBudget
	notificationTimeBudget = -1
	t.Cleanup(func() { notificationTimeBudget = old })
	first := getList(t, h, c, "")
	if len(first.Notifications) != 0 || first.NextCursor == "" {
		t.Fatalf("first page %v cursor %q: want short with a cursor after one batch", ids(first), first.NextCursor)
	}
	var got []string
	cursor := first.NextCursor
	for i := 0; cursor != "" && i < 10; i++ {
		l := getList(t, h, c, "?cursor="+cursor)
		got = append(got, ids(l)...)
		cursor = l.NextCursor
	}
	if !equalIDs(got, []string{live}) {
		t.Fatalf("following the cursors found %v, want the live row", got)
	}
}
