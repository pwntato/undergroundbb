package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
)

// notificationsOf reads every NOTIF# row in the user's partition.
func notificationsOf(t *testing.T, userID string) []map[string]types.AttributeValue {
	t.Helper()
	out, err := rawDDB(t).Query(context.Background(), &dynamodb.QueryInput{
		TableName:                 aws.String(testTableName()),
		ConsistentRead:            aws.Bool(true),
		KeyConditionExpression:    aws.String("PK = :p AND begins_with(SK, :n)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": s("USER#" + userID), ":n": s("NOTIF#")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.Items
}

// notifFixture is a group whose owner wrote a post, with two more members, bob and carol.
func notifFixture(t *testing.T, ttl int64) (h *Handler, gid, pid string, owner, bob, carol registeredUser, ownerCookie, bobCookie, carolCookie *http.Cookie) {
	t.Helper()
	h, gid, owner, ownerCookie = postFixture(t)
	bob, bobCookie = loggedInUser(t, h)
	carol, carolCookie = loggedInUser(t, h)
	addMember(t, gid, bob, "member")
	addMember(t, gid, carol, "member")
	postKey := "POST#2026-10-28#00112233445566d1"
	storePostAt(t, gid, postKey, owner.userID, ttl)
	return h, gid, pidOf(gid, postKey), owner, bob, carol, ownerCookie, bobCookie, carolCookie
}

var notifSortKeyPattern = regexp.MustCompile(`^NOTIF#\d{4}-\d{2}-\d{2}#[0-9a-f]{32}$`)

func TestACommentOnSomeonesPostNotifiesItsAuthorWithIdentifiersOnly(t *testing.T) {
	future := time.Now().Add(72 * time.Hour).Unix()
	h, gid, pid, owner, bob, _, _, bobCookie, _ := notifFixture(t, future)
	if rec := doComment(t, h, bobCookie, pid, signedComment(t, gid, bob, copts{})); rec.Code != http.StatusCreated {
		t.Fatalf("comment: %d %s", rec.Code, rec.Body.String())
	}
	got := notificationsOf(t, owner.userID)
	if len(got) != 1 {
		t.Fatalf("owner has %d notifications, want 1", len(got))
	}
	n := got[0]
	if !notifSortKeyPattern.MatchString(strAttr(n, "SK")) {
		t.Errorf("sort key %q is not NOTIF#<day>#<32 hex>", strAttr(n, "SK"))
	}
	if strAttr(n, "SK")[len("NOTIF#"):len("NOTIF#2006-01-02")] != time.Now().UTC().Format("2006-01-02") {
		t.Errorf("sort key day %q is not today (UTC)", strAttr(n, "SK"))
	}
	want := map[string]string{"Kind": "reply", "ActorUserID": bob.userID, "GroupID": gid, "PostID": pid, "CmtPath": "0001"}
	for k, v := range want {
		if strAttr(n, k) != v {
			t.Errorf("%s = %q, want %q", k, strAttr(n, k), v)
		}
	}
	if r, ok := n["Read"].(*types.AttributeValueMemberBOOL); !ok || r.Value {
		t.Errorf("Read = %v, want an explicit false", n["Read"])
	}
	if numAttr(n, "TTL") != strconv.FormatInt(future, 10) {
		t.Errorf("TTL = %s, want the post's %d", numAttr(n, "TTL"), future)
	}
	// Identifiers and nothing else: no text, no time.
	for name := range n {
		switch name {
		case "PK", "SK", "Type", "Kind", "ActorUserID", "GroupID", "PostID", "CmtPath", "Read", "TTL":
		default:
			t.Errorf("unexpected attribute %q on a notification", name)
		}
	}
}

func TestANotificationOnAPostThatNeverExpiresHasNoTTL(t *testing.T) {
	h, gid, pid, owner, bob, _, _, bobCookie, _ := notifFixture(t, 0)
	if rec := doComment(t, h, bobCookie, pid, signedComment(t, gid, bob, copts{})); rec.Code != http.StatusCreated {
		t.Fatalf("comment: %d", rec.Code)
	}
	got := notificationsOf(t, owner.userID)
	if len(got) != 1 {
		t.Fatalf("owner has %d notifications, want 1", len(got))
	}
	if _, has := got[0]["TTL"]; has {
		t.Error("a notification about a post with no expiry carries a TTL")
	}
}

func TestAReplyNotifiesTheParentsAuthorAndNotThePostsAuthor(t *testing.T) {
	h, gid, pid, owner, bob, carol, _, bobCookie, carolCookie := notifFixture(t, 0)
	if rec := doComment(t, h, bobCookie, pid, signedComment(t, gid, bob, copts{})); rec.Code != http.StatusCreated {
		t.Fatalf("bob: %d", rec.Code)
	}
	if rec := doComment(t, h, carolCookie, pid, signedComment(t, gid, carol, copts{path: "0001.0001"})); rec.Code != http.StatusCreated {
		t.Fatalf("carol: %d %s", rec.Code, rec.Body.String())
	}
	if got := notificationsOf(t, owner.userID); len(got) != 1 {
		t.Errorf("owner has %d notifications, want only bob's top-level one", len(got))
	}
	got := notificationsOf(t, bob.userID)
	if len(got) != 1 {
		t.Fatalf("bob has %d notifications, want 1", len(got))
	}
	if strAttr(got[0], "ActorUserID") != carol.userID || strAttr(got[0], "CmtPath") != "0001.0001" || strAttr(got[0], "Kind") != "reply" {
		t.Errorf("notification = %v", got[0])
	}
	if got := notificationsOf(t, carol.userID); len(got) != 0 {
		t.Errorf("carol was told of her own reply: %v", got)
	}
}

func TestNobodyIsNotifiedOfTheirOwnActivity(t *testing.T) {
	h, gid, pid, owner, _, _, ownerCookie, _, _ := notifFixture(t, 0)
	if rec := doComment(t, h, ownerCookie, pid, signedComment(t, gid, owner, copts{})); rec.Code != http.StatusCreated {
		t.Fatalf("comment: %d", rec.Code)
	}
	if rec := doComment(t, h, ownerCookie, pid, signedComment(t, gid, owner, copts{path: "0001.0001"})); rec.Code != http.StatusCreated {
		t.Fatalf("self reply: %d", rec.Code)
	}
	if rec := doReaction(t, h, http.MethodPut, ownerCookie, pid, "0001", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("self reaction: %d", rec.Code)
	}
	if got := notificationsOf(t, owner.userID); len(got) != 0 {
		t.Errorf("owner was told of their own activity: %v", got)
	}
}

func TestAResentCommentNotifiesOnce(t *testing.T) {
	h, gid, pid, owner, bob, _, _, bobCookie, _ := notifFixture(t, 0)
	req := signedComment(t, gid, bob, copts{})
	for i := 0; i < 3; i++ {
		if rec := doComment(t, h, bobCookie, pid, req); rec.Code != http.StatusCreated {
			t.Fatalf("send %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	if got := notificationsOf(t, owner.userID); len(got) != 1 {
		t.Errorf("owner has %d notifications after a resend, want 1", len(got))
	}
}

func TestACommentRefusedWritesNoNotification(t *testing.T) {
	h, gid, pid, owner, bob, _, _, bobCookie, _ := notifFixture(t, 0)
	// Skips a number: refused before the write.
	if rec := doComment(t, h, bobCookie, pid, signedComment(t, gid, bob, copts{path: "0002"})); rec.Code == http.StatusCreated {
		t.Fatal("a comment that skips a number was accepted")
	}
	if got := notificationsOf(t, owner.userID); len(got) != 0 {
		t.Errorf("a refused comment left %d notifications", len(got))
	}
}

func TestNobodyWhoHasLeftTheGroupIsNotified(t *testing.T) {
	h, gid, pid, owner, bob, _, _, bobCookie, _ := notifFixture(t, 0)
	if _, err := rawDDB(t).DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
		TableName: aws.String(testTableName()),
		Key:       map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s("MEMBER#" + owner.userID)},
	}); err != nil {
		t.Fatal(err)
	}
	if rec := doComment(t, h, bobCookie, pid, signedComment(t, gid, bob, copts{})); rec.Code != http.StatusCreated {
		t.Fatalf("comment: %d %s", rec.Code, rec.Body.String())
	}
	if got := notificationsOf(t, owner.userID); len(got) != 0 {
		t.Errorf("a non-member was notified: %v", got)
	}
}

func TestAReactionNotifiesTheAuthorOfWhatItIsOnOnceWhateverTheEmoji(t *testing.T) {
	future := time.Now().Add(72 * time.Hour).Unix()
	h, gid, pid, owner, bob, carol, _, bobCookie, carolCookie := notifFixture(t, future)
	storeCommentAt(t, pid, "0001", carol.userID, future)
	// On the post: the post's author. On the comment: the comment's author.
	for _, c := range []struct {
		target string
		cookie *http.Cookie
		who    registeredUser
	}{{"0000", bobCookie, owner}, {"0001", bobCookie, carol}} {
		for i := 0; i < 3; i++ {
			if rec := doReaction(t, h, http.MethodPut, c.cookie, pid, c.target, sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
				t.Fatalf("react %s #%d: %d %s", c.target, i, rec.Code, rec.Body.String())
			}
		}
		got := notificationsOf(t, c.who.userID)
		if len(got) != 1 {
			t.Fatalf("target %s: %d notifications for %s, want 1 (a new emoji or a resend must not notify again)", c.target, len(got), c.who.userID)
		}
		n := got[0]
		want := map[string]string{"Kind": "reaction", "ActorUserID": bob.userID, "GroupID": gid, "PostID": pid, "CmtPath": c.target}
		for k, v := range want {
			if strAttr(n, k) != v {
				t.Errorf("target %s: %s = %q, want %q", c.target, k, strAttr(n, k), v)
			}
		}
		// The post's TTL, copied: a reaction's notification must not say when it was made.
		if numAttr(n, "TTL") != strconv.FormatInt(future, 10) {
			t.Errorf("target %s: TTL = %s, want the post's %d", c.target, numAttr(n, "TTL"), future)
		}
		// And no day: a reaction is the one item the schema keeps undated.
		if !regexp.MustCompile(`^NOTIF#0000-00-00#[0-9a-f]{32}$`).MatchString(strAttr(n, "SK")) {
			t.Errorf("target %s: sort key %q carries a real day or the wrong shape", c.target, strAttr(n, "SK"))
		}
	}
	// Taking it back takes the notification with it; giving it again starts a new, unread one.
	if rec := doReaction(t, h, http.MethodDelete, bobCookie, pid, "0001", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("unreact: %d", rec.Code)
	}
	if got := notificationsOf(t, carol.userID); len(got) != 0 {
		t.Errorf("after taking the reaction back carol still has %d notifications: %v", len(got), got)
	}
	if got := notificationsOf(t, owner.userID); len(got) != 1 {
		t.Errorf("taking back the comment reaction touched the owner's notification (%d left, want 1)", len(got))
	}
	if rec := doReaction(t, h, http.MethodPut, bobCookie, pid, "0001", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("react again: %d", rec.Code)
	}
	if got := notificationsOf(t, carol.userID); len(got) != 1 {
		t.Errorf("after undo and react again carol has %d notifications, want 1", len(got))
	}
	// A second reactor is a second notification.
	if rec := doReaction(t, h, http.MethodPut, carolCookie, pid, "0000", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("carol reacts: %d", rec.Code)
	}
	if got := notificationsOf(t, owner.userID); len(got) != 2 {
		t.Errorf("owner has %d notifications after a second reactor, want 2", len(got))
	}
}

func TestNobodyWhoHasLeftTheGroupIsNotifiedOfAReaction(t *testing.T) {
	h, gid, pid, owner, _, _, _, bobCookie, _ := notifFixture(t, 0)
	if _, err := rawDDB(t).DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
		TableName: aws.String(testTableName()),
		Key:       map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s("MEMBER#" + owner.userID)},
	}); err != nil {
		t.Fatal(err)
	}
	if rec := doReaction(t, h, http.MethodPut, bobCookie, pid, "0000", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("react: %d %s", rec.Code, rec.Body.String())
	}
	if got := notificationsOf(t, owner.userID); len(got) != 0 {
		t.Errorf("a non-member was notified of a reaction: %v", got)
	}
}

// Deleting an account clears the notifications it was sent: each names who interacted with the
// person, in which group and on what day, and one about a post that never expires would otherwise
// stay for good.
func TestDeletingAnAccountRemovesItsNotifications(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenPrivateGroup(t, h, owner, ownerCookie)
	bob, bobCookie := loggedInUser(t, h)
	addMember(t, gid, bob, "member")
	postKey := "POST#2026-10-28#00112233445566d2"
	storePostAt(t, gid, postKey, bob.userID, 0)
	pid := pidOf(gid, postKey)
	if rec := doComment(t, h, ownerCookie, pid, signedComment(t, gid, owner, copts{})); rec.Code != http.StatusCreated {
		t.Fatalf("comment: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReaction(t, h, http.MethodPut, ownerCookie, pid, "0000", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("react: %d", rec.Code)
	}
	if got := notificationsOf(t, bob.userID); len(got) != 2 {
		t.Fatalf("bob has %d notifications before deleting, want 2", len(got))
	}
	if rec := doLeave(t, h, bobCookie, gid); rec.Code != http.StatusOK {
		t.Fatalf("leave: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doDeleteAccount(t, h, bobCookie); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if got := notificationsOf(t, bob.userID); len(got) != 0 {
		t.Errorf("%d notifications survived account deletion: %v", len(got), got)
	}
}

func TestAReactionToAGoneCommentIsRefusedAndWritesNoNotification(t *testing.T) {
	h, _, pid, owner, _, _, _, bobCookie, _ := notifFixture(t, 0)
	if rec := doReaction(t, h, http.MethodPut, bobCookie, pid, "0007", sealedReaction(t, 0)); rec.Code != http.StatusConflict {
		t.Fatalf("react to a comment that is not there: %d %s", rec.Code, rec.Body.String())
	}
	if got := notificationsOf(t, owner.userID); len(got) != 0 {
		t.Errorf("a refused reaction left %d notifications", len(got))
	}
}

func TestReactingAndTakingBackInALoopLeavesNoNotificationsAndAChangedEmojiKeepsItsReadFlag(t *testing.T) {
	h, _, pid, owner, _, _, _, bobCookie, _ := notifFixture(t, 0)
	for i := 0; i < 5; i++ {
		if rec := doReaction(t, h, http.MethodPut, bobCookie, pid, "0000", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
			t.Fatalf("react %d: %d", i, rec.Code)
		}
		if got := notificationsOf(t, owner.userID); len(got) != 1 {
			t.Fatalf("cycle %d: %d notifications, want 1", i, len(got))
		}
		if rec := doReaction(t, h, http.MethodDelete, bobCookie, pid, "0000", nil); rec.Code != http.StatusNoContent {
			t.Fatalf("unreact %d: %d", i, rec.Code)
		}
		if got := notificationsOf(t, owner.userID); len(got) != 0 {
			t.Fatalf("cycle %d: %d notifications left after taking it back", i, len(got))
		}
	}
	// The recipient reads it; a different emoji must not make it unread again.
	if rec := doReaction(t, h, http.MethodPut, bobCookie, pid, "0000", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("react: %d", rec.Code)
	}
	row := notificationsOf(t, owner.userID)[0]
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:                 aws.String(testTableName()),
		Key:                       map[string]types.AttributeValue{"PK": row["PK"], "SK": row["SK"]},
		UpdateExpression:          aws.String("SET #r = :t"),
		ExpressionAttributeNames:  map[string]string{"#r": "Read"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":t": &types.AttributeValueMemberBOOL{Value: true}},
	}); err != nil {
		t.Fatal(err)
	}
	if rec := doReaction(t, h, http.MethodPut, bobCookie, pid, "0000", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("react with another emoji: %d", rec.Code)
	}
	got := notificationsOf(t, owner.userID)
	if len(got) != 1 {
		t.Fatalf("%d notifications after a changed emoji, want 1", len(got))
	}
	if r, ok := got[0]["Read"].(*types.AttributeValueMemberBOOL); !ok || !r.Value {
		t.Errorf("a changed emoji made the notification unread again: %v", got[0]["Read"])
	}
}

func TestTakingBackAReactionAfterTheRecipientLeftStillRemovesItsNotification(t *testing.T) {
	h, gid, pid, owner, _, _, _, bobCookie, _ := notifFixture(t, 0)
	if rec := doReaction(t, h, http.MethodPut, bobCookie, pid, "0000", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("react: %d", rec.Code)
	}
	if _, err := rawDDB(t).DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
		TableName: aws.String(testTableName()),
		Key:       map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s("MEMBER#" + owner.userID)},
	}); err != nil {
		t.Fatal(err)
	}
	if rec := doReaction(t, h, http.MethodDelete, bobCookie, pid, "0000", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("unreact: %d", rec.Code)
	}
	if got := notificationsOf(t, owner.userID); len(got) != 0 {
		t.Errorf("the notification of a taken-back reaction survived its recipient leaving: %v", got)
	}
}

func doDeleteComment(t *testing.T, h *Handler, cookie *http.Cookie, pid, path string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/posts/"+url.PathEscape(pid)+"/comments/"+path, nil)
	req.AddCookie(cookie)
	mux.ServeHTTP(rec, req)
	return rec
}

// Deleting a comment removes what it sent (the notification to whoever it answered) and what its
// reactions sent its author, and nothing else; an admin deleting it clears the same rows, and
// deleting a tombstone again is harmless.
func TestDeletingACommentRemovesItsNotificationsAndTheOnesItsReactionsSent(t *testing.T) {
	h, gid, pid, owner, bob, carol, ownerCookie, bobCookie, carolCookie := notifFixture(t, 0)
	// bob answers the post; carol answers bob; carol reacts to bob's comment and to the post.
	if rec := doComment(t, h, bobCookie, pid, signedComment(t, gid, bob, copts{})); rec.Code != http.StatusCreated {
		t.Fatalf("bob: %d", rec.Code)
	}
	if rec := doComment(t, h, carolCookie, pid, signedComment(t, gid, carol, copts{path: "0001.0001"})); rec.Code != http.StatusCreated {
		t.Fatalf("carol: %d", rec.Code)
	}
	if rec := doComment(t, h, carolCookie, pid, signedComment(t, gid, carol, copts{path: "0002"})); rec.Code != http.StatusCreated {
		t.Fatalf("carol second: %d", rec.Code)
	}
	for _, target := range []string{"0001", "0000"} {
		if rec := doReaction(t, h, http.MethodPut, carolCookie, pid, target, sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
			t.Fatalf("react %s: %d", target, rec.Code)
		}
	}
	// owner: bob's top-level comment, carol's top-level comment, carol's reaction to the post.
	// bob: carol's reply, carol's reaction to his comment.
	if got := notificationsOf(t, owner.userID); len(got) != 3 {
		t.Fatalf("owner has %d notifications, want 3", len(got))
	}
	if got := notificationsOf(t, bob.userID); len(got) != 2 {
		t.Fatalf("bob has %d notifications, want 2", len(got))
	}
	// The admin (owner) deletes bob's comment: the one it sent the owner goes, and so does the one
	// carol's reaction to it sent bob. carol's reply to it was addressed to bob and stays (it is
	// carol's comment, still there).
	if rec := doDeleteComment(t, h, ownerCookie, pid, "0001"); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	ownerRows := notificationsOf(t, owner.userID)
	if len(ownerRows) != 2 {
		t.Fatalf("owner has %d notifications after the delete, want 2 (carol's comment and carol's reaction to the post)", len(ownerRows))
	}
	for _, n := range ownerRows {
		if strAttr(n, "Kind") == "reply" && strAttr(n, "CmtPath") == "0001" {
			t.Errorf("the notification bob's deleted comment sent survived: %v", n)
		}
	}
	bobRows := notificationsOf(t, bob.userID)
	if len(bobRows) != 1 || strAttr(bobRows[0], "Kind") != "reply" || strAttr(bobRows[0], "CmtPath") != "0001.0001" {
		t.Errorf("bob's notifications after the delete = %v, want only carol's reply", bobRows)
	}
	// Again: a tombstone deleted twice is the same.
	if rec := doDeleteComment(t, h, ownerCookie, pid, "0001"); rec.Code != http.StatusNoContent {
		t.Fatalf("delete again: %d", rec.Code)
	}
	if got := notificationsOf(t, owner.userID); len(got) != 2 {
		t.Errorf("a second delete changed the owner's notifications: %d", len(got))
	}
	// A reply is deleted by its author: its notification to bob goes.
	if rec := doDeleteComment(t, h, carolCookie, pid, "0001.0001"); rec.Code != http.StatusNoContent {
		t.Fatalf("delete reply: %d %s", rec.Code, rec.Body.String())
	}
	if got := notificationsOf(t, bob.userID); len(got) != 0 {
		t.Errorf("bob still has %d notifications after the reply was deleted: %v", len(got), got)
	}
}

// Deleting a post removes the notifications its own reactions sent the author.
func TestDeletingAPostRemovesTheNotificationsOfItsReactions(t *testing.T) {
	h, _, pid, owner, _, _, ownerCookie, bobCookie, _ := notifFixture(t, 0)
	if rec := doReaction(t, h, http.MethodPut, bobCookie, pid, "0000", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("react: %d", rec.Code)
	}
	if got := notificationsOf(t, owner.userID); len(got) != 1 {
		t.Fatalf("owner has %d notifications, want 1", len(got))
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/posts/"+url.PathEscape(pid), nil)
	req.AddCookie(ownerCookie)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete post: %d %s", rec.Code, rec.Body.String())
	}
	if got := notificationsOf(t, owner.userID); len(got) != 0 {
		t.Errorf("%d notifications of a deleted post's reactions survived: %v", len(got), got)
	}
}

// One notification per reactor, target and post: the same person reacting to two things of the
// same author, or to two posts of theirs, is two notifications, and taking one back leaves the other.
func TestReactionNotificationsAreKeyedByPostTargetAndReactor(t *testing.T) {
	h, gid, pid, owner, _, _, _, bobCookie, carolCookie := notifFixture(t, 0)
	storeCommentAt(t, pid, "0001", owner.userID, 0)
	otherKey := "POST#2026-10-28#00112233445566d3"
	storePostAt(t, gid, otherKey, owner.userID, 0)
	otherPid := pidOf(gid, otherKey)
	react := func(cookie *http.Cookie, p, target string) {
		t.Helper()
		if rec := doReaction(t, h, http.MethodPut, cookie, p, target, sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
			t.Fatalf("react %s %s: %d", p, target, rec.Code)
		}
	}
	react(bobCookie, pid, "0000")      // the post
	react(bobCookie, pid, "0001")      // a comment of the same author on the same post
	react(bobCookie, otherPid, "0000") // another post of the same author
	react(carolCookie, pid, "0000")    // another reactor
	if got := notificationsOf(t, owner.userID); len(got) != 4 {
		t.Fatalf("owner has %d notifications, want 4 (post, comment, other post, other reactor)", len(got))
	}
	if rec := doReaction(t, h, http.MethodDelete, bobCookie, pid, "0001", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("unreact: %d", rec.Code)
	}
	if got := notificationsOf(t, owner.userID); len(got) != 3 {
		t.Errorf("taking back one reaction left %d notifications, want 3", len(got))
	}
}
