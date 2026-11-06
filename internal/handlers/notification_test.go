package handlers

import (
	"context"
	"net/http"
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
	// Taking it back and reacting again is a new reaction.
	if rec := doReaction(t, h, http.MethodDelete, bobCookie, pid, "0001", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("unreact: %d", rec.Code)
	}
	if rec := doReaction(t, h, http.MethodPut, bobCookie, pid, "0001", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("react again: %d", rec.Code)
	}
	if got := notificationsOf(t, carol.userID); len(got) != 2 {
		t.Errorf("after undo and react again carol has %d notifications, want 2", len(got))
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
