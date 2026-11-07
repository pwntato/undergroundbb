package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type unreadEntry struct {
	GroupID    string `json:"groupId"`
	Unread     int    `json:"unread"`
	UnreadMore bool   `json:"unreadMore"`
}

func unreadByGroup(t *testing.T, h *Handler, c *http.Cookie) map[string]unreadEntry {
	t.Helper()
	rec := doListGroups(t, h, c)
	if rec.Code != http.StatusOK {
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
	if g := got[gid]; g.Unread != 3 || g.UnreadMore {
		t.Fatalf("group 1: %+v, want 3 unread, not more", g)
	}
	if g := got[gid2]; g.Unread != 1 || g.UnreadMore {
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
	if g.Unread != maxUnreadShown || !g.UnreadMore {
		t.Fatalf("%+v, want %d and more", g, maxUnreadShown)
	}

	// Exactly 99 is a full count, not a lower bound.
	h2, gid2, owner2, bob2, c2, p2, _, _ := listFixture(t)
	putManyReactions(t, owner2.userID, bob2.userID, gid2, p2, maxUnreadShown)
	g = unreadByGroup(t, h2, c2)[gid2]
	if g.Unread != maxUnreadShown || g.UnreadMore {
		t.Fatalf("%+v, want exactly %d and not more", g, maxUnreadShown)
	}
}

func TestListGroupsUnreadIsALowerBoundWhenTheReadRunsOutOfBudget(t *testing.T) {
	h, gid, owner, bob, c, pOld, _, _ := listFixture(t)
	gone := pidOf(gid, "POST#2026-10-30#00112233445566a5")
	putManyReactions(t, owner.userID, bob.userID, gid, gone, 2*notificationReadBatch)
	putNotif(t, owner.userID, reactSK(pOld, 0), "reaction", bob.userID, gid, pOld)

	old := notificationTimeBudget
	notificationTimeBudget = -1
	t.Cleanup(func() { notificationTimeBudget = old })
	g := unreadByGroup(t, h, c)[gid]
	if !g.UnreadMore {
		t.Fatalf("%+v, want unreadMore when the read stopped before the end", g)
	}
}

func TestListGroupsUnreadIsZeroWithoutNotifications(t *testing.T) {
	h, gid, _, _, c, _, _, _ := listFixture(t)
	if g := unreadByGroup(t, h, c)[gid]; g.Unread != 0 || g.UnreadMore {
		t.Fatalf("%+v, want 0", g)
	}
}
