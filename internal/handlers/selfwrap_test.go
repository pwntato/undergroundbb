package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/models"
)

// A member of an Open group wraps the key their handoff row holds to their own
// new key (#62, slice 4d). Every member of such a group owes a row, because
// each one's entry point is wrapped to the key they rotated away from.

func selfWrapBody(gen int64) selfWrapRequest {
	return selfWrapRequest{
		Generation: gen,
		WrappedKey: wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
	}
}

func TestSelfWrapBringsAMembersEntryToTheNewKeyAndConsumesTheRow(t *testing.T) {
	h := noCooldown(t)
	owner, _ := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, loginCookie(t, h, owner))
	carol, carolCookie := loggedInUser(t, h)
	addMember(t, gid, carol, "member")

	// A plain member of an Open group cannot rotate without a row.
	rot := signedRotation(t, carol, rotateOpts{})
	if rec := doRotateKeys(t, h, carolCookie, rot.req); rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_required" {
		t.Fatalf("member without a row: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doPutHandoff(t, h, carolCookie, gid, handoffBody(rot.next.wrapPub, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	// The row names a key that is not yet the account's: nothing to self-wrap.
	if rec := doRotationCall(t, h, carolCookie, http.MethodPost, gid, "selfwrap", selfWrapBody(0)); rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_stale" {
		t.Fatalf("before the rotation: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRotateKeys(t, h, carolCookie, rot.req); rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	nextCookie := loginCookie(t, h, rot.next)
	if !handoffRowExists(t, carol.userID, gid) {
		t.Fatal("the rotation lost the member's row")
	}
	if wrapEpochOf(t, gid, carol.userID) == "1" {
		t.Fatal("the entry was already current before the self-wrap")
	}
	before := getRow(t, "GROUP#"+gid, "MEMBER#"+carol.userID)

	// The next rotation is refused while the row is waiting.
	if rec := doRotateKeys(t, h, nextCookie, signedRotation(t, rot.next, rotateOpts{epoch: 1, credVersion: 2}).req); rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_pending" {
		t.Fatalf("second rotation: %d %s", rec.Code, rec.Body.String())
	}

	if rec := doRotationCall(t, h, nextCookie, http.MethodPost, gid, "selfwrap", selfWrapBody(0)); rec.Code != http.StatusNoContent {
		t.Fatalf("selfwrap: %d %s", rec.Code, rec.Body.String())
	}
	if wrapEpochOf(t, gid, carol.userID) != "1" {
		t.Errorf("WrapEpoch = %s, want 1", wrapEpochOf(t, gid, carol.userID))
	}
	after := getRow(t, "GROUP#"+gid, "MEMBER#"+carol.userID)
	if fmt.Sprint(after["WrappedGroupKey"]) == fmt.Sprint(before["WrappedGroupKey"]) {
		t.Error("the entry still holds the old wrap")
	}
	if handoffRowExists(t, carol.userID, gid) {
		t.Error("the self-wrap left its row behind")
	}
	if memberGen(t, gid, carol) != "0" {
		t.Error("the self-wrap moved the generation of an Open group")
	}
	// Used once: the row is gone, so a replay is stale.
	if rec := doRotationCall(t, h, nextCookie, http.MethodPost, gid, "selfwrap", selfWrapBody(0)); rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_stale" {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSelfWrapRefusals(t *testing.T) {
	h := noCooldown(t)
	owner, ownerCookie := loggedInUser(t, h)
	open := createOpenGroup(t, h, owner, ownerCookie)
	private := createPrivateGroup(t, h, owner, ownerCookie)
	outsider := registerTestUser(t, h)
	next, nextCookie := rotateUser(t, h, owner, ownerCookie, open, private)

	for name, tc := range map[string]struct {
		cookie *http.Cookie
		gid    string
		body   selfWrapRequest
		status int
		code   string
	}{
		"a group that rotates": {nextCookie, private, selfWrapBody(0), http.StatusBadRequest, "rotation_not_applicable"},
		"not a member":         {loginCookie(t, h, outsider), open, selfWrapBody(0), http.StatusNotFound, ""},
		"another generation":   {nextCookie, open, selfWrapBody(1), http.StatusBadRequest, ""},
		"a malformed wrap":     {nextCookie, open, selfWrapRequest{Generation: 0}, http.StatusBadRequest, ""},
		"not a group id":       {nextCookie, "nope", selfWrapBody(0), http.StatusNotFound, ""},
		"no session":           {nil, open, selfWrapBody(0), http.StatusUnauthorized, ""},
	} {
		t.Run(name, func(t *testing.T) {
			rec := doRotationCall(t, h, tc.cookie, http.MethodPost, tc.gid, "selfwrap", tc.body)
			if rec.Code != tc.status || (tc.code != "" && errCode(t, rec) != tc.code) {
				t.Fatalf("%d %s, want %d %s", rec.Code, rec.Body.String(), tc.status, tc.code)
			}
		})
	}
	if !handoffRowExists(t, next.userID, open) || !handoffRowExists(t, next.userID, private) {
		t.Fatal("a refused self-wrap consumed a row")
	}
	if wrapEpochOf(t, open, owner.userID) == "1" {
		t.Fatal("a refused self-wrap changed the entry")
	}
}

func TestSelfWrapWithoutARowIsStale(t *testing.T) {
	h := noCooldown(t)
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	_, nextCookie := rotateUser(t, h, owner, ownerCookie, gid)
	if rec := doJSON(t, h, http.MethodDelete, "/api/account/rotation-handoff/"+gid, nextCookie, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	rec := doRotationCall(t, h, nextCookie, http.MethodPost, gid, "selfwrap", selfWrapBody(0))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_stale" {
		t.Fatalf("no row: %d %s", rec.Code, rec.Body.String())
	}
}

// Only a member of an Open group owes a row; a plain member of a Rotating one
// still waits for an admin and writes none.
func TestHandoffRowsFollowTheGroupKind(t *testing.T) {
	h := noCooldown(t)
	owner, ownerCookie := loggedInUser(t, h)
	open := createOpenGroup(t, h, owner, ownerCookie)
	private := createPrivateGroup(t, h, owner, ownerCookie)
	carol, carolCookie := loggedInUser(t, h)
	addMember(t, open, carol, "member")
	addMember(t, private, carol, "member")
	_, outsiderCookie := loggedInUser(t, h)

	rot := signedRotation(t, carol, rotateOpts{})
	rec := doRotateKeys(t, h, carolCookie, rot.req)
	if got := conflictGroups(t, rec); len(got) != 1 || got[0] != open {
		t.Fatalf("groups owed = %v, want only the Open group", got)
	}
	for name, tc := range map[string]struct {
		cookie *http.Cookie
		gid    string
	}{
		"a member of a Rotating group": {carolCookie, private},
		"a stranger to an Open group":  {outsiderCookie, open},
	} {
		if rec := doPutHandoff(t, h, tc.cookie, tc.gid, handoffBody(rot.next.wrapPub, 0)); rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_stale" {
			t.Errorf("%s: %d %s, want 409 handoff_stale", name, rec.Code, rec.Body.String())
		}
	}
	if rec := doPutHandoff(t, h, carolCookie, open, handoffBody(rot.next.wrapPub, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRotateKeys(t, h, carolCookie, rot.req); rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
}

// After a rotation commits, the sweep keeps a member's row for an Open group
// (it is how they get back in) and drops one for a Rotating group.
func TestSweepKeepsAMembersRowOnlyInAGroupWithNoRotation(t *testing.T) {
	h := noCooldown(t)
	owner, _ := loggedInUser(t, h)
	open := createOpenGroup(t, h, owner, loginCookie(t, h, owner))
	private := createPrivateGroup(t, h, owner, loginCookie(t, h, owner))
	carol, carolCookie := loggedInUser(t, h)
	addMember(t, open, carol, "admin")
	addMember(t, private, carol, "admin")
	rot := signedRotation(t, carol, rotateOpts{})
	for _, gid := range []string{open, private} {
		if rec := doPutHandoff(t, h, carolCookie, gid, handoffBody(rot.next.wrapPub, 0)); rec.Code != http.StatusNoContent {
			t.Fatalf("put %s: %d %s", gid, rec.Code, rec.Body.String())
		}
	}
	// Demoted by a co-admin after the rows were written.
	setMemberRole(t, open, carol.userID, "member")
	setMemberRole(t, private, carol.userID, "member")
	if rec := doRotateKeys(t, h, carolCookie, rot.req); rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	if !handoffRowExists(t, carol.userID, open) {
		t.Error("the sweep deleted a member's row for an Open group")
	}
	if handoffRowExists(t, carol.userID, private) {
		t.Error("the sweep kept a plain member's row for a Rotating group")
	}
}

// The transaction, not the handler, is what holds when something moves between
// the handler's reads and the commit.
func TestSelfWrapTransactionRefusesWhatHasMovedUnderIt(t *testing.T) {
	h := noCooldown(t)
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	next, _ := rotateUser(t, h, owner, ownerCookie, gid)
	current, err := h.db.GetUserByIDConsistent(t.Context(), owner.userID)
	if err != nil {
		t.Fatal(err)
	}
	good := db.SelfWrapInput{
		GroupID: gid, CallerUserID: owner.userID, Generation: 0,
		Wrapped:           models.WrappedKey{EphemeralPub: randBytes(32), Nonce: randBytes(12), Ciphertext: randBytes(48)},
		CallerKeyEpoch:    current.KeyEpoch,
		CallerWrappingKey: next.wrapPub,
	}
	for name, tc := range map[string]struct {
		mutate func(*db.SelfWrapInput)
		want   error
	}{
		"a key epoch that moved":      {func(in *db.SelfWrapInput) { in.CallerKeyEpoch++ }, db.ErrWrapEpochStale},
		"a key the row does not name": {func(in *db.SelfWrapInput) { in.CallerWrappingKey = randBytes(32) }, db.ErrHandoffStale},
		"another generation":          {func(in *db.SelfWrapInput) { in.Generation = 1 }, db.ErrHandoffStale},
		"a member who left":           {func(in *db.SelfWrapInput) { in.GroupID = "00000000-0000-4000-8000-000000000000" }, db.ErrHandoffStale},
	} {
		in := good
		tc.mutate(&in)
		if err := h.db.SelfWrap(t.Context(), in); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
		if !handoffRowExists(t, owner.userID, gid) || wrapEpochOf(t, gid, owner.userID) == "1" {
			t.Fatalf("%s: a refused self-wrap wrote something", name)
		}
	}
	if err := h.db.SelfWrap(t.Context(), good); err != nil {
		t.Fatalf("the untouched input: %v", err)
	}
}

// The row's generation and the entry's are separate conditions: each is the
// only thing standing when the other agrees with the request.
func TestSelfWrapTransactionChecksTheRowAndTheEntryGenerationSeparately(t *testing.T) {
	h := noCooldown(t)
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	next, _ := rotateUser(t, h, owner, ownerCookie, gid)
	in := db.SelfWrapInput{
		GroupID: gid, CallerUserID: owner.userID, Generation: 0,
		Wrapped:           models.WrappedKey{EphemeralPub: randBytes(32), Nonce: randBytes(12), Ciphertext: randBytes(48)},
		CallerKeyEpoch:    1,
		CallerWrappingKey: next.wrapPub,
	}
	setEntryGen := func(n int) {
		t.Helper()
		if _, err := rawDDB(t).UpdateItem(t.Context(), &dynamodb.UpdateItemInput{
			TableName: aws.String(testTableName()),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "GROUP#" + gid},
				"SK": &types.AttributeValueMemberS{Value: "MEMBER#" + owner.userID},
			},
			UpdateExpression:          aws.String("SET Generation = :v"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":v": &types.AttributeValueMemberN{Value: strconv.Itoa(n)}},
		}); err != nil {
			t.Fatal(err)
		}
	}

	// The row says generation 1 while the entry and the request say 0.
	setProfileAttr(t, owner.userID, "HANDOFF#"+gid, "Generation", 1)
	if err := h.db.SelfWrap(t.Context(), in); !errors.Is(err, db.ErrHandoffStale) {
		t.Errorf("a row at another generation: %v, want ErrHandoffStale", err)
	}
	// The row agrees with the request, the entry does not.
	setProfileAttr(t, owner.userID, "HANDOFF#"+gid, "Generation", 0)
	setEntryGen(1)
	if err := h.db.SelfWrap(t.Context(), in); !errors.Is(err, db.ErrHandoffStale) {
		t.Errorf("an entry at another generation: %v, want ErrHandoffStale", err)
	}
	if !handoffRowExists(t, owner.userID, gid) || wrapEpochOf(t, gid, owner.userID) == "1" {
		t.Fatal("a refused self-wrap wrote something")
	}
}

// The list tells the client which groups have no re-key, so it need not read
// every group to know which ones it owes a row for.
func TestListGroupsServesNoRotation(t *testing.T) {
	h := noCooldown(t)
	owner, cookie := loggedInUser(t, h)
	open := createOpenGroup(t, h, owner, cookie)
	public := createPublicGroup(t, h, owner, cookie)
	private := createPrivateGroup(t, h, owner, cookie)
	var list listGroupsResponse
	if rec := doJSON(t, h, http.MethodGet, "/api/groups", cookie, nil); rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	got := map[string]bool{}
	for _, g := range list.Groups {
		got[g.GroupID] = g.NoRotation
	}
	want := map[string]bool{open: true, public: true, private: false}
	if len(got) != len(want) {
		t.Fatalf("groups = %v, want %v", got, want)
	}
	for gid, w := range want {
		if got[gid] != w {
			t.Errorf("group %s: noRotation = %v, want %v", gid, got[gid], w)
		}
	}
}
