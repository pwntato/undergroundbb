package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

func doPostAt(t *testing.T, h *Handler, method string, cookie *http.Cookie, pid string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, "/api/posts/"+url.PathEscape(pid), &buf)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

// postEdit builds an edit of the post at pid, signed as a real client signs it:
// over the post's own sort key and signedDay.
func postEdit(t *testing.T, pid string, signer registeredUser, signedDay string, nonce, ct []byte) editPostRequest {
	t.Helper()
	gid, sortKey, _ := idgen.ParsePostID(pid)
	payload := crypto.SignedPayload(signer.userID, gid, sortKey, 0, signedDay, ct)
	sig, err := crypto.Sign(signer.signPriv, crypto.ContextPost, payload)
	if err != nil {
		t.Fatal(err)
	}
	return editPostRequest{
		Generation: 0, SignedDay: signedDay,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
		Signature:  base64.StdEncoding.EncodeToString(sig),
	}
}

func today() string { return time.Now().UTC().Format("2006-01-02") }

func postRow(t *testing.T, pid string) map[string]types.AttributeValue {
	t.Helper()
	gid, sortKey, _ := idgen.ParsePostID(pid)
	return getRow(t, "GROUP#"+gid, sortKey)
}

func TestEditPostReplacesTheSealedTextAndRecordsTheDayItWasSigned(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	before := postRow(t, pid)
	req := postEdit(t, pid, owner, today(), nonceOf(7), ctOf(7))
	if rec := doPostAt(t, h, http.MethodPut, cookie, pid, req); rec.Code != http.StatusOK {
		t.Fatalf("edit: %d %s", rec.Code, rec.Body.String())
	}
	after := postRow(t, pid)
	for _, attr := range []string{"PK", "SK", "AuthorUserID", "TTL"} {
		if fmt.Sprint(before[attr]) != fmt.Sprint(after[attr]) {
			t.Errorf("%s changed: %v -> %v", attr, before[attr], after[attr])
		}
	}
	if rowHas(before, "SignedDay") {
		t.Error("a post that was never edited carries a SignedDay")
	}
	list := decodeList(t, doListPosts(t, h, cookie, gid, ""))
	if len(list.Posts) != 1 || list.Posts[0].Ciphertext != req.Ciphertext || list.Posts[0].Nonce != req.Nonce ||
		list.Posts[0].Signature != req.Signature || list.Posts[0].SignedDay != today() {
		t.Fatalf("the list does not serve the edit and its day: %+v", list.Posts)
	}
}

func TestEditPostRefusesWhatItShould(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	other, otherCookie := loggedInUser(t, h)
	addMember(t, gid, other, "member")
	_, outsiderCookie := loggedInUser(t, h)
	// A second post by the other member, and a deleted one by the owner.
	otherReq, _ := signedPost(t, gid, other, postOpts{})
	if rec := doPost(t, h, otherCookie, gid, otherReq); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body.String())
	}
	otherPid := pidOf(gid, otherReq.SortKey)
	goneReq, _ := signedPost(t, gid, owner, postOpts{sortKey: "POST#" + time.Now().UTC().Format("2006-01-02") + "#00112233445566aa"})
	if rec := doPost(t, h, cookie, gid, goneReq); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body.String())
	}
	gonePid := pidOf(gid, goneReq.SortKey)
	if rec := doPostAt(t, h, http.MethodDelete, cookie, gonePid, nil); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Body.String())
	}
	stored := postRow(t, pid)["Nonce"].(*types.AttributeValueMemberB).Value
	reused := postEdit(t, pid, owner, today(), stored, ctOf(9))

	cases := []struct {
		name   string
		cookie *http.Cookie
		pid    string
		body   editPostRequest
		status int
		want   string
	}{
		{"another member", otherCookie, pid, postEdit(t, pid, other, today(), nonceOf(1), ctOf(1)), 403, ""},
		{"an admin who is not the author", cookie, otherPid, postEdit(t, otherPid, owner, today(), nonceOf(1), ctOf(1)), 403, ""},
		{"a tombstone", cookie, gonePid, postEdit(t, gonePid, owner, today(), nonceOf(1), ctOf(1)), 409, `"post_gone"`},
		{"signed by someone else", cookie, pid, postEdit(t, pid, other, today(), nonceOf(1), ctOf(1)), 400, `"bad_signature"`},
		{"signed for another post", cookie, pid, postEdit(t, otherPid, owner, today(), nonceOf(1), ctOf(1)), 400, `"bad_signature"`},
		{"signed on a far day", cookie, pid, postEdit(t, pid, owner, "2020-01-01", nonceOf(1), ctOf(1)), 400, "signedDay: not within tolerance"},
		{"signed on a malformed day", cookie, pid, postEdit(t, pid, owner, "yesterday", nonceOf(1), ctOf(1)), 400, "signedDay: must be a UTC date"},
		{"the stored nonce over other text", cookie, pid, reused, 400, `"nonce_reused"`},
		{"not a member", outsiderCookie, pid, postEdit(t, pid, owner, today(), nonceOf(1), ctOf(1)), 404, ""},
		{"no session", nil, pid, postEdit(t, pid, owner, today(), nonceOf(1), ctOf(1)), 401, ""},
		{"a malformed post id", cookie, "nope", postEdit(t, pid, owner, today(), nonceOf(1), ctOf(1)), 404, ""},
	}
	for _, tc := range cases {
		rec := doPostAt(t, h, http.MethodPut, tc.cookie, tc.pid, tc.body)
		if rec.Code != tc.status {
			t.Errorf("%s: status %d, want %d: %s", tc.name, rec.Code, tc.status, rec.Body.String())
			continue
		}
		if tc.want != "" && !bytes.Contains(rec.Body.Bytes(), []byte(tc.want)) {
			t.Errorf("%s: body %s lacks %s", tc.name, rec.Body.String(), tc.want)
		}
	}
	if got := postRow(t, pid)["Nonce"].(*types.AttributeValueMemberB).Value; !bytes.Equal(got, stored) {
		t.Error("a refused edit changed the stored post")
	}
}

func TestEditPostNeverGoesBackToAnEarlierEditionsNonce(t *testing.T) {
	h, _, pid, owner, cookie := commentFixture(t)
	original := postRow(t, pid)["Nonce"].(*types.AttributeValueMemberB).Value
	for i, tc := range []struct {
		nonce  []byte
		status int
	}{{nonceOf(2), 200}, {nonceOf(3), 200}, {original, 400}, {nonceOf(2), 400}, {nonceOf(3), 400}, {nonceOf(4), 200}} {
		rec := doPostAt(t, h, http.MethodPut, cookie, pid, postEdit(t, pid, owner, today(), tc.nonce, ctOf(byte(10+i))))
		if rec.Code != tc.status {
			t.Fatalf("edit %d: %d, want %d: %s", i, rec.Code, tc.status, rec.Body.String())
		}
		if tc.status == 400 && !bytes.Contains(rec.Body.Bytes(), []byte(`"nonce_reused"`)) {
			t.Errorf("edit %d: %s lacks nonce_reused", i, rec.Body.String())
		}
	}
	if used := postRow(t, pid)["UsedNonces"].(*types.AttributeValueMemberBS).Value; len(used) != 3 {
		t.Errorf("%d superseded nonces filed, want 3", len(used))
	}
}

func TestEditPostResendOfALandedEditIsAnsweredEvenWhenItsDayHasPassed(t *testing.T) {
	h, _, pid, owner, cookie := commentFixture(t)
	old := postEdit(t, pid, owner, "2020-01-01", nonceOf(2), ctOf(2))
	if rec := doPostAt(t, h, http.MethodPut, cookie, pid, old); rec.Code != 400 {
		t.Fatalf("a new edit signed in 2020: %d, want 400", rec.Code)
	}
	nonce, _ := base64.StdEncoding.DecodeString(old.Nonce)
	ct, _ := base64.StdEncoding.DecodeString(old.Ciphertext)
	sig, _ := base64.StdEncoding.DecodeString(old.Signature)
	gid, sortKey, _ := idgen.ParsePostID(pid)
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:        aws.String(testTableName()),
		Key:              map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s(sortKey)},
		UpdateExpression: aws.String("SET SignedDay = :d, Nonce = :n, Ciphertext = :c, Signature = :g"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":d": s(old.SignedDay), ":n": &types.AttributeValueMemberB{Value: nonce},
			":c": &types.AttributeValueMemberB{Value: ct}, ":g": &types.AttributeValueMemberB{Value: sig},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if rec := doPostAt(t, h, http.MethodPut, cookie, pid, old); rec.Code != 200 {
		t.Errorf("resend of the landed edit: %d %s, want 200", rec.Code, rec.Body.String())
	}
}

func TestEditPostWriteIsRefusedWhenAnotherEditGotThereFirstAndMayBeSignedAgain(t *testing.T) {
	h, gid, pid, owner, _ := commentFixture(t)
	self, err := h.db.GetUserByIDConsistent(context.Background(), owner.userID)
	if err != nil {
		t.Fatal(err)
	}
	_, sortKey, _ := idgen.ParsePostID(pid)
	original := postRow(t, pid)["Nonce"].(*types.AttributeValueMemberB).Value
	build := func(prior, nonce []byte, ct []byte, sig string) db.EditPostInput {
		return db.EditPostInput{
			GroupID: gid, SortKey: sortKey, AuthorUserID: owner.userID, SignedDay: today(), Nonce: nonce,
			Ciphertext: ct, Signature: []byte(sig), PriorNonce: prior, AuthorKeyEpoch: self.KeyEpoch, Now: time.Now(),
		}
	}
	ctx := context.Background()
	if err := h.db.EditPost(ctx, build(original, nonceOf(2), ctOf(2), "a")); err != nil {
		t.Fatalf("first edit: %v", err)
	}
	// The slower of two editors still names the first edition.
	if err := h.db.EditPost(ctx, build(original, nonceOf(3), ctOf(3), "a")); !errors.Is(err, db.ErrRoleChangeConflict) {
		t.Errorf("a write over a replaced edition: %v, want a retryable conflict", err)
	}
	// A superseded nonce is refused by the write itself, whatever the handler saw.
	if err := h.db.EditPost(ctx, build(nonceOf(2), original, ctOf(3), "a")); !errors.Is(err, db.ErrRoleChangeConflict) {
		t.Errorf("a write under a superseded nonce: %v, want a retryable conflict", err)
	}
	// The same nonce over the same ciphertext, signed again, is the same text.
	if err := h.db.EditPost(ctx, build(nonceOf(2), nonceOf(2), ctOf(2), "b")); err != nil {
		t.Errorf("re-sign: %v", err)
	}
	if err := h.db.EditPost(ctx, build(nonceOf(2), nonceOf(2), ctOf(5), "b")); !errors.Is(err, db.ErrRoleChangeConflict) {
		t.Errorf("same nonce, other text at the write: %v, want a conflict", err)
	}
	if used := postRow(t, pid)["UsedNonces"].(*types.AttributeValueMemberBS).Value; len(used) != 1 {
		t.Errorf("%d superseded nonces, want only the original's", len(used))
	}
}

// An edit also carries the time it was made, so its ciphertext may be longer
// than a new item's by exactly that; an item written at its size cap could not
// be edited otherwise.
func TestEditsHaveRoomForTheTimeTheyWereMade(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	writeComment(t, h, gid, pid, owner, cookie, "0001")
	for _, tc := range []struct {
		name   string
		extra  int
		status int
	}{{"at the edit limit", 0, 200}, {"one byte over", 1, 400}} {
		n := h.postCiphertextLimit() + editedAtOverhead + tc.extra
		if rec := doPostAt(t, h, http.MethodPut, cookie, pid, postEdit(t, pid, owner, today(), nonceOf(byte(20+tc.extra)), bytes.Repeat([]byte{1}, n))); rec.Code != tc.status {
			t.Errorf("post %s: %d, want %d: %s", tc.name, rec.Code, tc.status, rec.Body.String())
		}
		n = h.commentEditCiphertextLimit() + tc.extra
		req := edited(signedComment(t, gid, owner, copts{path: "0001", ctLen: n}))
		if rec := doCommentAt(t, h, http.MethodPut, cookie, pid, "0001", req); rec.Code != tc.status {
			t.Errorf("comment %s: %d, want %d: %s", tc.name, rec.Code, tc.status, rec.Body.String())
		}
	}
	// A NEW item gets no such room.
	if rec := doComment(t, h, cookie, pid, signedComment(t, gid, owner, copts{path: "0002", ctLen: h.commentCiphertextLimit() + 1})); rec.Code != 400 {
		t.Errorf("a new comment one byte over its own limit: %d, want 400", rec.Code)
	}
}

func TestDeletePostLeavesATombstoneAndItsCommentsStayReadable(t *testing.T) {
	h, gid, pid, _, cookie := commentFixture(t)
	before := postRow(t, pid)
	other, otherCookie := loggedInUser(t, h)
	addMember(t, gid, other, "member")
	writeComment(t, h, gid, pid, other, otherCookie, "0001")
	storeReactionAt(t, pid, "0001", "a")
	if rec := doPostAt(t, h, http.MethodDelete, cookie, pid, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	row := postRow(t, pid)
	for _, attr := range []string{"Nonce", "Ciphertext", "Signature", "SignedDay", "Generation", "UsedNonces"} {
		if rowHas(row, attr) {
			t.Errorf("tombstone still holds %s", attr)
		}
	}
	if b, ok := row["Deleted"].(*types.AttributeValueMemberBOOL); !ok || !b.Value {
		t.Errorf("tombstone is not marked deleted: %v", row)
	}
	for _, attr := range []string{"PK", "SK", "AuthorUserID", "TTL"} {
		if fmt.Sprint(before[attr]) != fmt.Sprint(row[attr]) {
			t.Errorf("%s changed: %v -> %v", attr, before[attr], row[attr])
		}
	}
	list := decodeList(t, doListPosts(t, h, cookie, gid, ""))
	if len(list.Posts) != 1 || list.Posts[0] != (postEntry{SortKey: list.Posts[0].SortKey, Deleted: true}) {
		t.Errorf("tombstone served as %+v, want only its sort key and the flag", list.Posts)
	}
	out := decodeThread(t, doThread(t, h, otherCookie, pid, ""))
	if fmt.Sprint(threadPaths(out)) != "[0001]" || fmt.Sprint(reactionTargets(out)) != "[0001]" {
		t.Errorf("the thread of a deleted post lost its comments or their reactions: %v %v", threadPaths(out), reactionTargets(out))
	}
}

func TestDeletePostWhoMay(t *testing.T) {
	h, gid, _, _, adminCookie := commentFixture(t)
	a, aCookie := loggedInUser(t, h)
	b, bCookie := loggedInUser(t, h)
	addMember(t, gid, a, "member")
	addMember(t, gid, b, "member")
	_, outsider := loggedInUser(t, h)
	mk := func(author registeredUser, c *http.Cookie, suffix string) string {
		req, _ := signedPost(t, gid, author, postOpts{sortKey: "POST#" + today() + "#00112233445566" + suffix})
		if rec := doPost(t, h, c, gid, req); rec.Code != http.StatusCreated {
			t.Fatal(rec.Body.String())
		}
		return pidOf(gid, req.SortKey)
	}
	p1, p2 := mk(a, aCookie, "01"), mk(a, aCookie, "02")
	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
		pid    string
		status int
	}{
		{"another plain member", bCookie, p1, 403},
		{"not a member", outsider, p1, 404},
		{"no session", nil, p1, 401},
		{"a malformed id", aCookie, "nope", 404},
		{"a post that is not there", aCookie, gid + "#2020-01-01#00112233445566ff", 404},
		{"the author", aCookie, p1, 204},
		{"an admin", adminCookie, p2, 204},
	} {
		if rec := doPostAt(t, h, http.MethodDelete, tc.cookie, tc.pid, nil); rec.Code != tc.status {
			t.Errorf("%s: %d, want %d: %s", tc.name, rec.Code, tc.status, rec.Body.String())
		}
	}
	for _, p := range []string{p1, p2} {
		if v, ok := postRow(t, p)["Deleted"].(*types.AttributeValueMemberBOOL); !ok || !v.Value {
			t.Errorf("%s is not deleted", p)
		}
	}
}

func TestDeletePostSweepsOnlyThePostsOwnReactionsAndRepeatingFinishesTheJob(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	writeComment(t, h, gid, pid, owner, cookie, "0001")
	for i := 0; i < 60; i++ {
		storeReactionAt(t, pid, "0000", fmt.Sprintf("reactor-%03d", i))
	}
	storeReactionAt(t, pid, "0001", "a")
	if rec := doPostAt(t, h, http.MethodDelete, cookie, pid, nil); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Body.String())
	}
	if n := countReactionRows(t, pid, "0000#"); n != 0 {
		t.Errorf("%d reactions left on the deleted post", n)
	}
	if n := countReactionRows(t, pid, "0001#"); n != 1 {
		t.Errorf("a comment's reactions = %d, want 1: the post's delete must not touch them", n)
	}
	storeReactionAt(t, pid, "0000", "left-behind")
	// The thread does not serve a stray one...
	if out := decodeThread(t, doThread(t, h, cookie, pid, "")); fmt.Sprint(reactionTargets(out)) != "[0001]" {
		t.Errorf("served reaction targets = %v, want only 0001", reactionTargets(out))
	}
	// ...and repeating the delete removes it.
	if rec := doPostAt(t, h, http.MethodDelete, cookie, pid, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("repeat: %d %s", rec.Code, rec.Body.String())
	}
	if n := countReactionRows(t, pid, "0000#"); n != 0 {
		t.Errorf("%d reactions left after the repeat", n)
	}
}

func TestADeletedPostTakesNothingNewButItsCommentsCanStillBeDeleted(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	writeComment(t, h, gid, pid, owner, cookie, "0001")
	if rec := doPostAt(t, h, http.MethodDelete, cookie, pid, nil); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Body.String())
	}
	if rec := doComment(t, h, cookie, pid, signedComment(t, gid, owner, copts{path: "0002"})); rec.Code != 404 {
		t.Errorf("a new comment on a deleted post: %d %s, want 404", rec.Code, rec.Body.String())
	}
	for _, target := range []string{"0000", "0001"} {
		if rec := doReaction(t, h, http.MethodPut, cookie, pid, target, sealedReaction(t, 0)); rec.Code != 404 {
			t.Errorf("a reaction on %s of a deleted post: %d %s, want 404", target, rec.Code, rec.Body.String())
		}
	}
	if rec := doCommentAt(t, h, http.MethodPut, cookie, pid, "0001", edited(signedComment(t, gid, owner, copts{path: "0001"}))); rec.Code != 404 {
		t.Errorf("an edit of a comment on a deleted post: %d %s, want 404", rec.Code, rec.Body.String())
	}
	if n := countReactionRows(t, pid, ""); n != 0 {
		t.Errorf("%d reactions stored on a deleted post", n)
	}
	// Taking back what you said still works.
	if rec := doCommentAt(t, h, http.MethodDelete, cookie, pid, "0001", nil); rec.Code != http.StatusNoContent {
		t.Errorf("deleting a comment under a deleted post: %d %s", rec.Code, rec.Body.String())
	}
}

// The handler answers 404 for an expired post, so the write's own expiry check
// is reached only when the post expires between the read and the write. It
// must still refuse, or an edit would revive text the group's policy expired.
func TestEditPostWriteRefusesAPostThatExpiredMeanwhile(t *testing.T) {
	h, gid, pid, owner, _ := commentFixture(t)
	self, err := h.db.GetUserByIDConsistent(context.Background(), owner.userID)
	if err != nil {
		t.Fatal(err)
	}
	_, sortKey, _ := idgen.ParsePostID(pid)
	original := postRow(t, pid)["Nonce"].(*types.AttributeValueMemberB).Value
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:                aws.String(testTableName()),
		Key:                      map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s(sortKey)},
		UpdateExpression:         aws.String("SET #t = :past"),
		ExpressionAttributeNames: map[string]string{"#t": "TTL"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":past": &types.AttributeValueMemberN{Value: fmt.Sprint(time.Now().Add(-time.Hour).Unix())},
		},
	}); err != nil {
		t.Fatal(err)
	}
	err = h.db.EditPost(context.Background(), db.EditPostInput{
		GroupID: gid, SortKey: sortKey, AuthorUserID: owner.userID, SignedDay: today(), Nonce: nonceOf(2),
		Ciphertext: ctOf(2), Signature: []byte("sig"), PriorNonce: original, AuthorKeyEpoch: self.KeyEpoch, Now: time.Now(),
	})
	if !errors.Is(err, db.ErrPostGone) {
		t.Errorf("edit of an expired post: %v, want ErrPostGone", err)
	}
	if got := postRow(t, pid)["Nonce"].(*types.AttributeValueMemberB).Value; !bytes.Equal(got, original) {
		t.Error("a refused edit changed the stored post")
	}
}
