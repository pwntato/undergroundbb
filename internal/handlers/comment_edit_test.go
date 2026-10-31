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

	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

func doCommentAt(t *testing.T, h *Handler, method string, cookie *http.Cookie, pid, path string, body any) *httptest.ResponseRecorder {
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
	req := httptest.NewRequest(method, "/api/posts/"+url.PathEscape(pid)+"/comments/"+path, &buf)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

// edited turns a freshly signed comment into the body of an edit.
func edited(r createCommentRequest) editCommentRequest {
	return editCommentRequest{Generation: r.Generation, SignedDay: r.SignedDay, Nonce: r.Nonce, Ciphertext: r.Ciphertext, Signature: r.Signature}
}

// writeComment posts a real signed comment and fails the test if it is refused.
func writeComment(t *testing.T, h *Handler, gid, pid string, author registeredUser, cookie *http.Cookie, path string) {
	t.Helper()
	if rec := doComment(t, h, cookie, pid, signedComment(t, gid, author, copts{path: path})); rec.Code != http.StatusCreated {
		t.Fatalf("comment %s: %d %s", path, rec.Code, rec.Body.String())
	}
}

func rowHas(row map[string]types.AttributeValue, attr string) bool {
	_, ok := row[attr]
	return ok
}

func countReactionRows(t *testing.T, pid, prefix string) int {
	t.Helper()
	n := 0
	var start map[string]types.AttributeValue
	for {
		out, err := rawDDB(t).Query(context.Background(), &dynamodb.QueryInput{
			TableName:              aws.String(testTableName()),
			KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": s("POST#" + pid), ":sk": s("RXN#" + prefix),
			},
			ConsistentRead:    aws.Bool(true),
			ExclusiveStartKey: start,
		})
		if err != nil {
			t.Fatal(err)
		}
		n += len(out.Items)
		if len(out.LastEvaluatedKey) == 0 {
			return n
		}
		start = out.LastEvaluatedKey
	}
}

func TestEditCommentReplacesTheSealedTextAndNothingElse(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	writeComment(t, h, gid, pid, owner, cookie, "0001")
	before := getRow(t, "POST#"+pid, "CMT#0001")
	req := edited(signedComment(t, gid, owner, copts{path: "0001", ctLen: 200}))
	if rec := doCommentAt(t, h, http.MethodPut, cookie, pid, "0001", req); rec.Code != http.StatusOK {
		t.Fatalf("edit: %d %s", rec.Code, rec.Body.String())
	}
	after := getRow(t, "POST#"+pid, "CMT#0001")
	out := decodeThread(t, doThread(t, h, cookie, pid, ""))
	if len(out.Comments) != 1 || out.Comments[0].Ciphertext != req.Ciphertext || out.Comments[0].Nonce != req.Nonce ||
		out.Comments[0].Signature != req.Signature {
		t.Fatalf("thread does not serve the edited bytes: %+v", out.Comments)
	}
	for _, attr := range []string{"PK", "SK", "AuthorUserID", "TTL"} {
		if fmt.Sprint(before[attr]) != fmt.Sprint(after[attr]) {
			t.Errorf("%s changed: %v -> %v", attr, before[attr], after[attr])
		}
	}
}

func TestEditCommentResendOfTheStoredBytesIsHarmless(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	writeComment(t, h, gid, pid, owner, cookie, "0001")
	req := edited(signedComment(t, gid, owner, copts{path: "0001"}))
	for i := 0; i < 2; i++ {
		if rec := doCommentAt(t, h, http.MethodPut, cookie, pid, "0001", req); rec.Code != http.StatusOK {
			t.Fatalf("send %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
}

func TestEditCommentRefusesWhatItShould(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	other, otherCookie := loggedInUser(t, h)
	addMember(t, gid, other, "member")
	_, outsiderCookie := loggedInUser(t, h)
	writeComment(t, h, gid, pid, owner, cookie, "0001")
	writeComment(t, h, gid, pid, owner, cookie, "0002")
	writeComment(t, h, gid, pid, other, otherCookie, "0003")
	if rec := doCommentAt(t, h, http.MethodDelete, cookie, pid, "0002", nil); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Body.String())
	}
	stored := getRow(t, "POST#"+pid, "CMT#0001")
	storedNonce := stored["Nonce"].(*types.AttributeValueMemberB).Value
	reusedNonce := edited(signedComment(t, gid, owner, copts{path: "0001"}))
	reusedNonce.Nonce = base64.StdEncoding.EncodeToString(storedNonce)

	cases := []struct {
		name   string
		cookie *http.Cookie
		path   string
		body   editCommentRequest
		status int
		want   string // a piece of the body, so the right refusal is the one asserted
	}{
		{"another member", otherCookie, "0001", edited(signedComment(t, gid, other, copts{path: "0001"})), 403, ""},
		{"signed by someone else", cookie, "0001", edited(signedComment(t, gid, owner, copts{path: "0001", signer: other})), 400, `"bad_signature"`},
		{"an admin who is not the author", cookie, "0003", edited(signedComment(t, gid, owner, copts{path: "0003"})), 403, ""},
		{"a tombstone", cookie, "0002", edited(signedComment(t, gid, owner, copts{path: "0002"})), 409, `"comment_gone"`},
		{"a comment that is not there", cookie, "0009", edited(signedComment(t, gid, owner, copts{path: "0009"})), 409, `"comment_gone"`},
		{"signed for another path", cookie, "0001", edited(signedComment(t, gid, owner, copts{path: "0001", signedPath: "0002"})), 400, `"bad_signature"`},
		{"signed for another generation", cookie, "0001", edited(signedComment(t, gid, owner, copts{path: "0001", generation: 1, signedPath: "0001"})), 409, `"generation_stale"`},
		{"signed on a far day", cookie, "0001", edited(signedComment(t, gid, owner, copts{path: "0001", signedDay: "2020-01-01"})), 400, "signedDay: not within tolerance"},
		{"a nonce already used", cookie, "0001", reusedNonce, 400, `"nonce_reused"`},
		{"not a member", outsiderCookie, "0001", edited(signedComment(t, gid, owner, copts{path: "0001"})), 404, ""},
		{"no session", nil, "0001", edited(signedComment(t, gid, owner, copts{path: "0001"})), 401, ""},
		{"a malformed path", cookie, "1", edited(signedComment(t, gid, owner, copts{path: "0001"})), 400, "path:"},
	}
	for _, tc := range cases {
		rec := doCommentAt(t, h, http.MethodPut, tc.cookie, pid, tc.path, tc.body)
		if rec.Code != tc.status {
			t.Errorf("%s: status %d, want %d: %s", tc.name, rec.Code, tc.status, rec.Body.String())
			continue
		}
		if tc.want != "" && !bytes.Contains(rec.Body.Bytes(), []byte(tc.want)) {
			t.Errorf("%s: body %s lacks %s", tc.name, rec.Body.String(), tc.want)
		}
	}
	if got := getRow(t, "POST#"+pid, "CMT#0001"); fmt.Sprint(got["Ciphertext"]) != fmt.Sprint(stored["Ciphertext"]) {
		t.Error("a refused edit changed the stored comment")
	}
}

func TestDeleteCommentLeavesATombstoneRepliesSurviveAndNobodyIsNamed(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	other, otherCookie := loggedInUser(t, h)
	addMember(t, gid, other, "member")
	writeComment(t, h, gid, pid, other, otherCookie, "0001")
	writeComment(t, h, gid, pid, other, otherCookie, "0001.0001")
	if rec := doCommentAt(t, h, http.MethodDelete, otherCookie, pid, "0001", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	row := getRow(t, "POST#"+pid, "CMT#0001")
	for _, attr := range []string{"Nonce", "Ciphertext", "Signature", "SignedDay", "Generation", "UsedNonces"} {
		if rowHas(row, attr) {
			t.Errorf("tombstone still holds %s", attr)
		}
	}
	if b, ok := row["Deleted"].(*types.AttributeValueMemberBOOL); !ok || !b.Value {
		t.Errorf("tombstone is not marked deleted: %v", row)
	}
	// The row keeps replies in place: a new reply under it is written.
	writeComment(t, h, gid, pid, owner, cookie, "0001.0002")
	out := decodeThread(t, doThread(t, h, cookie, pid, ""))
	if fmt.Sprint(threadPaths(out)) != "[0001 0001.0001 0001.0002]" {
		t.Fatalf("paths = %v", threadPaths(out))
	}
	if got := out.Comments[0]; got != (commentEntry{Path: "0001", Deleted: true}) {
		t.Errorf("tombstone served as %+v, want only its path and the flag", got)
	}
	if out.Comments[1].Deleted || out.Comments[1].Ciphertext == "" {
		t.Errorf("a reply was damaged: %+v", out.Comments[1])
	}
}

func TestDeleteCommentWhoMay(t *testing.T) {
	h, gid, pid, _, cookie := commentFixture(t)
	a, aCookie := loggedInUser(t, h)
	b, bCookie := loggedInUser(t, h)
	addMember(t, gid, a, "member")
	addMember(t, gid, b, "member")
	_, outsider := loggedInUser(t, h)
	writeComment(t, h, gid, pid, a, aCookie, "0001")
	writeComment(t, h, gid, pid, a, aCookie, "0002")
	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
		path   string
		status int
	}{
		{"another plain member", bCookie, "0001", 403},
		{"not a member", outsider, "0001", 404},
		{"no session", nil, "0001", 401},
		{"a comment that is not there", aCookie, "0009", 404},
		{"a malformed path", aCookie, "1", 400},
		{"the author", aCookie, "0001", 204},
		{"an admin", cookie, "0002", 204},
	} {
		if rec := doCommentAt(t, h, http.MethodDelete, tc.cookie, pid, tc.path, nil); rec.Code != tc.status {
			t.Errorf("%s: %d, want %d: %s", tc.name, rec.Code, tc.status, rec.Body.String())
		}
	}
	for _, p := range []string{"0001", "0002"} {
		if b, ok := getRow(t, "POST#"+pid, "CMT#"+p)["Deleted"].(*types.AttributeValueMemberBOOL); !ok || !b.Value {
			t.Errorf("%s is not deleted", p)
		}
	}
}

func TestDeleteCommentTwiceIsTheSame204AndFinishesAHalfDoneSweep(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	writeComment(t, h, gid, pid, owner, cookie, "0001")
	if rec := doCommentAt(t, h, http.MethodDelete, cookie, pid, "0001", nil); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Body.String())
	}
	// A reaction that outlived the sweep (it failed half way).
	storeReactionAt(t, pid, "0001", "left-behind")
	if rec := doCommentAt(t, h, http.MethodDelete, cookie, pid, "0001", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("repeat: %d %s", rec.Code, rec.Body.String())
	}
	if n := countReactionRows(t, pid, "0001#"); n != 0 {
		t.Errorf("%d reactions left after the repeat", n)
	}
}

func TestDeleteCommentSweepsItsReactionsOnlyAcrossPages(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	for _, p := range []string{"0001", "0002"} {
		writeComment(t, h, gid, pid, owner, cookie, p)
	}
	writeComment(t, h, gid, pid, owner, cookie, "0001.0001")
	// More reactors than one batch (25) holds, plus neighbours that must stay:
	// a reply, the next comment, and the post itself.
	for i := 0; i < 60; i++ {
		storeReactionAt(t, pid, "0001", fmt.Sprintf("reactor-%03d", i))
	}
	storeReactionAt(t, pid, "0001.0001", "a")
	storeReactionAt(t, pid, "0002", "a")
	storeReactionAt(t, pid, "0000", "a")
	if rec := doCommentAt(t, h, http.MethodDelete, cookie, pid, "0001", nil); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Body.String())
	}
	if n := countReactionRows(t, pid, "0001#"); n != 0 {
		t.Errorf("%d reactions left on the deleted comment", n)
	}
	for _, p := range []string{"0001.0001#", "0002#", "0000#"} {
		if n := countReactionRows(t, pid, p); n != 1 {
			t.Errorf("reactions under %s = %d, want 1", p, n)
		}
	}
}

// A comment whose reactions span several DynamoDB query pages (a query returns
// at most 1 MB) is swept completely.
func TestDeleteCommentSweepsReactionsThatSpanQueryPages(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	writeComment(t, h, gid, pid, owner, cookie, "0001")
	for i := 0; i < 30; i++ {
		putCommentRow(t, map[string]types.AttributeValue{
			"PK": s("POST#" + pid), "SK": s(fmt.Sprintf("RXN#0001#reactor-%03d", i)), "Type": s("REACTION"),
			"Ciphertext": &types.AttributeValueMemberB{Value: make([]byte, 50_000)},
		})
	}
	if n := countReactionRows(t, pid, "0001#"); n != 30 {
		t.Fatalf("seeded %d rows", n)
	}
	if rec := doCommentAt(t, h, http.MethodDelete, cookie, pid, "0001", nil); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Body.String())
	}
	if n := countReactionRows(t, pid, "0001#"); n != 0 {
		t.Errorf("%d reactions left after the sweep", n)
	}
}

func TestReactionOnATombstoneIsRefusedAndTheThreadIgnoresStrays(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	writeComment(t, h, gid, pid, owner, cookie, "0001")
	writeComment(t, h, gid, pid, owner, cookie, "0002")
	if rec := doCommentAt(t, h, http.MethodDelete, cookie, pid, "0001", nil); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Body.String())
	}
	rec := doReaction(t, h, http.MethodPut, cookie, pid, "0001", sealedReaction(t, 0))
	if rec.Code != http.StatusConflict || !bytes.Contains(rec.Body.Bytes(), []byte("parent_gone")) {
		t.Errorf("reaction on a tombstone: %d %s", rec.Code, rec.Body.String())
	}
	if n := countReactionRows(t, pid, "0001#"); n != 0 {
		t.Errorf("%d reactions stored on a tombstone", n)
	}
	// A stray one (a failed sweep) is not served; the live comment's is.
	storeReactionAt(t, pid, "0001", "stray")
	storeReactionAt(t, pid, "0002", "kept")
	out := decodeThread(t, doThread(t, h, cookie, pid, ""))
	if fmt.Sprint(reactionTargets(out)) != "[0002]" {
		t.Errorf("served reaction targets = %v, want only 0002", reactionTargets(out))
	}
}

func TestReplyUnderAMissingParentIsParentGoneBeforeAnySkipRule(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	for _, path := range []string{"0003.0001", "0003.0002", "0001.0001"} {
		rec := doComment(t, h, cookie, pid, signedComment(t, gid, owner, copts{path: path}))
		if rec.Code != http.StatusConflict || !bytes.Contains(rec.Body.Bytes(), []byte(`"parent_gone"`)) ||
			bytes.Contains(rec.Body.Bytes(), []byte("nextPath")) {
			t.Errorf("%s: %d %s, want parent_gone with no nextPath", path, rec.Code, rec.Body.String())
		}
	}
}

// editBytes seals nothing: it builds an edit with chosen nonce and ciphertext,
// signed as a real client would sign it.
func editWith(t *testing.T, gid string, author registeredUser, path, signedDay string, nonce, ct []byte) editCommentRequest {
	t.Helper()
	req := signedComment(t, gid, author, copts{path: path, signedDay: signedDay, signedCt: ct})
	req.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	req.Nonce = base64.StdEncoding.EncodeToString(nonce)
	return edited(req)
}

func nonceOf(b byte) []byte { return bytes.Repeat([]byte{b}, 12) }
func ctOf(b byte) []byte    { return bytes.Repeat([]byte{b}, 120) }

func TestEditCommentNeverGoesBackToAnEarlierEditionsNonce(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	today := time.Now().UTC().Format("2006-01-02")
	first := editWith(t, gid, owner, "0001", today, nonceOf(1), ctOf(1))
	if rec := doComment(t, h, cookie, pid, createCommentRequest{Path: "0001", Generation: 0, SignedDay: first.SignedDay, Nonce: first.Nonce, Ciphertext: first.Ciphertext, Signature: first.Signature}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	for i, tc := range []struct {
		nonce  byte
		status int
	}{{2, 200}, {3, 200}, {1, 400}, {2, 400}, {3, 400}, {4, 200}} {
		rec := doCommentAt(t, h, http.MethodPut, cookie, pid, "0001", editWith(t, gid, owner, "0001", today, nonceOf(tc.nonce), ctOf(byte(10+i))))
		if rec.Code != tc.status {
			t.Fatalf("edit %d under nonce %d: %d, want %d: %s", i, tc.nonce, rec.Code, tc.status, rec.Body.String())
		}
		if tc.status == 400 && !bytes.Contains(rec.Body.Bytes(), []byte(`"nonce_reused"`)) {
			t.Errorf("edit %d: %s lacks nonce_reused", i, rec.Body.String())
		}
	}
	if used := getRow(t, "POST#"+pid, "CMT#0001")["UsedNonces"].(*types.AttributeValueMemberBS).Value; len(used) != 3 {
		t.Errorf("%d superseded nonces filed, want 3", len(used))
	}
}

func TestEditCommentMayBeSignedAgainOverTheSameCiphertextAndNonce(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	today := time.Now().UTC().Format("2006-01-02")
	first := editWith(t, gid, owner, "0001", today, nonceOf(1), ctOf(1))
	if rec := doComment(t, h, cookie, pid, createCommentRequest{Path: "0001", SignedDay: first.SignedDay, Nonce: first.Nonce, Ciphertext: first.Ciphertext, Signature: first.Signature}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doCommentAt(t, h, http.MethodPut, cookie, pid, "0001", editWith(t, gid, owner, "0001", today, nonceOf(2), ctOf(2))); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	// The same nonce over different text is the reuse the guard is for.
	if rec := doCommentAt(t, h, http.MethodPut, cookie, pid, "0001", editWith(t, gid, owner, "0001", today, nonceOf(2), ctOf(3))); rec.Code != 400 ||
		!bytes.Contains(rec.Body.Bytes(), []byte(`"nonce_reused"`)) {
		t.Errorf("same nonce, different text: %d %s", rec.Code, rec.Body.String())
	}
	// The same sealed bytes signed again (a client signing a lost-response
	// resend after midnight: a different signature and day over the same
	// nonce and ciphertext) are harmless. The handler lets them through and
	// the write accepts them without filing the nonce away; a day cannot
	// differ within the skew window for long, so this goes to the write.
	self, err := h.db.GetUserByIDConsistent(context.Background(), owner.userID)
	if err != nil {
		t.Fatal(err)
	}
	_, postSortKey, _ := idgen.ParsePostID(pid)
	in := db.EditCommentInput{
		GroupID: gid, PostID: pid, PostSortKey: postSortKey, Path: "0001", AuthorUserID: owner.userID,
		SignedDay: "2099-01-01", Nonce: nonceOf(2), Ciphertext: ctOf(2), Signature: []byte("signed-again"),
		PriorNonce: nonceOf(2), AuthorKeyEpoch: self.KeyEpoch, Now: time.Now(),
	}
	have, err := h.db.GetComment(context.Background(), pid, "0001")
	if err != nil || have == nil {
		t.Fatal(err)
	}
	if in.ReusesNonce(have) {
		t.Error("the same nonce over the same ciphertext is counted as a reuse")
	}
	if err := h.db.EditComment(context.Background(), in); err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	row := getRow(t, "POST#"+pid, "CMT#0001")
	if day := row["SignedDay"].(*types.AttributeValueMemberS).Value; day != "2099-01-01" {
		t.Errorf("signed day = %s, want the new one", day)
	}
	if used := row["UsedNonces"].(*types.AttributeValueMemberBS).Value; len(used) != 1 {
		t.Errorf("%d superseded nonces, want only the first edition's", len(used))
	}
	// Over different text the write itself refuses it.
	in.Ciphertext = ctOf(4)
	if err := h.db.EditComment(context.Background(), in); !errors.Is(err, db.ErrRoleChangeConflict) {
		t.Errorf("same nonce, different text at the write: %v, want a conflict", err)
	}
}

func TestEditCommentWriteIsRefusedWhenAnotherEditGotThereFirst(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	today := time.Now().UTC().Format("2006-01-02")
	first := editWith(t, gid, owner, "0001", today, nonceOf(1), ctOf(1))
	doComment(t, h, cookie, pid, createCommentRequest{Path: "0001", SignedDay: first.SignedDay, Nonce: first.Nonce, Ciphertext: first.Ciphertext, Signature: first.Signature})
	self, err := h.db.GetUserByIDConsistent(context.Background(), owner.userID)
	if err != nil {
		t.Fatal(err)
	}
	_, postSortKey, _ := idgen.ParsePostID(pid)
	build := func(prior, nonce byte) db.EditCommentInput {
		e := editWith(t, gid, owner, "0001", today, nonceOf(nonce), ctOf(nonce))
		n, _ := base64.StdEncoding.DecodeString(e.Nonce)
		ct, _ := base64.StdEncoding.DecodeString(e.Ciphertext)
		sig, _ := base64.StdEncoding.DecodeString(e.Signature)
		return db.EditCommentInput{
			GroupID: gid, PostID: pid, PostSortKey: postSortKey, Path: "0001", AuthorUserID: owner.userID,
			SignedDay: today, Nonce: n, Ciphertext: ct, Signature: sig, PriorNonce: nonceOf(prior),
			AuthorKeyEpoch: self.KeyEpoch, Now: time.Now(),
		}
	}
	if err := h.db.EditComment(context.Background(), build(1, 2)); err != nil {
		t.Fatalf("first edit: %v", err)
	}
	// Two editors read edition 2... the slower one still names edition 1.
	if err := h.db.EditComment(context.Background(), build(1, 3)); !errors.Is(err, db.ErrRoleChangeConflict) {
		t.Errorf("a write over a replaced edition: %v, want a retryable conflict", err)
	}
	// And a superseded nonce is refused by the write itself, whatever the handler saw.
	if err := h.db.EditComment(context.Background(), build(2, 1)); !errors.Is(err, db.ErrRoleChangeConflict) {
		t.Errorf("a write under a superseded nonce: %v, want a retryable conflict", err)
	}
	if got := getRow(t, "POST#"+pid, "CMT#0001")["Nonce"].(*types.AttributeValueMemberB).Value; !bytes.Equal(got, nonceOf(2)) {
		t.Error("a refused write changed the stored edition")
	}
}

// A resend of an edit that already landed is answered by what was written,
// before the freshness checks, as a resent comment is: a lost response is
// retried hours later, when its signing day is long out of tolerance.
func TestEditCommentResendOfALandedEditIsAnsweredEvenWhenItsDayHasPassed(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	today := time.Now().UTC().Format("2006-01-02")
	first := editWith(t, gid, owner, "0001", today, nonceOf(1), ctOf(1))
	if rec := doComment(t, h, cookie, pid, createCommentRequest{Path: "0001", SignedDay: first.SignedDay, Nonce: first.Nonce, Ciphertext: first.Ciphertext, Signature: first.Signature}); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body.String())
	}
	old := editWith(t, gid, owner, "0001", "2020-01-01", nonceOf(2), ctOf(2))
	if rec := doCommentAt(t, h, http.MethodPut, cookie, pid, "0001", old); rec.Code != 400 {
		t.Fatalf("a new edit signed in 2020: %d, want 400", rec.Code)
	}
	// The edit "landed" earlier, when its day was current.
	nonce, _ := base64.StdEncoding.DecodeString(old.Nonce)
	ct, _ := base64.StdEncoding.DecodeString(old.Ciphertext)
	sig, _ := base64.StdEncoding.DecodeString(old.Signature)
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:        aws.String(testTableName()),
		Key:              map[string]types.AttributeValue{"PK": s("POST#" + pid), "SK": s("CMT#0001")},
		UpdateExpression: aws.String("SET SignedDay = :d, Nonce = :n, Ciphertext = :c, Signature = :g"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":d": s(old.SignedDay), ":n": &types.AttributeValueMemberB{Value: nonce},
			":c": &types.AttributeValueMemberB{Value: ct}, ":g": &types.AttributeValueMemberB{Value: sig},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if rec := doCommentAt(t, h, http.MethodPut, cookie, pid, "0001", old); rec.Code != 200 {
		t.Errorf("resend of the landed edit: %d %s, want 200", rec.Code, rec.Body.String())
	}
}

func TestDeleteCommentForgetsTheNoncesOfEarlierEditions(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	today := time.Now().UTC().Format("2006-01-02")
	first := editWith(t, gid, owner, "0001", today, nonceOf(1), ctOf(1))
	doComment(t, h, cookie, pid, createCommentRequest{Path: "0001", SignedDay: first.SignedDay, Nonce: first.Nonce, Ciphertext: first.Ciphertext, Signature: first.Signature})
	if rec := doCommentAt(t, h, http.MethodPut, cookie, pid, "0001", editWith(t, gid, owner, "0001", today, nonceOf(2), ctOf(2))); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	if !rowHas(getRow(t, "POST#"+pid, "CMT#0001"), "UsedNonces") {
		t.Fatal("the edit filed no nonce, so this test proves nothing")
	}
	if rec := doCommentAt(t, h, http.MethodDelete, cookie, pid, "0001", nil); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Body.String())
	}
	if rowHas(getRow(t, "POST#"+pid, "CMT#0001"), "UsedNonces") {
		t.Error("the tombstone still lists earlier nonces")
	}
}
