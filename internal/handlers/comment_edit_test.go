package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
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
		code   string
	}{
		{"another member", otherCookie, "0001", edited(signedComment(t, gid, other, copts{path: "0001"})), 403, ""},
		{"signed by someone else", cookie, "0001", edited(signedComment(t, gid, owner, copts{path: "0001", signer: other})), 400, "bad_signature"},
		{"an admin who is not the author", cookie, "0003", edited(signedComment(t, gid, owner, copts{path: "0003"})), 403, ""},
		{"a tombstone", cookie, "0002", edited(signedComment(t, gid, owner, copts{path: "0002"})), 409, "comment_gone"},
		{"a comment that is not there", cookie, "0009", edited(signedComment(t, gid, owner, copts{path: "0009"})), 409, "comment_gone"},
		{"signed for another path", cookie, "0001", edited(signedComment(t, gid, owner, copts{path: "0001", signedPath: "0002"})), 400, "bad_signature"},
		{"signed for another generation", cookie, "0001", edited(signedComment(t, gid, owner, copts{path: "0001", generation: 1, signedPath: "0001"})), 409, "generation_stale"},
		{"signed on a far day", cookie, "0001", edited(signedComment(t, gid, owner, copts{path: "0001", signedDay: "2020-01-01"})), 400, ""},
		{"a nonce already used", cookie, "0001", reusedNonce, 400, ""},
		{"not a member", outsiderCookie, "0001", edited(signedComment(t, gid, owner, copts{path: "0001"})), 404, ""},
		{"no session", nil, "0001", edited(signedComment(t, gid, owner, copts{path: "0001"})), 401, ""},
		{"a malformed path", cookie, "1", edited(signedComment(t, gid, owner, copts{path: "0001"})), 400, ""},
	}
	for _, tc := range cases {
		rec := doCommentAt(t, h, http.MethodPut, tc.cookie, pid, tc.path, tc.body)
		if rec.Code != tc.status {
			t.Errorf("%s: status %d, want %d: %s", tc.name, rec.Code, tc.status, rec.Body.String())
			continue
		}
		if tc.code != "" && !bytes.Contains(rec.Body.Bytes(), []byte(`"`+tc.code+`"`)) {
			t.Errorf("%s: body %s lacks code %s", tc.name, rec.Body.String(), tc.code)
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
	for _, attr := range []string{"Nonce", "Ciphertext", "Signature", "SignedDay", "Generation"} {
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
	h, gid, pid, owner, cookie := commentFixture(t)
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
	_ = owner
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
