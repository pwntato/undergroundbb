package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
)

// copts shapes one signed comment. Zero values give a valid top-level comment
// at generation 0 signed today by the author.
type copts struct {
	path       string
	signer     registeredUser // defaults to the author
	generation int64
	signedDay  string
	ctLen      int
	// signedPath and signedCt, when set, are what the signature covers instead
	// of the request's own, to prove each is bound.
	signedPath string
	signedCt   []byte
}

func signedComment(t *testing.T, gid string, author registeredUser, o copts) createCommentRequest {
	t.Helper()
	if o.path == "" {
		o.path = "0001"
	}
	if o.ctLen == 0 {
		o.ctLen = 120
	}
	if o.signer.userID == "" {
		o.signer = author
	}
	if o.signedDay == "" {
		o.signedDay = time.Now().UTC().Format("2006-01-02")
	}
	ct := make([]byte, o.ctLen)
	_, _ = rand.Read(ct)
	nonce := make([]byte, crypto.NonceSize)
	_, _ = rand.Read(nonce)
	signedPath, signedCt := o.path, ct
	if o.signedPath != "" {
		signedPath = o.signedPath
	}
	if o.signedCt != nil {
		signedCt = o.signedCt
	}
	payload := crypto.SignedPayload(author.userID, gid, "CMT#"+signedPath, uint64(o.generation), o.signedDay, signedCt)
	sig, err := crypto.Sign(o.signer.signPriv, crypto.ContextComment, payload)
	if err != nil {
		t.Fatal(err)
	}
	return createCommentRequest{
		Path:       o.path,
		Generation: o.generation,
		SignedDay:  o.signedDay,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
		Signature:  base64.StdEncoding.EncodeToString(sig),
	}
}

func pidOf(gid, postSortKey string) string {
	return gid + "#" + strings.TrimPrefix(postSortKey, "POST#")
}

func doComment(t *testing.T, h *Handler, cookie *http.Cookie, pid string, body createCommentRequest) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	// The post id holds '#', which a URL carries as %23.
	req := httptest.NewRequest(http.MethodPost, "/api/posts/"+url.PathEscape(pid)+"/comments", &buf)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func doThread(t *testing.T, h *Handler, cookie *http.Cookie, pid, query string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/posts/"+url.PathEscape(pid)+"/thread"+query, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func decodeThread(t *testing.T, rec *httptest.ResponseRecorder) threadResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var out threadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// commentFixture is a group with a live post to comment on.
func commentFixture(t *testing.T) (h *Handler, gid, pid string, owner registeredUser, cookie *http.Cookie) {
	t.Helper()
	h, gid, owner, cookie = postFixture(t)
	req, _ := signedPost(t, gid, owner, postOpts{})
	if rec := doPost(t, h, cookie, gid, req); rec.Code != http.StatusCreated {
		t.Fatalf("create post: %d %s", rec.Code, rec.Body.String())
	}
	return h, gid, pidOf(gid, req.SortKey), owner, cookie
}

func storeCommentAt(t *testing.T, pid, path, author string, ttl int64) {
	t.Helper()
	storeCommentSized(t, pid, path, author, ttl, len("ciphertext"))
}

// storeCommentSized stores a comment whose ciphertext is n bytes, to put a
// page near the 1 MB a single DynamoDB query returns.
func storeCommentSized(t *testing.T, pid, path, author string, ttl int64, n int) {
	t.Helper()
	item := map[string]types.AttributeValue{
		"PK": s("POST#" + pid), "SK": s("CMT#" + path), "Type": s("COMMENT"),
		"AuthorUserID": s(author), "SignedDay": s("2026-10-28"),
		"Generation": &types.AttributeValueMemberN{Value: "0"},
		"Nonce":      &types.AttributeValueMemberB{Value: make([]byte, 12)},
		"Ciphertext": &types.AttributeValueMemberB{Value: make([]byte, n)},
		"Signature":  &types.AttributeValueMemberB{Value: []byte("signature")},
	}
	if ttl != 0 {
		item["TTL"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(ttl, 10)}
	}
	putCommentRow(t, item)
}

func storeReactionAt(t *testing.T, pid, target, reactor string) {
	t.Helper()
	putCommentRow(t, map[string]types.AttributeValue{
		"PK": s("POST#" + pid), "SK": s("RXN#" + target + "#" + reactor), "Type": s("REACTION"),
		"Generation": &types.AttributeValueMemberN{Value: "0"},
		"Nonce":      &types.AttributeValueMemberB{Value: make([]byte, 12)},
		"Ciphertext": &types.AttributeValueMemberB{Value: []byte("emoji")},
	})
}

func putCommentRow(t *testing.T, item map[string]types.AttributeValue) {
	t.Helper()
	if _, err := rawDDB(t).PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName: aws.String(testTableName()), Item: item,
	}); err != nil {
		t.Fatal(err)
	}
}

func threadPaths(out threadResponse) []string {
	var paths []string
	for _, c := range out.Comments {
		paths = append(paths, c.Path)
	}
	return paths
}

func reactionTargets(out threadResponse) []string {
	var targets []string
	for _, x := range out.Reactions {
		targets = append(targets, x.Target)
	}
	return targets
}

func TestCreateCommentStoresTheSignedCiphertextWithThePostsTTL(t *testing.T) {
	h, gid, owner, cookie := postFixture(t)
	future := time.Now().Add(72 * time.Hour).Unix()
	postKey := "POST#2026-10-28#00112233445566ff"
	storePostAt(t, gid, postKey, owner.userID, future)
	pid := pidOf(gid, postKey)
	req := signedComment(t, gid, owner, copts{})
	rec := doComment(t, h, cookie, pid, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	row := getRow(t, "POST#"+pid, "CMT#0001")
	if row == nil {
		t.Fatal("no row stored")
	}
	if strAttr(row, "AuthorUserID") != owner.userID || strAttr(row, "SignedDay") != req.SignedDay || strAttr(row, "Type") != "COMMENT" {
		t.Errorf("row = %v", row)
	}
	// Copied from the post, not computed from now: a day-rounded "now + days"
	// could never equal this exact second.
	if got := numAttr(row, "TTL"); got != strconv.FormatInt(future, 10) {
		t.Errorf("TTL = %s, want the post's %d", got, future)
	}
}

func TestCreateCommentOnAPostThatNeverExpiresHasNoTTL(t *testing.T) {
	h, gid, owner, cookie := postFixture(t)
	postKey := "POST#2026-10-28#00112233445566fe"
	storePostAt(t, gid, postKey, owner.userID, 0)
	pid := pidOf(gid, postKey)
	if rec := doComment(t, h, cookie, pid, signedComment(t, gid, owner, copts{})); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if _, has := getRow(t, "POST#"+pid, "CMT#0001")["TTL"]; has {
		t.Error("a comment on a post with no expiry carries a TTL")
	}
}

func TestCreateCommentRefusesWhatItShould(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	outsider, outsiderCookie := loggedInUser(t, h)
	other := registerTestUser(t, h)
	short := signedComment(t, gid, owner, copts{ctLen: 20})
	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
		pid    string
		req    createCommentRequest
		status int
		code   string
	}{
		{"no session", nil, pid, signedComment(t, gid, owner, copts{}), http.StatusUnauthorized, ""},
		{"not a member", outsiderCookie, pid, signedComment(t, gid, outsider, copts{}), http.StatusNotFound, ""},
		{"malformed post id", cookie, "nonsense", signedComment(t, gid, owner, copts{}), http.StatusNotFound, ""},
		{"missing post", cookie, pidOf(gid, "POST#2020-01-01#0000000000000000"), signedComment(t, gid, owner, copts{}), http.StatusNotFound, ""},
		{"path 0000", cookie, pid, signedComment(t, gid, owner, copts{path: "0000"}), http.StatusBadRequest, ""},
		{"path nine deep", cookie, pid, signedComment(t, gid, owner, copts{path: "0001.0001.0001.0001.0001.0001.0001.0001.0001"}), http.StatusBadRequest, ""},
		{"path unpadded", cookie, pid, signedComment(t, gid, owner, copts{path: "1"}), http.StatusBadRequest, ""},
		{"signed for another path", cookie, pid, signedComment(t, gid, owner, copts{signedPath: "0002"}), http.StatusBadRequest, "bad_signature"},
		{"signed over other ciphertext", cookie, pid, signedComment(t, gid, owner, copts{signedCt: []byte("something else")}), http.StatusBadRequest, "bad_signature"},
		{"signed as a post", cookie, pid, func() createCommentRequest {
			r := signedComment(t, gid, owner, copts{})
			payload := crypto.SignedPayload(owner.userID, gid, "CMT#0001", 0, r.SignedDay, mustDecode(t, r.Ciphertext))
			sig, _ := crypto.Sign(owner.signPriv, crypto.ContextPost, payload)
			r.Signature = base64.StdEncoding.EncodeToString(sig)
			return r
		}(), http.StatusBadRequest, "bad_signature"},
		{"signed by someone else", cookie, pid, signedComment(t, gid, owner, copts{signer: other}), http.StatusBadRequest, "bad_signature"},
		{"wrong generation", cookie, pid, signedComment(t, gid, owner, copts{generation: 1}), http.StatusConflict, "generation_stale"},
		{"signing day too old", cookie, pid, signedComment(t, gid, owner, copts{signedDay: time.Now().UTC().AddDate(0, 0, -3).Format("2006-01-02")}), http.StatusBadRequest, ""},
		{"signing day not a date", cookie, pid, signedComment(t, gid, owner, copts{signedDay: "yesterday"}), http.StatusBadRequest, ""},
		{"ciphertext too short", cookie, pid, short, http.StatusBadRequest, ""},
		{"ciphertext too long", cookie, pid, signedComment(t, gid, owner, copts{ctLen: h.commentCiphertextLimit() + 1}), http.StatusBadRequest, ""},
		{"parent missing", cookie, pid, signedComment(t, gid, owner, copts{path: "0001.0001"}), http.StatusConflict, "parent_gone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := doComment(t, h, tc.cookie, tc.pid, tc.req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			if tc.code != "" && errCode(t, rec) != tc.code {
				t.Fatalf("code = %q, want %q", errCode(t, rec), tc.code)
			}
			if tc.status != http.StatusUnauthorized && getRow(t, "POST#"+pid, "CMT#"+tc.req.Path) != nil {
				t.Error("a refused comment left a row")
			}
		})
	}
}

func mustDecode(t *testing.T, b64 string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCreateCommentRefusesADormantMember(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	setProfileKeyEpoch(t, owner.userID, 1)
	rec := doComment(t, h, cookie, pid, signedComment(t, gid, owner, copts{}))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "member_dormant" {
		t.Fatalf("dormant: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCreateCommentOnAnExpiredPostIsNotFound(t *testing.T) {
	h, gid, owner, cookie := postFixture(t)
	postKey := "POST#2026-10-28#00112233445566fd"
	storePostAt(t, gid, postKey, owner.userID, time.Now().Add(-time.Hour).Unix())
	rec := doComment(t, h, cookie, pidOf(gid, postKey), signedComment(t, gid, owner, copts{}))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expired post: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCreateCommentResendIsOneCommentAndADifferentOneAtTheSamePathIsRefusedWithTheNextFreePath(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	first := signedComment(t, gid, owner, copts{})
	for i := 0; i < 2; i++ {
		if rec := doComment(t, h, cookie, pid, first); rec.Code != http.StatusCreated {
			t.Fatalf("send %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	rec := doComment(t, h, cookie, pid, signedComment(t, gid, owner, copts{}))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "comment_path_taken" {
		t.Fatalf("second writer: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		NextPath string `json:"nextPath"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.NextPath != "0002" {
		t.Fatalf("nextPath = %q, want 0002", body.NextPath)
	}
	if rec := doComment(t, h, cookie, pid, signedComment(t, gid, owner, copts{path: body.NextPath})); rec.Code != http.StatusCreated {
		t.Fatalf("with the hinted path: %d %s", rec.Code, rec.Body.String())
	}
	if got := mustDecode(t, strAttrBlob(t, pid, "0001")); !bytes.Equal(got, mustDecode(t, first.Ciphertext)) {
		t.Error("the loser overwrote the first comment")
	}
}

func strAttrBlob(t *testing.T, pid, path string) string {
	t.Helper()
	row := getRow(t, "POST#"+pid, "CMT#"+path)
	b, ok := row["Ciphertext"].(*types.AttributeValueMemberB)
	if !ok {
		t.Fatal("no ciphertext")
	}
	return base64.StdEncoding.EncodeToString(b.Value)
}

func TestNextPathHintLooksPastTheLastChildsDescendants(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	for _, p := range []string{"0001", "0001.0001", "0001.0002", "0001.0002.0001", "0001.0002.0005", "0002"} {
		storeCommentAt(t, pid, p, owner.userID, 0)
	}
	cases := map[string]string{
		"0001.0001": "0001.0003", // the highest key under 0001 is a grandchild of 0001.0002
		"0001":      "0003",      // top level: 0002 is the last
	}
	for taken, want := range cases {
		rec := doComment(t, h, cookie, pid, signedComment(t, gid, owner, copts{path: taken}))
		if rec.Code != http.StatusConflict || errCode(t, rec) != "comment_path_taken" {
			t.Fatalf("%s: %d %s", taken, rec.Code, rec.Body.String())
		}
		var body struct {
			NextPath string `json:"nextPath"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body.NextPath != want {
			t.Errorf("taken %s: nextPath = %q, want %q", taken, body.NextPath, want)
		}
	}
}

func TestACommentWithNoRoomForANewSiblingSaysSo(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	storeCommentAt(t, pid, "9999", owner.userID, 0)
	rec := doComment(t, h, cookie, pid, signedComment(t, gid, owner, copts{path: "9999"}))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "replies_full" {
		t.Fatalf("full: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCreateCommentAcceptsAReplyUnderAnExistingParentToTheDepthCap(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	path := "0001"
	for depth := 1; depth <= 8; depth++ {
		if rec := doComment(t, h, cookie, pid, signedComment(t, gid, owner, copts{path: path})); rec.Code != http.StatusCreated {
			t.Fatalf("depth %d (%s): %d %s", depth, path, rec.Code, rec.Body.String())
		}
		path += ".0001"
	}
	deeper := strings.TrimSuffix(path, ".0001") + ".0001"
	if rec := doComment(t, h, cookie, pid, signedComment(t, gid, owner, copts{path: deeper})); rec.Code != http.StatusBadRequest {
		t.Fatalf("ninth level %s: %d %s", deeper, rec.Code, rec.Body.String())
	}
}

func TestCreateCommentUsesItsOwnSizeCap(t *testing.T) {
	cfg := config.FromEnv()
	cfg.MaxCommentBytes = 10
	cfg.MaxPostBodyBytes = 100000
	h := New(cfg, testDB(t))
	owner, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, cookie)
	post, _ := signedPost(t, gid, owner, postOpts{})
	if rec := doPost(t, h, cookie, gid, post); rec.Code != http.StatusCreated {
		t.Fatalf("post: %d %s", rec.Code, rec.Body.String())
	}
	pid := pidOf(gid, post.SortKey)
	if rec := doComment(t, h, cookie, pid, signedComment(t, gid, owner, copts{ctLen: 10 + commentEnvelopeOverhead})); rec.Code != http.StatusCreated {
		t.Fatalf("at the limit: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doComment(t, h, cookie, pid, signedComment(t, gid, owner, copts{path: "0002", ctLen: 10 + commentEnvelopeOverhead + 1})); rec.Code != http.StatusBadRequest {
		t.Fatalf("one over: %d %s", rec.Code, rec.Body.String())
	}
}

func TestThreadServesCommentsInDisplayOrderWhateverTheWriteOrder(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	_ = gid
	for _, p := range []string{"0002", "0001.0002", "0001", "0003.0001.0002", "0001.0001", "0003", "0003.0001", "0010", "0009"} {
		storeCommentAt(t, pid, p, owner.userID, 0)
	}
	out := decodeThread(t, doThread(t, h, cookie, pid, ""))
	want := []string{"0001", "0001.0001", "0001.0002", "0002", "0003", "0003.0001", "0003.0001.0002", "0009", "0010"}
	if got := threadPaths(out); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v", got, want)
	}
	if out.NextCursor != "" {
		t.Errorf("cursor = %q on a short thread", out.NextCursor)
	}
}

func TestThreadPagesByCursorWithoutRepeatsOrGapsAndReactionsFollowTheirComments(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	_ = gid
	for _, p := range []string{"0001", "0001.0001", "0001.0002", "0002"} {
		storeCommentAt(t, pid, p, owner.userID, 0)
	}
	// A is a stand-in reactor id; reactions on the post, a comment, its reply, the
	// reply's sibling (the first comment of page two) and the last comment.
	for _, x := range [][2]string{
		{"0000", "aaaa"}, {"0001", "aaaa"}, {"0001", "bbbb"}, {"0001.0001", "aaaa"}, {"0001.0002", "aaaa"}, {"0002", "bbbb"},
		{"0005", "aaaa"}, // targets a comment that does not exist, after the last one
	} {
		storeReactionAt(t, pid, x[0], x[1])
	}
	page1 := decodeThread(t, doThread(t, h, cookie, pid, "?limit=2"))
	if got := strings.Join(threadPaths(page1), ","); got != "0001,0001.0001" || page1.NextCursor != "0001.0001" {
		t.Fatalf("page 1 = %s, cursor %q", got, page1.NextCursor)
	}
	if got := strings.Join(reactionTargets(page1), ","); got != "0000,0001,0001,0001.0001" {
		t.Fatalf("page 1 reactions = %s, want the post's, 0001's two and 0001.0001's", got)
	}
	page2 := decodeThread(t, doThread(t, h, cookie, pid, "?limit=2&cursor="+page1.NextCursor))
	if got := strings.Join(threadPaths(page2), ","); got != "0001.0002,0002" || page2.NextCursor != "" {
		t.Fatalf("page 2 = %s, cursor %q", got, page2.NextCursor)
	}
	if got := strings.Join(reactionTargets(page2), ","); got != "0001.0002,0002" {
		t.Fatalf("page 2 reactions = %s, want 0001.0002's and 0002's, not the post's again", got)
	}
}

func TestThreadReactionsOnARepliesOfAPagesLastCommentWaitForTheirOwnPage(t *testing.T) {
	h, _, pid, owner, cookie := commentFixture(t)
	for _, p := range []string{"0001", "0001.0001", "0002"} {
		storeCommentAt(t, pid, p, owner.userID, 0)
	}
	for _, target := range []string{"0001", "0001.0001", "0002"} {
		storeReactionAt(t, pid, target, "aaaa")
	}
	// The page ends at 0001; 0001.0001 sorts right after it and so do its
	// reactions, but they belong with their comment on the next page.
	page1 := decodeThread(t, doThread(t, h, cookie, pid, "?limit=1"))
	if got := strings.Join(reactionTargets(page1), ","); got != "0001" {
		t.Fatalf("page 1 reactions = %s, want only 0001's", got)
	}
	page2 := decodeThread(t, doThread(t, h, cookie, pid, "?limit=1&cursor="+page1.NextCursor))
	if got := strings.Join(reactionTargets(page2), ","); got != "0001.0001" {
		t.Fatalf("page 2 reactions = %s, want only 0001.0001's", got)
	}
}

func TestThreadPageCutShortByTheQuerySizeLimitStillHasACursor(t *testing.T) {
	h, _, pid, owner, cookie := commentFixture(t)
	// 60 comments of 40,000 bytes are 2.4 MB: a query stops at 1 MB with fewer
	// than the 50 asked for, and says so only through LastEvaluatedKey.
	const total = 60
	var want []string
	for i := 1; i <= total; i++ {
		path := fmt.Sprintf("%04d", i)
		storeCommentSized(t, pid, path, owner.userID, 0, 40000)
		want = append(want, path)
	}
	first := decodeThread(t, doThread(t, h, cookie, pid, ""))
	if len(first.Comments) >= defaultCommentPageSize || first.NextCursor == "" {
		t.Fatalf("first page = %d comments, cursor %q; want a page cut short by size with a cursor to continue", len(first.Comments), first.NextCursor)
	}
	var got []string
	cursor := ""
	for pages := 0; pages < 20; pages++ {
		q := ""
		if cursor != "" {
			q = "?cursor=" + cursor
		}
		out := decodeThread(t, doThread(t, h, cookie, pid, q))
		got = append(got, threadPaths(out)...)
		if out.NextCursor == "" {
			break
		}
		cursor = out.NextCursor
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("paged %d comments, want all %d in order: %v", len(got), total, got)
	}
}

func TestThreadWithNoCommentsStillServesThePostsOwnReactions(t *testing.T) {
	h, _, pid, owner, cookie := commentFixture(t)
	storeReactionAt(t, pid, "0000", owner.userID)
	out := decodeThread(t, doThread(t, h, cookie, pid, ""))
	if len(out.Comments) != 0 || len(out.Reactions) != 1 || out.Reactions[0].Target != "0000" || out.Reactions[0].ReactorUserID != owner.userID {
		t.Fatalf("thread = %+v", out)
	}
}

func TestThreadRefusesWhatItShould(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	_, outsiderCookie := loggedInUser(t, h)
	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
		pid    string
		query  string
		status int
	}{
		{"no session", nil, pid, "", http.StatusUnauthorized},
		{"not a member", outsiderCookie, pid, "", http.StatusNotFound},
		{"malformed post id", cookie, "nonsense", "", http.StatusNotFound},
		{"missing post", cookie, pidOf(gid, "POST#2020-01-01#0000000000000000"), "", http.StatusNotFound},
		{"limit zero", cookie, pid, "?limit=0", http.StatusBadRequest},
		{"limit too big", cookie, pid, "?limit=" + strconv.Itoa(maxCommentPageSize+1), http.StatusBadRequest},
		{"cursor not a path", cookie, pid, "?cursor=RXN%230000%23x", http.StatusBadRequest},
		{"cursor 0000", cookie, pid, "?cursor=0000", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := doThread(t, h, tc.cookie, tc.pid, tc.query); rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
	_ = owner
}

func TestThreadOfAnExpiredPostIsNotFoundAndADormantMemberCanStillRead(t *testing.T) {
	h, gid, owner, cookie := postFixture(t)
	expiredKey := "POST#2026-10-28#00112233445566fc"
	storePostAt(t, gid, expiredKey, owner.userID, time.Now().Add(-time.Hour).Unix())
	if rec := doThread(t, h, cookie, pidOf(gid, expiredKey), ""); rec.Code != http.StatusNotFound {
		t.Fatalf("expired: %d %s", rec.Code, rec.Body.String())
	}
	liveKey := "POST#2026-10-28#00112233445566fb"
	storePostAt(t, gid, liveKey, owner.userID, 0)
	live := pidOf(gid, liveKey)
	storeCommentAt(t, live, "0001", owner.userID, 0)
	setProfileKeyEpoch(t, owner.userID, 1)
	out := decodeThread(t, doThread(t, h, cookie, live, ""))
	if len(out.Comments) != 1 {
		t.Fatalf("dormant member read %d comments, want 1", len(out.Comments))
	}
}

func TestThreadServesTheStoredFieldsOfEachComment(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	req := signedComment(t, gid, owner, copts{})
	if rec := doComment(t, h, cookie, pid, req); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	out := decodeThread(t, doThread(t, h, cookie, pid, ""))
	if len(out.Comments) != 1 {
		t.Fatalf("comments = %d", len(out.Comments))
	}
	got := out.Comments[0]
	want := commentEntry{Path: "0001", AuthorUserID: owner.userID, Generation: 0, SignedDay: req.SignedDay, Nonce: req.Nonce, Ciphertext: req.Ciphertext, Signature: req.Signature}
	if got != want {
		t.Fatalf("comment = %+v, want %+v", got, want)
	}
}

func TestConfigServesTheCommentCap(t *testing.T) {
	cfg := config.FromEnv()
	cfg.MaxCommentBytes = 1234
	h := New(cfg, testDB(t))
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	var out struct {
		MaxCommentBytes int `json:"maxCommentBytes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.MaxCommentBytes != 1234 {
		t.Fatalf("config = %s (%v)", rec.Body.String(), err)
	}
}
