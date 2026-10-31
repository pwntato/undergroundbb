package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

// sealedReaction is a request body of the one length a reaction seals to. The
// bytes are random: the server cannot open them, only size them.
func sealedReaction(t *testing.T, generation int64) putReactionRequest {
	t.Helper()
	ct := make([]byte, crypto.ReactionCiphertextSize)
	nonce := make([]byte, crypto.NonceSize)
	_, _ = rand.Read(ct)
	_, _ = rand.Read(nonce)
	return putReactionRequest{
		Generation: generation,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
}

func doReaction(t *testing.T, h *Handler, method string, cookie *http.Cookie, pid, target string, body any) *httptest.ResponseRecorder {
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
	req := httptest.NewRequest(method, "/api/posts/"+url.PathEscape(pid)+"/reactions/"+target, &buf)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func TestPutReactionStoresOneUnsignedRowWithThePostsTTLAndNoTime(t *testing.T) {
	h, gid, owner, cookie := postFixture(t)
	future := time.Now().Add(72 * time.Hour).Unix()
	postKey := "POST#2026-10-28#00112233445566e1"
	storePostAt(t, gid, postKey, owner.userID, future)
	pid := pidOf(gid, postKey)
	storeCommentAt(t, pid, "0001", owner.userID, future)

	for _, target := range []string{"0000", "0001"} {
		req := sealedReaction(t, 0)
		if rec := doReaction(t, h, http.MethodPut, cookie, pid, target, req); rec.Code != http.StatusNoContent {
			t.Fatalf("put on %s: %d %s", target, rec.Code, rec.Body.String())
		}
		row := getRow(t, "POST#"+pid, "RXN#"+target+"#"+owner.userID)
		if row == nil {
			t.Fatalf("%s: no row stored", target)
		}
		if strAttr(row, "Type") != "REACTION" || numAttr(row, "Generation") != "0" {
			t.Errorf("%s: row = %v", target, row)
		}
		if got := numAttr(row, "TTL"); got != strconv.FormatInt(future, 10) {
			t.Errorf("%s: TTL = %s, want the post's %d", target, got, future)
		}
		// A reaction records no signature and no time of any kind.
		for name := range row {
			switch name {
			case "PK", "SK", "Type", "Generation", "Nonce", "Ciphertext", "TTL":
			default:
				t.Errorf("%s: unexpected attribute %q on a reaction row", target, name)
			}
		}
		if b, ok := row["Ciphertext"].(*types.AttributeValueMemberB); !ok || len(b.Value) != crypto.ReactionCiphertextSize {
			t.Errorf("%s: ciphertext = %v", target, row["Ciphertext"])
		}
	}
}

func TestPutReactionOnAPostThatNeverExpiresHasNoTTL(t *testing.T) {
	h, gid, owner, cookie := postFixture(t)
	postKey := "POST#2026-10-28#00112233445566e2"
	storePostAt(t, gid, postKey, owner.userID, 0)
	pid := pidOf(gid, postKey)
	if rec := doReaction(t, h, http.MethodPut, cookie, pid, "0000", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	if _, has := getRow(t, "POST#"+pid, "RXN#0000#"+owner.userID)["TTL"]; has {
		t.Error("a reaction on a post with no expiry carries a TTL")
	}
}

func TestPutReactionReplacesTheReactorsEarlierOneAndResendIsHarmless(t *testing.T) {
	h, _, pid, owner, cookie := commentFixture(t)
	first := sealedReaction(t, 0)
	second := sealedReaction(t, 0)
	for i, req := range []putReactionRequest{first, second, second} {
		if rec := doReaction(t, h, http.MethodPut, cookie, pid, "0000", req); rec.Code != http.StatusNoContent {
			t.Fatalf("put %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	row := getRow(t, "POST#"+pid, "RXN#0000#"+owner.userID)
	if got := base64.StdEncoding.EncodeToString(row["Ciphertext"].(*types.AttributeValueMemberB).Value); got != second.Ciphertext {
		t.Errorf("stored ciphertext is not the latest one's")
	}
	out := decodeThread(t, doThread(t, h, cookie, pid, ""))
	if len(out.Reactions) != 1 {
		t.Fatalf("thread carries %d reactions, want the one", len(out.Reactions))
	}
}

func TestPutReactionIsReadBackByTheThreadWithItsTargetAndReactor(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	storeCommentAt(t, pid, "0001", owner.userID, 0)
	other, otherCookie := loggedInUser(t, h)
	addMember(t, gid, other, "member")
	for _, c := range []*http.Cookie{cookie, otherCookie} {
		for _, target := range []string{"0000", "0001"} {
			if rec := doReaction(t, h, http.MethodPut, c, pid, target, sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
				t.Fatalf("put on %s: %d %s", target, rec.Code, rec.Body.String())
			}
		}
	}
	out := decodeThread(t, doThread(t, h, otherCookie, pid, ""))
	got := map[string]bool{}
	for _, x := range out.Reactions {
		got[x.Target+"/"+x.ReactorUserID] = true
	}
	for _, want := range []string{"0000/" + owner.userID, "0000/" + other.userID, "0001/" + owner.userID, "0001/" + other.userID} {
		if !got[want] {
			t.Errorf("thread is missing reaction %s; has %v", want, got)
		}
	}
}

func TestPutReactionRefusesWhatItShould(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	storeCommentAt(t, pid, "0001", owner.userID, 0)
	_, outsiderCookie := loggedInUser(t, h)
	withCT := func(n int) putReactionRequest {
		r := sealedReaction(t, 0)
		r.Ciphertext = base64.StdEncoding.EncodeToString(make([]byte, n))
		return r
	}
	badNonce := sealedReaction(t, 0)
	badNonce.Nonce = base64.StdEncoding.EncodeToString(make([]byte, crypto.NonceSize-1))
	noNonce := sealedReaction(t, 0)
	noNonce.Nonce = ""
	notBase64 := sealedReaction(t, 0)
	notBase64.Ciphertext = "!!!"
	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
		pid    string
		target string
		req    putReactionRequest
		status int
		code   string
	}{
		{"no session", nil, pid, "0000", sealedReaction(t, 0), http.StatusUnauthorized, ""},
		{"not a member", outsiderCookie, pid, "0000", sealedReaction(t, 0), http.StatusNotFound, ""},
		{"malformed post id", cookie, "nonsense", "0000", sealedReaction(t, 0), http.StatusNotFound, ""},
		{"missing post", cookie, pidOf(gid, "POST#2020-01-01#0000000000000000"), "0000", sealedReaction(t, 0), http.StatusNotFound, ""},
		{"target not a path", cookie, pid, "abc", sealedReaction(t, 0), http.StatusBadRequest, ""},
		{"target unpadded", cookie, pid, "1", sealedReaction(t, 0), http.StatusBadRequest, ""},
		{"target zero under a parent", cookie, pid, "0001.0000", sealedReaction(t, 0), http.StatusBadRequest, ""},
		{"target nine deep", cookie, pid, "0001.0001.0001.0001.0001.0001.0001.0001.0001", sealedReaction(t, 0), http.StatusBadRequest, ""},
		{"target is a comment sort key", cookie, pid, "CMT%230001", sealedReaction(t, 0), http.StatusBadRequest, ""},
		{"comment missing", cookie, pid, "0002", sealedReaction(t, 0), http.StatusConflict, "parent_gone"},
		{"ciphertext one byte short", cookie, pid, "0000", withCT(crypto.ReactionCiphertextSize - 1), http.StatusBadRequest, ""},
		{"ciphertext one byte long", cookie, pid, "0000", withCT(crypto.ReactionCiphertextSize + 1), http.StatusBadRequest, ""},
		{"ciphertext a whole comment", cookie, pid, "0000", withCT(120), http.StatusBadRequest, ""},
		{"ciphertext empty", cookie, pid, "0000", withCT(0), http.StatusBadRequest, ""},
		{"ciphertext not base64", cookie, pid, "0000", notBase64, http.StatusBadRequest, ""},
		{"nonce wrong length", cookie, pid, "0000", badNonce, http.StatusBadRequest, ""},
		{"nonce missing", cookie, pid, "0000", noNonce, http.StatusBadRequest, ""},
		{"wrong generation", cookie, pid, "0000", sealedReaction(t, 1), http.StatusConflict, "generation_stale"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := doReaction(t, h, http.MethodPut, tc.cookie, tc.pid, tc.target, tc.req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			if tc.code != "" && errCode(t, rec) != tc.code {
				t.Fatalf("code = %q, want %q", errCode(t, rec), tc.code)
			}
			if tc.status == http.StatusNoContent {
				return
			}
			if n := countRows(t, "POST#"+pid, "RXN#"); n != 0 {
				t.Errorf("a refused reaction left %d rows", n)
			}
		})
	}
}

func TestPutReactionRefusesAMalformedBody(t *testing.T) {
	h, _, pid, _, cookie := commentFixture(t)
	for name, body := range map[string]any{"not an object": "text", "unknown shape": []int{1}} {
		if rec := doReaction(t, h, http.MethodPut, cookie, pid, "0000", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec := doReaction(t, h, http.MethodPut, cookie, pid, "0000", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("empty body: %d", rec.Code)
	}
}

func TestPutReactionRefusesADormantMember(t *testing.T) {
	h, _, pid, owner, cookie := commentFixture(t)
	setProfileKeyEpoch(t, owner.userID, 1)
	rec := doReaction(t, h, http.MethodPut, cookie, pid, "0000", sealedReaction(t, 0))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "member_dormant" {
		t.Fatalf("dormant: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPutReactionOnAnExpiredPostIsNotFound(t *testing.T) {
	h, gid, owner, cookie := postFixture(t)
	postKey := "POST#2026-10-28#00112233445566e3"
	storePostAt(t, gid, postKey, owner.userID, time.Now().Add(-time.Hour).Unix())
	rec := doReaction(t, h, http.MethodPut, cookie, pidOf(gid, postKey), "0000", sealedReaction(t, 0))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expired post: %d %s", rec.Code, rec.Body.String())
	}
}

// The handler reads the group, the member and the marker and then writes in a
// transaction; these call the transaction with a view that has since gone
// stale, as a concurrent change would leave it.
func TestPutReactionTransactionRefusesAStaleView(t *testing.T) {
	h, gid, pid, owner, _ := commentFixture(t)
	_, postKey, _ := idgen.ParsePostID(pid)
	expiredKey := "POST#2026-10-28#00112233445566e6"
	storePostAt(t, gid, expiredKey, owner.userID, time.Now().Add(-time.Hour).Unix())
	storeCommentAt(t, pid, "0001", owner.userID, 0)
	input := func() db.PutReactionInput {
		return db.PutReactionInput{
			GroupID: gid, PostID: pid, PostSortKey: postKey, Target: "0000", ReactorID: owner.userID,
			Nonce: make([]byte, crypto.NonceSize), Ciphertext: make([]byte, crypto.ReactionCiphertextSize),
			Now: time.Now(),
		}
	}
	if err := h.db.PutReaction(context.Background(), input()); err != nil {
		t.Fatalf("a fresh view: %v", err)
	}
	if err := h.db.DeleteReaction(context.Background(), pid, "0000", owner.userID); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		marker bool // a rotation marker for generation 1 exists
		mod    func(*db.PutReactionInput)
		want   error // nil: any refusal
	}{
		{"post missing", false, func(in *db.PutReactionInput) { in.PostSortKey = "POST#2020-01-01#0000000000000000" }, db.ErrCommentPostGone},
		{"post expired", false, func(in *db.PutReactionInput) {
			in.PostID, in.PostSortKey = pidOf(gid, expiredKey), expiredKey
		}, db.ErrCommentPostGone},
		{"comment gone", false, func(in *db.PutReactionInput) { in.Target = "0009" }, db.ErrReactionTargetGone},
		{"member behind the generation", false, func(in *db.PutReactionInput) { in.Generation = 5 }, db.ErrPostMemberChanged},
		{"marker appeared", true, func(in *db.PutReactionInput) {}, db.ErrPostMarkerChanged},
		{"marker moved on", true, func(in *db.PutReactionInput) { in.MarkerPresent = true; in.MarkerGeneration = 9 }, db.ErrPostMarkerChanged},
		{"keys rotated", false, func(in *db.PutReactionInput) { in.ReactorKeyEpoch = 7 }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.marker {
				putRotationMarker(t, gid, 1)
				defer deleteRotationMarker(t, gid)
			}
			in := input()
			tc.mod(&in)
			err := h.db.PutReaction(context.Background(), in)
			switch {
			case err == nil:
				t.Fatal("a stale view was accepted")
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if n := countRows(t, "POST#"+in.PostID, "RXN#"); n != 0 {
				t.Errorf("a refused reaction left %d rows", n)
			}
			if n := countRows(t, "POST#"+pid, "RXN#"); n != 0 {
				t.Errorf("a refused reaction left %d rows", n)
			}
		})
	}
}

func putRotationMarker(t *testing.T, gid string, generation int) {
	t.Helper()
	putCommentRow(t, map[string]types.AttributeValue{
		"PK": s("GROUP#" + gid), "SK": s(db.RotationSortKey), "Type": s("ROTATION"),
		"Generation": &types.AttributeValueMemberN{Value: strconv.Itoa(generation)},
	})
}

func deleteRotationMarker(t *testing.T, gid string) {
	t.Helper()
	if _, err := rawDDB(t).DeleteItem(context.Background(), &dynamodb.DeleteItemInput{
		TableName: aws.String(testTableName()),
		Key:       map[string]types.AttributeValue{"PK": s("GROUP#" + gid), "SK": s(db.RotationSortKey)},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteReactionRemovesOnlyTheCallersOwn(t *testing.T) {
	h, gid, pid, owner, cookie := commentFixture(t)
	other, otherCookie := loggedInUser(t, h)
	addMember(t, gid, other, "member")
	for _, c := range []*http.Cookie{cookie, otherCookie} {
		if rec := doReaction(t, h, http.MethodPut, c, pid, "0000", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
			t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
		}
	}
	if rec := doReaction(t, h, http.MethodDelete, otherCookie, pid, "0000", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if getRow(t, "POST#"+pid, "RXN#0000#"+other.userID) != nil {
		t.Error("the caller's own reaction is still there")
	}
	if getRow(t, "POST#"+pid, "RXN#0000#"+owner.userID) == nil {
		t.Error("deleting removed another member's reaction")
	}
	// Undoing twice, and undoing what was never there, are the same answer.
	for i := 0; i < 2; i++ {
		if rec := doReaction(t, h, http.MethodDelete, otherCookie, pid, "0000", nil); rec.Code != http.StatusNoContent {
			t.Errorf("repeat delete %d: %d", i, rec.Code)
		}
	}
	if rec := doReaction(t, h, http.MethodDelete, otherCookie, pid, "0007", nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete of a reaction never made: %d", rec.Code)
	}
}

func TestDeleteReactionRefusesWhatItShould(t *testing.T) {
	h, gid, owner, cookie := postFixture(t)
	_, outsiderCookie := loggedInUser(t, h)
	postKey := "POST#2026-10-28#00112233445566e4"
	storePostAt(t, gid, postKey, owner.userID, 0)
	pid := pidOf(gid, postKey)
	expiredKey := "POST#2026-10-28#00112233445566e5"
	storePostAt(t, gid, expiredKey, owner.userID, time.Now().Add(-time.Hour).Unix())
	if rec := doReaction(t, h, http.MethodPut, cookie, pid, "0000", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put: %d", rec.Code)
	}
	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
		pid    string
		target string
		status int
	}{
		{"no session", nil, pid, "0000", http.StatusUnauthorized},
		{"not a member", outsiderCookie, pid, "0000", http.StatusNotFound},
		{"malformed post id", cookie, "nonsense", "0000", http.StatusNotFound},
		{"missing post", cookie, pidOf(gid, "POST#2020-01-01#0000000000000000"), "0000", http.StatusNotFound},
		{"expired post", cookie, pidOf(gid, expiredKey), "0000", http.StatusNotFound},
		{"bad target", cookie, pid, "abc", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := doReaction(t, h, http.MethodDelete, tc.cookie, tc.pid, tc.target, nil); rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			if getRow(t, "POST#"+pid, "RXN#0000#"+owner.userID) == nil {
				t.Error("a refused delete removed the reaction")
			}
		})
	}
}

func TestDeleteReactionWorksForADormantMember(t *testing.T) {
	h, _, pid, owner, cookie := commentFixture(t)
	if rec := doReaction(t, h, http.MethodPut, cookie, pid, "0000", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put: %d", rec.Code)
	}
	setProfileKeyEpoch(t, owner.userID, 1)
	if rec := doReaction(t, h, http.MethodDelete, cookie, pid, "0000", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if getRow(t, "POST#"+pid, "RXN#0000#"+owner.userID) != nil {
		t.Error("a dormant member could not take back their reaction")
	}
}

func countRows(t *testing.T, pk, skPrefix string) int {
	t.Helper()
	out, err := rawDDB(t).Query(context.Background(), &dynamodb.QueryInput{
		TableName:                 aws.String(testTableName()),
		ConsistentRead:            aws.Bool(true),
		KeyConditionExpression:    aws.String("PK = :pk AND begins_with(SK, :p)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": s(pk), ":p": s(skPrefix)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return len(out.Items)
}
