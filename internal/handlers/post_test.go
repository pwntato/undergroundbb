package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
)

// Creating a post (#42). The server cannot read a post, so these pin the
// checks it can make: membership, the generation new posts use, dormancy, the
// day, the ciphertext size, and the signature under the author's CURRENT key
// over the post's own address.

type postOpts struct {
	signer     registeredUser // defaults to the author
	sortKey    string         // defaults to today's
	generation int64
	ctLen      int // defaults to a small valid ciphertext
	// signedKey and signedCt, when set, are what the signature covers instead
	// of the request's own, to prove each is bound.
	signedKey string
	signedCt  []byte
}

func todaySortKey(t *testing.T) string {
	t.Helper()
	suffix, err := idgen.DaySuffix(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return "POST#" + suffix
}

func signedPost(t *testing.T, gid string, author registeredUser, o postOpts) (createPostRequest, []byte) {
	t.Helper()
	if o.sortKey == "" {
		o.sortKey = todaySortKey(t)
	}
	if o.ctLen == 0 {
		o.ctLen = 120
	}
	if o.signer.userID == "" {
		o.signer = author
	}
	ct := make([]byte, o.ctLen)
	_, _ = rand.Read(ct)
	nonce := make([]byte, crypto.NonceSize)
	_, _ = rand.Read(nonce)
	signedKey, signedCt := o.sortKey, ct
	if o.signedKey != "" {
		signedKey = o.signedKey
	}
	if o.signedCt != nil {
		signedCt = o.signedCt
	}
	day := o.sortKey[len("POST#") : len("POST#")+10]
	payload := crypto.SignedPayload(author.userID, gid, signedKey, uint64(o.generation), day, signedCt)
	sig, err := crypto.Sign(o.signer.signPriv, crypto.ContextPost, payload)
	if err != nil {
		t.Fatal(err)
	}
	return createPostRequest{
		SortKey:    o.sortKey,
		Generation: o.generation,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
		Signature:  base64.StdEncoding.EncodeToString(sig),
	}, ct
}

func doPost(t *testing.T, h *Handler, cookie *http.Cookie, gid string, body createPostRequest) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/groups/"+gid+"/posts", &buf)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func postFixture(t *testing.T) (h *Handler, gid string, owner registeredUser, ownerCookie *http.Cookie) {
	t.Helper()
	h = New(config.FromEnv(), testDB(t))
	owner, ownerCookie = loggedInUser(t, h)
	gid = createPrivateGroup(t, h, owner, ownerCookie)
	return
}

func setProfileKeyEpoch(t *testing.T, userID string, epoch int) {
	t.Helper()
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:                 aws.String(testTableName()),
		Key:                       map[string]types.AttributeValue{"PK": s("USER#" + userID), "SK": s("PROFILE")},
		UpdateExpression:          aws.String("SET KeyEpoch = :e"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":e": &types.AttributeValueMemberN{Value: strconv.Itoa(epoch)}},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCreatePostStoresTheSignedCiphertextWithADayRoundedTTL(t *testing.T) {
	h, gid, owner, cookie := postFixture(t)
	days := numAttr(getRow(t, "GROUP#"+gid, "META"), "ExpirationDays")
	n, _ := strconv.Atoi(days)
	if n <= 0 {
		t.Fatalf("test group has no expiration (%q)", days)
	}
	req, ct := signedPost(t, gid, owner, postOpts{})
	lo := db.RoundUpToEndOfUTCDay(time.Now().AddDate(0, 0, n)).Unix()
	rec := doPost(t, h, cookie, gid, req)
	hi := db.RoundUpToEndOfUTCDay(time.Now().AddDate(0, 0, n)).Unix()
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	row := getRow(t, "GROUP#"+gid, req.SortKey)
	if row == nil {
		t.Fatal("no row stored")
	}
	if got := row["AuthorUserID"].(*types.AttributeValueMemberS).Value; got != owner.userID {
		t.Errorf("author = %s", got)
	}
	if !bytes.Equal(row["Ciphertext"].(*types.AttributeValueMemberB).Value, ct) {
		t.Error("stored ciphertext differs from the request's")
	}
	ttl, _ := strconv.ParseInt(numAttr(row, "TTL"), 10, 64)
	if ttl != lo && ttl != hi {
		t.Errorf("TTL = %d, want %d (or %d across midnight)", ttl, lo, hi)
	}
	if ttl%86400 != 86399 {
		t.Errorf("TTL %d is not the end of a UTC day", ttl)
	}
}

func TestCreatePostRetryIsIdempotentButADifferentPostAtTheSameAddressIsRefused(t *testing.T) {
	h, gid, owner, cookie := postFixture(t)
	req, _ := signedPost(t, gid, owner, postOpts{})
	if rec := doPost(t, h, cookie, gid, req); rec.Code != http.StatusCreated {
		t.Fatalf("first: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doPost(t, h, cookie, gid, req); rec.Code != http.StatusCreated {
		t.Fatalf("lost-response retry: %d %s", rec.Code, rec.Body.String())
	}
	other, _ := signedPost(t, gid, owner, postOpts{sortKey: req.SortKey})
	rec := doPost(t, h, cookie, gid, other)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "post_exists" {
		t.Fatalf("different post, same address: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCreatePostRefusals(t *testing.T) {
	h, gid, owner, cookie := postFixture(t)
	stranger, strangerCookie := loggedInUser(t, h)
	today := time.Now().UTC()
	oldKey := func() string {
		suffix, _ := idgen.DaySuffix(today.AddDate(0, 0, -3))
		return "POST#" + suffix
	}()
	tooLong := h.postCiphertextLimit() + 1

	tests := []struct {
		name   string
		cookie *http.Cookie
		author registeredUser
		o      postOpts
		mutate func(*createPostRequest)
		status int
		code   string
	}{
		{name: "no session", cookie: nil, author: owner, status: http.StatusUnauthorized},
		{name: "not a member", cookie: strangerCookie, author: stranger, status: http.StatusNotFound},
		{name: "malformed sort key", cookie: cookie, author: owner, mutate: func(r *createPostRequest) { r.SortKey = "POST#2026-10-28#xyz" }, status: http.StatusBadRequest},
		{name: "impossible date", cookie: cookie, author: owner, mutate: func(r *createPostRequest) { r.SortKey = "POST#2026-02-31#00112233445566ff" }, status: http.StatusBadRequest},
		{name: "backdated day", cookie: cookie, author: owner, o: postOpts{sortKey: oldKey}, status: http.StatusBadRequest},
		{name: "wrong generation", cookie: cookie, author: owner, o: postOpts{generation: 1}, status: http.StatusConflict, code: "generation_stale"},
		{name: "over the size cap", cookie: cookie, author: owner, o: postOpts{ctLen: tooLong}, status: http.StatusBadRequest},
		{name: "too short to hold a post", cookie: cookie, author: owner, o: postOpts{ctLen: 20}, status: http.StatusBadRequest},
		{name: "short nonce", cookie: cookie, author: owner, mutate: func(r *createPostRequest) { r.Nonce = b64(8) }, status: http.StatusBadRequest},
		{name: "signed by someone else's key", cookie: cookie, author: owner, o: postOpts{signer: stranger}, status: http.StatusBadRequest, code: "bad_signature"},
		{name: "signature moved to another address", cookie: cookie, author: owner, o: postOpts{signedKey: "POST#2026-01-01#00112233445566ff"}, status: http.StatusBadRequest, code: "bad_signature"},
		{name: "signature over other ciphertext", cookie: cookie, author: owner, o: postOpts{signedCt: []byte("not the ciphertext sent, padded out to look real")}, status: http.StatusBadRequest, code: "bad_signature"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := signedPost(t, gid, tc.author, tc.o)
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			rec := doPost(t, h, tc.cookie, gid, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			if tc.code != "" && errCode(t, rec) != tc.code {
				t.Fatalf("code = %q, want %q", errCode(t, rec), tc.code)
			}
			if tc.status != http.StatusUnauthorized && getRow(t, "GROUP#"+gid, req.SortKey) != nil {
				t.Error("a refused post left a row")
			}
		})
	}
}

func TestCreatePostRefusesADormantMember(t *testing.T) {
	h, gid, owner, cookie := postFixture(t)
	setProfileKeyEpoch(t, owner.userID, 1) // rotated away; the entry is still wrapped to epoch 0
	req, _ := signedPost(t, gid, owner, postOpts{})
	rec := doPost(t, h, cookie, gid, req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "member_dormant" {
		t.Fatalf("dormant: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCreatePostDuringARotationStaysOnTheOldGeneration(t *testing.T) {
	f := startRotation(t) // rotation 0 -> 1 running; the owner is already at 1, carol still at 0
	old, _ := signedPost(t, f.gid, f.carol, postOpts{generation: 0})
	carolCookie := loginCookie(t, f.h, f.carol)
	if rec := doPost(t, f.h, carolCookie, f.gid, old); rec.Code != http.StatusCreated {
		t.Fatalf("carol at the old generation: %d %s", rec.Code, rec.Body.String())
	}
	// The re-wrapped owner can also post at the old generation (the chain gives
	// them that key), but not at the one being rotated to.
	ownerOld, _ := signedPost(t, f.gid, f.owner, postOpts{generation: 0})
	if rec := doPost(t, f.h, f.ownerCookie, f.gid, ownerOld); rec.Code != http.StatusCreated {
		t.Fatalf("owner at the old generation: %d %s", rec.Code, rec.Body.String())
	}
	ownerNew, _ := signedPost(t, f.gid, f.owner, postOpts{generation: 1})
	rec := doPost(t, f.h, f.ownerCookie, f.gid, ownerNew)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "generation_stale" {
		t.Fatalf("owner at the new generation mid-rotation: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCreatePostRefusesAMemberBehindTheGroupsGeneration(t *testing.T) {
	f := startRotation(t)
	for _, u := range []registeredUser{f.carol, f.dave} {
		if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", rewrapReq(1, u)); rec.Code != http.StatusNoContent {
			t.Fatalf("rewrap: %d %s", rec.Code, rec.Body.String())
		}
	}
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "complete", completeRotationRequest{Generation: 1}); rec.Code != http.StatusNoContent {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
	setMemberGeneration(t, f.gid, f.carol.userID, 0)
	req, _ := signedPost(t, f.gid, f.carol, postOpts{generation: 1})
	rec := doPost(t, f.h, loginCookie(t, f.h, f.carol), f.gid, req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "member_behind" {
		t.Fatalf("behind: %d %s", rec.Code, rec.Body.String())
	}
	ok, _ := signedPost(t, f.gid, f.dave, postOpts{generation: 1})
	if rec := doPost(t, f.h, loginCookie(t, f.h, f.dave), f.gid, ok); rec.Code != http.StatusCreated {
		t.Fatalf("a member at the new generation: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPostCiphertextLimitFollowsTheConfiguredCaps(t *testing.T) {
	cfg := config.FromEnv()
	cfg.MaxPostTitleBytes, cfg.MaxPostBodyBytes = 10, 20
	h := New(cfg, testDB(t))
	if got, want := h.postCiphertextLimit(), 10+20+postEnvelopeOverhead; got != want {
		t.Fatalf("limit = %d, want %d", got, want)
	}
	owner, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, cookie)
	fits, _ := signedPost(t, gid, owner, postOpts{ctLen: h.postCiphertextLimit()})
	if rec := doPost(t, h, cookie, gid, fits); rec.Code != http.StatusCreated {
		t.Fatalf("at the limit: %d %s", rec.Code, rec.Body.String())
	}
	over, _ := signedPost(t, gid, owner, postOpts{ctLen: h.postCiphertextLimit() + 1})
	if rec := doPost(t, h, cookie, gid, over); rec.Code != http.StatusBadRequest {
		t.Fatalf("one over: %d %s", rec.Code, rec.Body.String())
	}
}
