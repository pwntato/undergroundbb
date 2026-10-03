package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
)

// putGenKey writes a GENKEY# link directly, with a nonce/ciphertext that
// encode the generation so a test can tell which link it got back.
func putGenKey(t *testing.T, gid string, gen int) {
	t.Helper()
	if _, err := rawDDB(t).PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName: aws.String(testTableName()),
		Item: map[string]types.AttributeValue{
			"PK":   &types.AttributeValueMemberS{Value: "GROUP#" + gid},
			"SK":   &types.AttributeValueMemberS{Value: fmt.Sprintf("GENKEY#%06d", gen)},
			"Type": &types.AttributeValueMemberS{Value: "GenerationKey"},
			"Wrapped": &types.AttributeValueMemberM{Value: map[string]types.AttributeValue{
				"Nonce":      &types.AttributeValueMemberB{Value: []byte(fmt.Sprintf("n%d", gen))},
				"Ciphertext": &types.AttributeValueMemberB{Value: []byte(fmt.Sprintf("c%d", gen))},
			}},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func doKeychain(t *testing.T, h *Handler, cookie *http.Cookie, gid, query string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/groups/"+gid+"/keychain?"+query, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

func decodeKeychain(t *testing.T, rec *httptest.ResponseRecorder) keychainResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("keychain: %d %s", rec.Code, rec.Body.String())
	}
	var resp keychainResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestKeychainReturnsRangeAscendingForMembers(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, cookie)
	other, otherCookie := loggedInUser(t, h)
	otherGid := createPrivateGroup(t, h, other, otherCookie)
	for _, g := range []int{0, 1, 2, 3, 5} {
		putGenKey(t, gid, g)
	}
	putGenKey(t, otherGid, 1) // another group's link must never appear

	resp := decodeKeychain(t, doKeychain(t, h, cookie, gid, "from=1&to=4"))
	if len(resp.Links) != 3 || resp.NextFrom != nil {
		t.Fatalf("links = %+v, next = %v; want generations 1,2,3 and no next", resp.Links, resp.NextFrom)
	}
	for i, want := range []int64{1, 2, 3} {
		l := resp.Links[i]
		if l.Generation != want {
			t.Errorf("link %d generation = %d, want %d", i, l.Generation, want)
		}
		nonce, _ := base64.StdEncoding.DecodeString(l.Wrapped.Nonce)
		if string(nonce) != fmt.Sprintf("n%d", want) {
			t.Errorf("link %d nonce = %q, want n%d", i, nonce, want)
		}
	}

	// A gap (generation 4 is absent) is not an error: the client decides.
	resp = decodeKeychain(t, doKeychain(t, h, cookie, gid, "from=4&to=4"))
	if len(resp.Links) != 0 {
		t.Errorf("a missing generation returned %+v", resp.Links)
	}
}

func TestKeychainPagesAndResumesFromNextFrom(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, cookie)
	total := maxKeychainPage + 5
	for g := 0; g < total; g++ {
		putGenKey(t, gid, g)
	}

	first := decodeKeychain(t, doKeychain(t, h, cookie, gid, fmt.Sprintf("from=0&to=%d", total-1)))
	if len(first.Links) != maxKeychainPage || first.NextFrom == nil || *first.NextFrom != int64(maxKeychainPage) {
		t.Fatalf("first page = %d links, next = %v; want %d and next %d", len(first.Links), first.NextFrom, maxKeychainPage, maxKeychainPage)
	}
	second := decodeKeychain(t, doKeychain(t, h, cookie, gid, fmt.Sprintf("from=%d&to=%d", *first.NextFrom, total-1)))
	if len(second.Links) != 5 || second.NextFrom != nil || second.Links[0].Generation != int64(maxKeychainPage) {
		t.Fatalf("second page = %d links starting %d, next = %v", len(second.Links), second.Links[0].Generation, second.NextFrom)
	}
}

func TestKeychainRefusesNonMembersAndAnonymous(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, cookie)
	putGenKey(t, gid, 0)
	_, outsiderCookie := loggedInUser(t, h)

	if rec := doKeychain(t, h, outsiderCookie, gid, "from=0&to=0"); rec.Code != http.StatusNotFound {
		t.Errorf("non-member: %d, want 404", rec.Code)
	}
	if rec := doKeychain(t, h, nil, gid, "from=0&to=0"); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d, want 401", rec.Code)
	}
	if rec := doKeychain(t, h, cookie, "not-a-uuid", "from=0&to=0"); rec.Code != http.StatusNotFound {
		t.Errorf("bad group id: %d, want 404", rec.Code)
	}
}

func TestKeychainValidatesRange(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, cookie)
	for _, q := range []string{
		"", "from=0", "to=0", "from=a&to=1", "from=-1&to=1", "from=0&to=1000000", "from=3&to=2",
	} {
		if rec := doKeychain(t, h, cookie, gid, q); rec.Code != http.StatusBadRequest {
			t.Errorf("query %q: %d, want 400", q, rec.Code)
		}
	}
}
