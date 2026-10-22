package handlers

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/models"
)

// rotateOpts varies one thing about a signed rotation request so a test can
// break exactly that.
type rotateOpts struct {
	epoch       uint64 // the epoch signed into the payload; also expectedKeyEpoch
	credVersion int64
	day         string
	roster      [][]byte
	// signedRoster, when set, is the roster the signatures cover while the
	// request lists roster instead.
	signedRoster [][]byte
	newWrap      []byte // default: random
	newSignPub   ed25519.PublicKey
	newSignPriv  ed25519.PrivateKey
	oldSigner    ed25519.PrivateKey // default: the user's own key
	// newSigner, when set, makes the second signature with a key that is not the
	// new one, leaving the first (and the payload) valid.
	newSigner ed25519.PrivateKey
	prefs     *wrappedBlob
}

type rotation struct {
	req rotateKeysRequest
	// next is the account as it reads after this rotation commits.
	next registeredUser
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func signedRotation(t *testing.T, user registeredUser, o rotateOpts) rotation {
	t.Helper()
	if o.credVersion == 0 {
		o.credVersion = 1
	}
	if o.day == "" {
		o.day = utcToday()
	}
	if o.newWrap == nil {
		o.newWrap = randBytes(32)
	}
	if o.newSignPub == nil {
		pub, priv, err := crypto.GenerateSigningKey()
		if err != nil {
			t.Fatal(err)
		}
		o.newSignPub, o.newSignPriv = pub, priv
	}
	if o.oldSigner == nil {
		o.oldSigner = user.signPriv
	}
	signed := o.signedRoster
	if signed == nil {
		signed = o.roster
	}
	payload := crypto.KeyRotationPayload(user.userID, user.signPub, user.wrapPub, o.newSignPub, o.newWrap, o.day, o.epoch, crypto.RosterDigest(signed))
	oldSig, err := crypto.Sign(o.oldSigner, crypto.ContextKeyRotation, payload)
	if err != nil {
		t.Fatal(err)
	}
	newSigningKey := o.newSignPriv
	if o.newSigner != nil {
		newSigningKey = o.newSigner
	}
	newSig, err := crypto.Sign(newSigningKey, crypto.ContextKeyRotation, payload)
	if err != nil {
		t.Fatal(err)
	}
	roster := make([]string, 0, len(o.roster))
	for _, e := range o.roster {
		roster = append(roster, pinB64(e))
	}
	next := user
	next.signPub, next.signPriv, next.wrapPub = o.newSignPub, o.newSignPriv, o.newWrap
	return rotation{
		req: rotateKeysRequest{
			ExpectedKeyEpoch:          o.epoch,
			ExpectedCredentialVersion: o.credVersion,
			SignedDay:                 o.day,
			NewSigningPublicKey:       pinB64(o.newSignPub),
			NewWrappingPublicKey:      pinB64(o.newWrap),
			Roster:                    roster,
			OldSignature:              pinB64(oldSig),
			NewSignature:              pinB64(newSig),
			PreferencesBlob:           o.prefs,
			credentialRewrapFields:    validCredentialRewrapFields(),
		},
		next: next,
	}
}

func doRotateKeys(t *testing.T, h *Handler, cookie *http.Cookie, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, h, http.MethodPost, "/api/account/rotate-keys", cookie, body)
}

func conflictGroups(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	var body groupsConflict
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding conflict body %q: %v", rec.Body.String(), err)
	}
	return body.Groups
}

// noCooldown is a handler whose rotations are not rate limited, for tests of a
// second rotation.
func noCooldown(t *testing.T) *Handler {
	t.Helper()
	cfg := config.FromEnv()
	cfg.KeyRotationCooldown = 0
	return New(cfg, testDB(t))
}

func TestRotateKeysCommits(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	before, err := h.db.GetUserByID(t.Context(), user.userID)
	if err != nil {
		t.Fatal(err)
	}
	rot := signedRotation(t, user, rotateOpts{roster: [][]byte{randBytes(16), randBytes(16)}})

	rec := doRotateKeys(t, h, cookie, rot.req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	var resp rotateKeysResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.KeyEpoch != 1 || resp.CredentialVersion != 2 {
		t.Errorf("response = %+v, want epoch 1 and credential version 2", resp)
	}

	after, err := h.db.GetUserByID(t.Context(), user.userID)
	if err != nil {
		t.Fatal(err)
	}
	if string(after.SigningPublicKey) != string(rot.next.signPub) || string(after.WrappingPublicKey) != string(rot.next.wrapPub) {
		t.Error("PROFILE does not hold the new keys")
	}
	if after.KeyEpoch != 1 || after.CredentialVersion != 2 {
		t.Errorf("KeyEpoch = %d, CredentialVersion = %d, want 1 and 2", after.KeyEpoch, after.CredentialVersion)
	}
	if after.SessionGeneration != before.SessionGeneration+1 {
		t.Errorf("SessionGeneration = %d, want %d", after.SessionGeneration, before.SessionGeneration+1)
	}
	if len(after.SupersededSigningKeys) != 1 || string(after.SupersededSigningKeys[0].PublicKey) != string(user.signPub) {
		t.Fatalf("SupersededSigningKeys = %+v, want the old key", after.SupersededSigningKeys)
	}
	sk := after.SupersededSigningKeys[0]
	until, err := time.Parse(time.RFC3339, sk.Until)
	if err != nil || until.Format("2006-01-02") != utcToday() || until.Hour() != 0 {
		t.Errorf("Until = %q, want the signed day at 00:00Z", sk.Until)
	}
	if from, err := time.Parse(time.RFC3339, sk.From); err != nil || !from.Before(until) {
		t.Errorf("From = %q, want a parseable instant before Until", sk.From)
	}

	// The old cookie died with the session generation; the response carries a
	// working one.
	if rec := doJSON(t, h, http.MethodGet, "/api/account/rotation-handoff", cookie, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("old cookie after rotation: %d, want 401", rec.Code)
	}
	fresh := sessionCookieFrom(rec)
	if fresh == nil {
		t.Fatal("rotation set no fresh session cookie")
	}
	if rec := doJSON(t, h, http.MethodGet, "/api/account/rotation-handoff", fresh, nil); rec.Code != http.StatusOK {
		t.Errorf("fresh cookie after rotation: %d, want 200", rec.Code)
	}

	// RECOVERY moved with PROFILE, to the same credential version.
	if got := numAttr(getRow(t, "USER#"+user.userID, "RECOVERY"), "CredentialVersion"); got != "2" {
		t.Errorf("RECOVERY CredentialVersion = %s, want 2", got)
	}

	kc := getRow(t, "USER#"+user.userID, db.KeyChangeSortKey(1))
	if kc == nil {
		t.Fatal("no KEYCHANGE#000001 row")
	}
	if bytesAttrB64(kc, "OldSignature") != rot.req.OldSignature || bytesAttrB64(kc, "NewSignature") != rot.req.NewSignature ||
		bytesAttrB64(kc, "NewSigningPublicKey") != rot.req.NewSigningPublicKey ||
		bytesAttrB64(kc, "OldSigningPublicKey") != pinB64(user.signPub) {
		t.Error("KEYCHANGE row does not carry the keys and both signatures")
	}
	if bytesAttrB64(kc, "RosterDigest") == "" {
		t.Error("KEYCHANGE row has no roster digest")
	}
	if _, has := kc["CreatedAt"]; has {
		t.Error("KEYCHANGE row carries a CreatedAt")
	}

	// The cooldown is a TTL item, not a timestamp on PROFILE.
	cd := getRow(t, "USER#"+user.userID, "ROTCOOLDOWN")
	if cd == nil {
		t.Fatal("no ROTCOOLDOWN row")
	}
	ttl, _ := strconv.ParseInt(numAttr(cd, "TTL"), 10, 64)
	end := time.Unix(ttl, 0).UTC()
	// Rounded up to the end of its UTC day like every stored TTL, so it does not
	// date the rotation to the second; at least the 24h setting, less than a day over.
	if end.Hour() != 23 || end.Minute() != 59 || end.Second() != 59 {
		t.Errorf("cooldown TTL = %s, want the end of a UTC day", end)
	}
	if d := time.Until(end); d < 24*time.Hour || d >= 48*time.Hour {
		t.Errorf("cooldown ends in %s, want at least 24h and less than 48h", d)
	}
}

func TestRotateKeysRejections(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	otherPub, otherPriv, _ := crypto.GenerateSigningKey()
	stranger := randBytes(16)

	cases := []struct {
		name     string
		opts     rotateOpts
		mutate   func(*rotateKeysRequest)
		wantCode int
		wantErr  string
	}{
		{name: "old signature from another key", opts: rotateOpts{oldSigner: otherPriv}, wantCode: 400},
		{name: "signed against the wrong epoch", opts: rotateOpts{epoch: 0}, mutate: func(r *rotateKeysRequest) { r.ExpectedKeyEpoch = 1 }, wantCode: 409, wantErr: "key_epoch_stale"},
		{name: "roster differs from the signed digest", opts: rotateOpts{roster: [][]byte{stranger}, signedRoster: [][]byte{}}, wantCode: 400},
		{name: "day out of skew", opts: rotateOpts{day: time.Now().UTC().AddDate(0, 0, -3).Format("2006-01-02")}, wantCode: 400},
		{name: "new wrapping key equals the old one", opts: rotateOpts{newWrap: user.wrapPub}, wantCode: 400},
		{name: "new signing key equals the old one", opts: rotateOpts{newSignPub: user.signPub, newSignPriv: user.signPriv}, wantCode: 400},
		{name: "second signature not made by the new key", opts: rotateOpts{newSigner: otherPriv}, wantCode: 400},
		{name: "new signing key swapped after signing", opts: rotateOpts{}, mutate: func(r *rotateKeysRequest) {
			r.NewSigningPublicKey = pinB64(otherPub)
		}, wantCode: 400},
		{name: "stale credential version", opts: rotateOpts{credVersion: 7}, wantCode: 409},
		{name: "duplicate roster entry", opts: rotateOpts{roster: [][]byte{stranger, stranger}}, wantCode: 400},
		{name: "short roster entry", opts: rotateOpts{}, mutate: func(r *rotateKeysRequest) { r.Roster = []string{b64(8)} }, wantCode: 400},
		{name: "bad new wrapping key", opts: rotateOpts{}, mutate: func(r *rotateKeysRequest) { r.NewWrappingPublicKey = b64(31) }, wantCode: 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rot := signedRotation(t, user, tc.opts)
			if tc.mutate != nil {
				tc.mutate(&rot.req)
			}
			rec := doRotateKeys(t, h, cookie, rot.req)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantCode, rec.Body.String())
			}
			if tc.wantErr != "" && errCode(t, rec) != tc.wantErr {
				t.Errorf("code = %q, want %q", errCode(t, rec), tc.wantErr)
			}
			// Nothing was written.
			u, err := h.db.GetUserByID(t.Context(), user.userID)
			if err != nil {
				t.Fatal(err)
			}
			if u.KeyEpoch != 0 || string(u.SigningPublicKey) != string(user.signPub) || len(u.SupersededSigningKeys) != 0 {
				t.Errorf("a refused rotation changed the account: %+v", u.KeyEpoch)
			}
			if getRow(t, "USER#"+user.userID, db.KeyChangeSortKey(1)) != nil || getRow(t, "USER#"+user.userID, "ROTCOOLDOWN") != nil {
				t.Error("a refused rotation wrote a KEYCHANGE or cooldown row")
			}
		})
	}

	t.Run("unauthenticated", func(t *testing.T) {
		rot := signedRotation(t, user, rotateOpts{})
		if rec := doRotateKeys(t, h, nil, rot.req); rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

func TestRotateKeysIsSingleUse(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	rot := signedRotation(t, user, rotateOpts{})
	if rec := doRotateKeys(t, h, cookie, rot.req); rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	// A replay of the same signed request, with the fresh session, is refused:
	// the epoch it was signed against is gone.
	fresh := loginCookie(t, h, rot.next)
	rec := doRotateKeys(t, h, fresh, rot.req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "key_epoch_stale" {
		t.Errorf("replay: %d %s, want 409 key_epoch_stale", rec.Code, rec.Body.String())
	}
}

func TestRotateKeysCooldown(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	first := signedRotation(t, user, rotateOpts{})
	if rec := doRotateKeys(t, h, cookie, first.req); rec.Code != http.StatusOK {
		t.Fatalf("first: %d %s", rec.Code, rec.Body.String())
	}
	fresh := loginCookie(t, h, first.next)
	second := signedRotation(t, first.next, rotateOpts{epoch: 1, credVersion: 2})
	rec := doRotateKeys(t, h, fresh, second.req)
	if rec.Code != http.StatusTooManyRequests || errCode(t, rec) != "rotation_cooldown" {
		t.Fatalf("second inside the cooldown: %d %s, want 429 rotation_cooldown", rec.Code, rec.Body.String())
	}
	if u, _ := h.db.GetUserByID(t.Context(), user.userID); u.KeyEpoch != 1 {
		t.Errorf("KeyEpoch = %d after a refused second rotation, want 1", u.KeyEpoch)
	}
	if getRow(t, "USER#"+user.userID, db.KeyChangeSortKey(2)) != nil {
		t.Error("a refused rotation wrote KEYCHANGE#000002")
	}
}

func TestRotateKeysChainsIntervalsAndKeyChanges(t *testing.T) {
	h := noCooldown(t)
	user, cookie := loggedInUser(t, h)
	first := signedRotation(t, user, rotateOpts{})
	if rec := doRotateKeys(t, h, cookie, first.req); rec.Code != http.StatusOK {
		t.Fatalf("first: %d %s", rec.Code, rec.Body.String())
	}
	fresh := loginCookie(t, h, first.next)
	second := signedRotation(t, first.next, rotateOpts{epoch: 1, credVersion: 2})
	if rec := doRotateKeys(t, h, fresh, second.req); rec.Code != http.StatusOK {
		t.Fatalf("second: %d %s", rec.Code, rec.Body.String())
	}
	u, err := h.db.GetUserByID(t.Context(), user.userID)
	if err != nil {
		t.Fatal(err)
	}
	if u.KeyEpoch != 2 || len(u.SupersededSigningKeys) != 2 {
		t.Fatalf("KeyEpoch = %d, superseded = %d, want 2 and 2", u.KeyEpoch, len(u.SupersededSigningKeys))
	}
	a, b := u.SupersededSigningKeys[0], u.SupersededSigningKeys[1]
	if string(a.PublicKey) != string(user.signPub) || string(b.PublicKey) != string(first.next.signPub) {
		t.Error("superseded keys are not in rotation order")
	}
	if b.From != a.Until {
		t.Errorf("second interval starts %q, want the first one's end %q", b.From, a.Until)
	}
	// The chain: each new key introduced by the one before it.
	rows, err := h.db.ListKeyChanges(t.Context(), user.userID, true)
	if err != nil || len(rows) != 2 {
		t.Fatalf("ListKeyChanges = %d rows, %v", len(rows), err)
	}
	if string(rows[1].OldSigningPublicKey) != string(rows[0].NewSigningPublicKey) {
		t.Error("KEYCHANGE rows do not chain")
	}
	if rows[0].KeyEpoch != 1 || rows[1].KeyEpoch != 2 {
		t.Errorf("epochs = %d, %d", rows[0].KeyEpoch, rows[1].KeyEpoch)
	}
	// With the limit off (zero), no cooldown item is written at all.
	if getRow(t, "USER#"+user.userID, "ROTCOOLDOWN") != nil {
		t.Error("a rotation with the cooldown off wrote a ROTCOOLDOWN row")
	}
	// A key used before cannot come back.
	third := signedRotation(t, second.next, rotateOpts{epoch: 2, credVersion: 3, newSignPub: user.signPub, newSignPriv: user.signPriv})
	if rec := doRotateKeys(t, h, loginCookie(t, h, second.next), third.req); rec.Code != http.StatusBadRequest {
		t.Errorf("re-using a superseded signing key: %d, want 400", rec.Code)
	}
}

func TestRotateKeysPreferencesBlob(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	// Give the account a preferences blob.
	if _, err := rawDDB(t).UpdateItem(t.Context(), preferencesUpdate(user.userID)); err != nil {
		t.Fatal(err)
	}
	missing := signedRotation(t, user, rotateOpts{})
	if rec := doRotateKeys(t, h, cookie, missing.req); rec.Code != http.StatusBadRequest {
		t.Fatalf("without the re-sealed blob: %d %s, want 400", rec.Code, rec.Body.String())
	}
	blob := &wrappedBlob{Nonce: b64(12), Ciphertext: b64(40)}
	with := signedRotation(t, user, rotateOpts{prefs: blob})
	if rec := doRotateKeys(t, h, cookie, with.req); rec.Code != http.StatusOK {
		t.Fatalf("with the blob: %d %s", rec.Code, rec.Body.String())
	}
	u, _ := h.db.GetUserByID(t.Context(), user.userID)
	if u.PreferencesBlob == nil || base64.StdEncoding.EncodeToString(u.PreferencesBlob.Nonce) != blob.Nonce {
		t.Error("PreferencesBlob was not replaced by the re-sealed one")
	}
}

func TestRotateKeysDeletedAccount(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	if rec := doJSON(t, h, http.MethodDelete, "/api/account", cookie, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	rot := signedRotation(t, user, rotateOpts{})
	// The account's cookie was cleared on delete but still verifies until it
	// expires, which is exactly the case a rotation must refuse.
	if rec := doRotateKeys(t, h, cookie, rot.req); rec.Code != http.StatusNotFound {
		t.Errorf("rotating a deleted account: %d %s, want 404", rec.Code, rec.Body.String())
	}
}

// preferencesUpdate gives an account a preferences blob, as a client that has
// saved a theme would have.
func preferencesUpdate(userID string) *dynamodb.UpdateItemInput {
	return &dynamodb.UpdateItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		UpdateExpression: aws.String("SET PreferencesBlob = :p"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":p": &types.AttributeValueMemberM{Value: map[string]types.AttributeValue{
				"Nonce":      &types.AttributeValueMemberB{Value: randBytes(12)},
				"Ciphertext": &types.AttributeValueMemberB{Value: randBytes(40)},
			}},
		},
	}
}

func handoffBody(newWrap []byte, gen int64) handoffRequest {
	return handoffRequest{
		Generation:           gen,
		NewWrappingPublicKey: pinB64(newWrap),
		WrappedGroupKey:      wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
	}
}

func doPutHandoff(t *testing.T, h *Handler, cookie *http.Cookie, gid string, body handoffRequest) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, h, http.MethodPut, "/api/account/rotation-handoff/"+gid, cookie, body)
}

func handoffRowExists(t *testing.T, userID, gid string) bool {
	t.Helper()
	return getRow(t, "USER#"+userID, "HANDOFF#"+gid) != nil
}

func TestRotateKeysNeedsAHandoffForEveryAdminGroup(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	adminA := createPrivateGroup(t, h, user, cookie)
	adminB := createOpenPrivateGroup(t, h, user, cookie)
	// A group they are only a member of needs no handoff.
	other, otherCookie := loggedInUser(t, h)
	memberOnly := createPrivateGroup(t, h, other, otherCookie)
	addMember(t, memberOnly, user, "member")

	newWrap := randBytes(32)
	rot := signedRotation(t, user, rotateOpts{newWrap: newWrap})
	rec := doRotateKeys(t, h, cookie, rot.req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_required" {
		t.Fatalf("no handoffs: %d %s, want 409 handoff_required", rec.Code, rec.Body.String())
	}
	if got := conflictGroups(t, rec); len(got) != 2 {
		t.Errorf("groups = %v, want both administered groups", got)
	}

	// One row is not enough, and the answer names only the one still missing.
	if rec := doPutHandoff(t, h, cookie, adminA, handoffBody(newWrap, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put handoff: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRotateKeys(t, h, cookie, rot.req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_required" {
		t.Fatalf("one handoff: %d %s", rec.Code, rec.Body.String())
	}
	if got := conflictGroups(t, rec); len(got) != 1 || got[0] != adminB {
		t.Errorf("groups = %v, want [%s]", got, adminB)
	}

	// A row naming a different new key does not count.
	if rec := doPutHandoff(t, h, cookie, adminB, handoffBody(randBytes(32), 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put handoff B: %d %s", rec.Code, rec.Body.String())
	}
	rec = doRotateKeys(t, h, cookie, rot.req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_required" {
		t.Fatalf("handoff naming another key: %d %s", rec.Code, rec.Body.String())
	}

	if rec := doPutHandoff(t, h, cookie, adminB, handoffBody(newWrap, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("replace handoff B: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRotateKeys(t, h, cookie, rot.req); rec.Code != http.StatusOK {
		t.Fatalf("with every handoff: %d %s", rec.Code, rec.Body.String())
	}
	// The rows of a committed rotation stay: they are the self re-key's only
	// copy of the key.
	if !handoffRowExists(t, user.userID, adminA) || !handoffRowExists(t, user.userID, adminB) {
		t.Error("the committed rotation's handoff rows were deleted")
	}
}

func TestRotateKeysHandoffRowMustBeAtTheGroupsGeneration(t *testing.T) {
	f := startRotation(t) // group at generation 1, owner is an admin at 1
	newWrap := randBytes(32)
	owner := f.owner
	// A row for generation 0 is stale the moment the group is at 1.
	rec := doPutHandoff(t, f.h, f.ownerCookie, f.gid, handoffBody(newWrap, 0))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_stale" {
		t.Fatalf("stale generation: %d %s, want 409 handoff_stale", rec.Code, rec.Body.String())
	}
	if rec := doPutHandoff(t, f.h, f.ownerCookie, f.gid, handoffBody(newWrap, 1)); rec.Code != http.StatusNoContent {
		t.Fatalf("current generation: %d %s", rec.Code, rec.Body.String())
	}
	// A row written for generation 1 goes stale if the group moves on; rotate
	// then asks for it again.
	if _, err := rawDDB(t).PutItem(t.Context(), genKeyLinkItem(f.gid, 1)); err != nil {
		t.Fatal(err)
	}
	setMemberGeneration(t, f.gid, owner.userID, 2)
	rot := signedRotation(t, owner, rotateOpts{newWrap: newWrap})
	rec = doRotateKeys(t, f.h, f.ownerCookie, rot.req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_required" {
		t.Fatalf("row behind the group's generation: %d %s, want 409 handoff_required", rec.Code, rec.Body.String())
	}
}

func genKeyLinkItem(gid string, gen int64) *dynamodb.PutItemInput {
	return &dynamodb.PutItemInput{
		TableName: aws.String(testTableName()),
		Item: map[string]types.AttributeValue{
			"PK":   &types.AttributeValueMemberS{Value: "GROUP#" + gid},
			"SK":   &types.AttributeValueMemberS{Value: db.GenKeySortKey(gen)},
			"Type": &types.AttributeValueMemberS{Value: "GenerationKey"},
		},
	}
}

func TestRotateKeysWaitsForARotationThatHasNotReachedTheCaller(t *testing.T) {
	f := startRotation(t) // group at generation 1; carol is at 0
	setMemberRole(t, f.gid, f.carol.userID, "admin")
	carolCookie := loginCookie(t, f.h, f.carol)
	newWrap := randBytes(32)

	// carol cannot write a row for a key she does not hold.
	rec := doPutHandoff(t, f.h, carolCookie, f.gid, handoffBody(newWrap, 1))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_stale" {
		t.Fatalf("put while behind: %d %s, want 409 handoff_stale", rec.Code, rec.Body.String())
	}
	// Nor for the generation her own entry is at: the group's key has moved on,
	// so that row would wrap a key nobody uses any more.
	rec = doPutHandoff(t, f.h, carolCookie, f.gid, handoffBody(newWrap, 0))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_stale" {
		t.Fatalf("put for her own generation: %d %s, want 409 handoff_stale", rec.Code, rec.Body.String())
	}
	if handoffRowExists(t, f.carol.userID, f.gid) {
		t.Fatal("a refused PUT wrote a row")
	}
	rot := signedRotation(t, f.carol, rotateOpts{newWrap: newWrap})
	rec = doRotateKeys(t, f.h, carolCookie, rot.req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_in_progress" {
		t.Fatalf("rotate while behind: %d %s, want 409 rotation_in_progress", rec.Code, rec.Body.String())
	}
	if got := conflictGroups(t, rec); len(got) != 1 || got[0] != f.gid {
		t.Errorf("groups = %v, want [%s]", got, f.gid)
	}
}

func TestPutHandoffRefusals(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, user, cookie)
	member, memberCookie := loggedInUser(t, h)
	addMember(t, gid, member, "member")
	newWrap := randBytes(32)

	cases := []struct {
		name   string
		cookie *http.Cookie
		gid    string
		body   handoffRequest
		want   int
		code   string
	}{
		{"a plain member", memberCookie, gid, handoffBody(newWrap, 0), 409, "handoff_stale"},
		{"a stranger to the group", loginCookie(t, h, registerTestUser(t, h)), gid, handoffBody(newWrap, 0), 409, "handoff_stale"},
		{"the current key", cookie, gid, handoffBody(user.wrapPub, 0), 400, ""},
		{"a negative generation", cookie, gid, handoffBody(newWrap, -1), 400, ""},
		{"a malformed group id", cookie, "not-a-uuid", handoffBody(newWrap, 0), 404, ""},
		{"a short wrapped key", cookie, gid, handoffRequest{Generation: 0, NewWrappingPublicKey: pinB64(newWrap), WrappedGroupKey: wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(10)}}, 400, ""},
		{"no session", nil, gid, handoffBody(newWrap, 0), 401, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doPutHandoff(t, h, tc.cookie, tc.gid, tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.code != "" && errCode(t, rec) != tc.code {
				t.Errorf("code = %q, want %q", errCode(t, rec), tc.code)
			}
		})
	}
	for _, id := range []string{user.userID, member.userID} {
		if handoffRowExists(t, id, gid) {
			t.Errorf("a refused PUT wrote a row for %s", id)
		}
	}
}

func TestHandoffListAndDelete(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, user, cookie)
	newWrap := randBytes(32)
	if rec := doPutHandoff(t, h, cookie, gid, handoffBody(newWrap, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	rec := doJSON(t, h, http.MethodGet, "/api/account/rotation-handoff", cookie, nil)
	var list listHandoffsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	if len(list.Handoffs) != 1 || list.Handoffs[0].GroupID != gid || list.Handoffs[0].Generation != 0 ||
		list.Handoffs[0].NewWrappingPublicKey != pinB64(newWrap) {
		t.Fatalf("handoffs = %+v", list.Handoffs)
	}
	// Another user sees none of it.
	_, otherCookie := loggedInUser(t, h)
	rec = doJSON(t, h, http.MethodGet, "/api/account/rotation-handoff", otherCookie, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Handoffs) != 0 {
		t.Errorf("another user's list = %s", rec.Body.String())
	}
	// Delete is idempotent.
	for range 2 {
		if rec := doJSON(t, h, http.MethodDelete, "/api/account/rotation-handoff/"+gid, cookie, nil); rec.Code != http.StatusNoContent {
			t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
		}
	}
	if handoffRowExists(t, user.userID, gid) {
		t.Error("the row survived DELETE")
	}
}

// A committed rotation's row is the only copy a sole admin can reach, so PUT
// never replaces it, and a second rotation waits until it has been used.
func TestCommittedHandoffIsNeverReplacedAndBlocksTheNextRotation(t *testing.T) {
	h := noCooldown(t)
	user, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, user, cookie)
	newWrap := randBytes(32)
	if rec := doPutHandoff(t, h, cookie, gid, handoffBody(newWrap, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	first := signedRotation(t, user, rotateOpts{newWrap: newWrap})
	if rec := doRotateKeys(t, h, cookie, first.req); rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	fresh := loginCookie(t, h, first.next)

	// The row now names the account's current key: PUT refuses to replace it.
	before := bytesAttrB64(getRow(t, "USER#"+user.userID, "HANDOFF#"+gid), "NewWrappingPublicKey")
	rec := doPutHandoff(t, h, fresh, gid, handoffBody(first.next.wrapPub, 0))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a row naming the current key: %d, want 400 (it is the current key)", rec.Code)
	}
	// Nor can a row for the next rotation take its place.
	rec = doPutHandoff(t, h, fresh, gid, handoffBody(randBytes(32), 0))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_pending" {
		t.Fatalf("a row for the next rotation: %d %s, want 409 handoff_pending", rec.Code, rec.Body.String())
	}
	if got := bytesAttrB64(getRow(t, "USER#"+user.userID, "HANDOFF#"+gid), "NewWrappingPublicKey"); got != before {
		t.Error("the pending row was replaced")
	}

	// The pending self re-key has not run, so the next rotation is refused with
	// the row still in place.
	second := signedRotation(t, first.next, rotateOpts{epoch: 1, credVersion: 2})
	rec = doRotateKeys(t, h, fresh, second.req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_pending" {
		t.Fatalf("second rotation: %d %s, want 409 handoff_pending", rec.Code, rec.Body.String())
	}
	if got := conflictGroups(t, rec); len(got) != 1 || got[0] != gid {
		t.Errorf("groups = %v, want [%s]", got, gid)
	}

	// Once the caller no longer administers the group nothing can use the row,
	// so it stops blocking and the rotation's sweep removes it.
	setMemberRole(t, gid, user.userID, "member")
	newerWrap := randBytes(32)
	third := signedRotation(t, first.next, rotateOpts{epoch: 1, credVersion: 2, newWrap: newerWrap})
	if rec := doRotateKeys(t, h, fresh, third.req); rec.Code != http.StatusOK {
		t.Fatalf("after demotion: %d %s", rec.Code, rec.Body.String())
	}
	if handoffRowExists(t, user.userID, gid) {
		t.Error("the row for a group the caller no longer administers survived the sweep")
	}
}

func TestRotateKeysSweepsRowsNothingCanUse(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	kept := createPrivateGroup(t, h, user, cookie)
	demoted := createPrivateGroup(t, h, user, cookie)
	abandoned := createPrivateGroup(t, h, user, cookie)
	newWrap := randBytes(32)
	for _, g := range []string{kept, demoted} {
		if rec := doPutHandoff(t, h, cookie, g, handoffBody(newWrap, 0)); rec.Code != http.StatusNoContent {
			t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
		}
	}
	// An earlier attempt that never committed left a row naming another key.
	// Rotation does not need it, because the caller no longer administers that
	// group by the time they rotate.
	if rec := doPutHandoff(t, h, cookie, abandoned, handoffBody(randBytes(32), 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put abandoned: %d %s", rec.Code, rec.Body.String())
	}
	setMemberRole(t, abandoned, user.userID, "member")
	// A co-admin demoted this user after their row was written.
	setMemberRole(t, demoted, user.userID, "member")

	rot := signedRotation(t, user, rotateOpts{newWrap: newWrap})
	if rec := doRotateKeys(t, h, cookie, rot.req); rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	if !handoffRowExists(t, user.userID, kept) {
		t.Error("the sweep deleted a usable row")
	}
	if handoffRowExists(t, user.userID, demoted) {
		t.Error("the sweep kept a row for a group the caller no longer administers")
	}
	if handoffRowExists(t, user.userID, abandoned) {
		t.Error("the sweep kept a row naming a key that is not the account's")
	}
}

func TestUserProjectionServesTheKeyChangeChainWithoutTheRoster(t *testing.T) {
	h := noCooldown(t)
	user, cookie := loggedInUser(t, h)
	_, viewerCookie := loggedInUser(t, h)

	// No rotation yet: the chain is present and empty.
	rec := doJSON(t, h, http.MethodGet, "/api/users/"+user.userID, viewerCookie, nil)
	var detail struct {
		KeyEpoch   uint64           `json:"keyEpoch"`
		KeyChanges []keyChangeEntry `json:"keyChanges"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &detail) != nil {
		t.Fatalf("get user: %d %s", rec.Code, rec.Body.String())
	}
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	if string(raw["keyChanges"]) != "[]" {
		t.Errorf("keyChanges before any rotation = %s, want []", raw["keyChanges"])
	}

	roster := [][]byte{randBytes(16), randBytes(16), randBytes(16)}
	first := signedRotation(t, user, rotateOpts{roster: roster})
	if rec := doRotateKeys(t, h, cookie, first.req); rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, http.MethodGet, "/api/users/"+user.userID, viewerCookie, nil)
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &detail) != nil {
		t.Fatalf("get user: %d %s", rec.Code, rec.Body.String())
	}
	if detail.KeyEpoch != 1 || len(detail.KeyChanges) != 1 {
		t.Fatalf("epoch = %d, chain = %+v", detail.KeyEpoch, detail.KeyChanges)
	}
	link := detail.KeyChanges[0]
	if link.KeyEpoch != 1 || link.OldSigningPublicKey != pinB64(user.signPub) || link.NewSigningPublicKey != first.req.NewSigningPublicKey ||
		link.OldSignature != first.req.OldSignature || link.NewSignature != first.req.NewSignature {
		t.Errorf("link = %+v", link)
	}
	// What the viewer is served lets them verify the link themselves.
	digest, _ := base64.StdEncoding.DecodeString(link.RosterDigest)
	oldSig, _ := base64.StdEncoding.DecodeString(link.OldSignature)
	payload := crypto.KeyRotationPayload(user.userID, user.signPub, user.wrapPub, first.next.signPub, first.next.wrapPub, link.Day, 0, digest)
	if !crypto.Verify(user.signPub, crypto.ContextKeyRotation, payload, oldSig) {
		t.Error("the served link does not verify under the old key")
	}
	// The roster itself is not in the response: its length is private.
	if bytesContain(rec.Body.Bytes(), pinB64(roster[0])) || bytesContain(rec.Body.Bytes(), "roster\"") {
		t.Errorf("GET /api/users served the roster: %s", rec.Body.String())
	}
	// The batch read stays chain-free.
	batch := doJSON(t, h, http.MethodPost, "/api/users:batch", viewerCookie, batchUsersRequest{IDs: []string{user.userID}})
	if bytesContain(batch.Body.Bytes(), "keyChanges") {
		t.Errorf("batch read served the chain: %s", batch.Body.String())
	}

	// The owner, and only the owner, gets the roster list from GET /api/pins.
	pins := decodePins(t, doListPins(t, h, loginCookie(t, h, first.next), ""))
	if len(pins.KeyChangeRosters) != 1 || pins.KeyChangeRosters[0].KeyEpoch != 1 || len(pins.KeyChangeRosters[0].Roster) != 3 {
		t.Fatalf("keyChangeRosters = %+v", pins.KeyChangeRosters)
	}
	got := map[string]bool{}
	for _, e := range pins.KeyChangeRosters[0].Roster {
		got[e] = true
	}
	for _, e := range roster {
		if !got[pinB64(e)] {
			t.Errorf("roster entry %x missing from GET /api/pins", e)
		}
	}
	other := decodePins(t, doListPins(t, h, viewerCookie, ""))
	if len(other.KeyChangeRosters) != 0 {
		t.Errorf("another user's GET /api/pins carried a roster: %+v", other.KeyChangeRosters)
	}
}

func bytesContain(b []byte, s string) bool { return strings.Contains(string(b), s) }

func TestDeleteAccountSweepsHandoffAndCooldownRowsButKeepsTheChain(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	rot := signedRotation(t, user, rotateOpts{})
	if rec := doRotateKeys(t, h, cookie, rot.req); rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	// A handoff row the account was left with (its group is gone).
	gid := "11111111-2222-4333-8444-555555555555"
	if _, err := rawDDB(t).PutItem(t.Context(), &dynamodb.PutItemInput{
		TableName: aws.String(testTableName()),
		Item: map[string]types.AttributeValue{
			"PK":                   &types.AttributeValueMemberS{Value: "USER#" + user.userID},
			"SK":                   &types.AttributeValueMemberS{Value: "HANDOFF#" + gid},
			"Type":                 &types.AttributeValueMemberS{Value: "Handoff"},
			"GroupID":              &types.AttributeValueMemberS{Value: gid},
			"NewWrappingPublicKey": &types.AttributeValueMemberB{Value: rot.next.wrapPub},
		},
	}); err != nil {
		t.Fatal(err)
	}
	// The DELETE endpoint bumps HANDOFFSEQ, so the account has one.
	fresh := loginCookie(t, h, rot.next)
	if rec := doJSON(t, h, http.MethodDelete, "/api/account/rotation-handoff/"+gid, fresh, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete handoff: %d %s", rec.Code, rec.Body.String())
	}
	if getRow(t, "USER#"+user.userID, "HANDOFFSEQ") == nil {
		t.Fatal("DELETE did not write HANDOFFSEQ")
	}
	if _, err := rawDDB(t).PutItem(t.Context(), &dynamodb.PutItemInput{
		TableName: aws.String(testTableName()),
		Item: map[string]types.AttributeValue{
			"PK":                   &types.AttributeValueMemberS{Value: "USER#" + user.userID},
			"SK":                   &types.AttributeValueMemberS{Value: "HANDOFF#" + gid},
			"Type":                 &types.AttributeValueMemberS{Value: "Handoff"},
			"GroupID":              &types.AttributeValueMemberS{Value: gid},
			"NewWrappingPublicKey": &types.AttributeValueMemberB{Value: rot.next.wrapPub},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if rec := doJSON(t, h, http.MethodDelete, "/api/account", fresh, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if handoffRowExists(t, user.userID, gid) || getRow(t, "USER#"+user.userID, "ROTCOOLDOWN") != nil || getRow(t, "USER#"+user.userID, "HANDOFFSEQ") != nil {
		t.Error("account deletion left a handoff, cooldown or HANDOFFSEQ row")
	}
	if getRow(t, "USER#"+user.userID, db.KeyChangeSortKey(1)) == nil {
		t.Error("account deletion removed the KEYCHANGE# chain, which the tombstone keeps")
	}
}

// rotateUser rotates user's keys through the endpoint, writing a handoff row
// for each group they administer first, and returns the account as it reads
// afterwards with a session for it.
func rotateUser(t *testing.T, h *Handler, user registeredUser, cookie *http.Cookie, adminGroups ...string) (registeredUser, *http.Cookie) {
	t.Helper()
	newWrap := randBytes(32)
	for _, gid := range adminGroups {
		gen, err := strconv.ParseInt(numAttr(getRow(t, "GROUP#"+gid, "MEMBER#"+user.userID), "Generation"), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		// A group that has rotated is one past its newest link; the fixtures
		// here keep the admin at that generation.
		if rec := doPutHandoff(t, h, cookie, gid, handoffBody(newWrap, gen)); rec.Code != http.StatusNoContent {
			t.Fatalf("handoff for %s: %d %s", gid, rec.Code, rec.Body.String())
		}
	}
	rot := signedRotation(t, user, rotateOpts{newWrap: newWrap})
	if rec := doRotateKeys(t, h, cookie, rot.req); rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	return rot.next, loginCookie(t, h, rot.next)
}

func wrapEpochOf(t *testing.T, gid, userID string) string {
	t.Helper()
	row := getRow(t, "GROUP#"+gid, "MEMBER#"+userID)
	if _, has := row["WrapEpoch"]; !has {
		return "absent"
	}
	return numAttr(row, "WrapEpoch")
}

func TestGroupCreatedByARotatedUserIsNotDormant(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	plain := createPrivateGroup(t, h, user, cookie)
	if got := wrapEpochOf(t, plain, user.userID); got != "absent" {
		t.Errorf("a never-rotated creator's WrapEpoch = %s, want it absent", got)
	}
	next, nextCookie := rotateUser(t, h, user, cookie, plain)
	// Their entry in the first group is now dormant (WrapEpoch 0 < KeyEpoch 1);
	// a group created after the rotation must not be.
	gid := createPrivateGroup(t, h, next, nextCookie)
	if got := wrapEpochOf(t, gid, next.userID); got != "1" {
		t.Errorf("a rotated creator's WrapEpoch = %s, want 1", got)
	}
	if got := wrapEpochOf(t, plain, next.userID); got != "absent" {
		t.Errorf("the pre-rotation membership's WrapEpoch = %s, want it left alone", got)
	}
}

func TestCompleteInviteForAnInviteeWhoRotatedAfterAccepting(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie, invitee, groupID, inviteID := acceptedInviteFixture(t, h)
	inviteeCookie := loginCookie(t, h, invitee)
	rotateUser(t, h, invitee, inviteeCookie)

	adm := signedAdmission(t, h, creator, groupID, inviteID, invitee)
	rec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/complete", creatorCookie, completeBody(adm))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "invitee_keys_changed" {
		t.Fatalf("complete: %d %s, want 409 invitee_keys_changed", rec.Code, rec.Body.String())
	}
	if getRow(t, "GROUP#"+groupID, "MEMBER#"+invitee.userID) != nil {
		t.Error("a membership was written for keys the invitee no longer holds")
	}
	// The invite can never complete, so its rows are cleared instead of left as a
	// zombie in pending-completions.
	if getRow(t, "INVITE#"+inviteID, "META") != nil || getRow(t, "USER#"+creator.userID, "SENT#"+inviteID) != nil {
		t.Error("the unfinishable invite's rows were left behind")
	}
}

func TestCompleteInviteForAnInviteeWhoRotatedBeforeAccepting(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	creator, creatorCookie := loggedInUser(t, h)
	groupID := createTestGroupWithMembers(t, h, creator, creatorCookie)
	inviteID := createTestInvite(t, h, creator, creatorCookie, groupID, time.Now().Add(24*time.Hour))
	invitee, inviteeCookie := loggedInUser(t, h)
	next, nextCookie := rotateUser(t, h, invitee, inviteeCookie)
	_ = inviteeCookie

	if rec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/accept", nextCookie, signedAcceptInviteRequest(t, next, inviteID)); rec.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
	}
	adm := signedAdmission(t, h, creator, groupID, inviteID, next)
	if rec := doJSON(t, h, http.MethodPost, "/api/invites/"+inviteID+"/complete", creatorCookie, completeBody(adm)); rec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body.String())
	}
	if got := wrapEpochOf(t, groupID, next.userID); got != "1" {
		t.Errorf("WrapEpoch = %s, want 1: the wrap went to the key they hold", got)
	}
}

func TestRewrapEndpointRefusesADormantMemberAndAStaleEpoch(t *testing.T) {
	f := startRotation(t) // owner at generation 1; carol and dave at 0
	carolNext, _ := rotateUser(t, f.h, f.carol, loginCookie(t, f.h, f.carol))

	req := rewrapReq(1, f.dave, carolNext)
	req.Wraps[1].WrapEpoch = 1 // wrapped to the key carol holds now
	rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "member_dormant" {
		t.Fatalf("dormant: %d %s, want 409 member_dormant", rec.Code, rec.Body.String())
	}
	req.Wraps[1].WrapEpoch = 0 // wrapped to the key carol replaced
	rec = doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "wrap_epoch_stale" {
		t.Fatalf("stale: %d %s, want 409 wrap_epoch_stale", rec.Code, rec.Body.String())
	}
	if memberGen(t, f.gid, f.dave) != "0" || memberGen(t, f.gid, f.carol) != "0" {
		t.Error("a refused batch moved a member")
	}
	// Without carol the batch is fine, and the rotation completes around her.
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPut, f.gid, "members", rewrapReq(1, f.dave)); rec.Code != http.StatusNoContent {
		t.Fatalf("without the dormant member: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRotationCall(t, f.h, f.ownerCookie, http.MethodPost, f.gid, "complete", completeRotationRequest{Generation: 1}); rec.Code != http.StatusNoContent {
		t.Fatalf("complete around the dormant member: %d %s", rec.Code, rec.Body.String())
	}
}

// A rotated admin's own entry is dormant until a start brings it current, and
// the start consumes their handoff row in the same transaction.
func TestStartByARotatedAdminBringsTheirEntryCurrentAndConsumesTheHandoff(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	victim := registerTestUser(t, h)
	addMember(t, gid, victim, "member")

	next, nextCookie := rotateUser(t, h, owner, ownerCookie, gid)
	if !handoffRowExists(t, owner.userID, gid) {
		t.Fatal("no handoff row after the rotation")
	}
	if got := wrapEpochOf(t, gid, owner.userID); got != "absent" {
		t.Fatalf("WrapEpoch before the re-key = %s, want it absent (dormant)", got)
	}
	if rec := doRemove(t, h, nextCookie, gid, victim.userID, &removeMemberRequest{Rotation: rotationBody(t, next, gid, victim.userID, 1)}); rec.Code != http.StatusNoContent {
		t.Fatalf("re-key: %d %s", rec.Code, rec.Body.String())
	}
	if got := wrapEpochOf(t, gid, owner.userID); got != "1" {
		t.Errorf("WrapEpoch after the re-key = %s, want 1", got)
	}
	if handoffRowExists(t, owner.userID, gid) {
		t.Error("the start left the handoff row behind")
	}
}

// rotateKeysInput builds the db-level input a handler would, from the account's
// PROFILE, so a test can vary what the handler's own checks would have caught.
func rotateKeysInput(t *testing.T, h *Handler, userID string, mutate func(*db.RotateKeysInput)) db.RotateKeysInput {
	t.Helper()
	user, err := h.db.GetUserByID(t.Context(), userID)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := crypto.GenerateSigningKey()
	in := db.RotateKeysInput{
		Credentials: db.RewrapCredentialsInput{
			UserID:                     userID,
			ExpectedCredentialVersion:  user.CredentialVersion,
			NewCredentialVersion:       user.CredentialVersion + 1,
			Salt:                       randBytes(16),
			Argon2Params:               user.Argon2Params,
			WrappedPrivateKeys:         user.WrappedPrivateKeys,
			RecoverySalt:               randBytes(16),
			RecoveryArgon2Params:       user.Argon2Params,
			RecoveryWrappedPrivateKeys: user.WrappedPrivateKeys,
			RecoveryVerifierSalt:       randBytes(16),
			RecoveryVerifierParams:     user.Argon2Params,
			RecoveryVerifier:           randBytes(32),
		},
		ExpectedKeyEpoch:     user.KeyEpoch,
		OldSigningPublicKey:  user.SigningPublicKey,
		OldWrappingPublicKey: user.WrappingPublicKey,
		NewSigningPublicKey:  pub,
		NewWrappingPublicKey: randBytes(32),
		SupersededFrom:       "1970-01-01T00:00:00Z",
		SupersededUntil:      utcToday() + "T00:00:00Z",
		KeyChange:            models.KeyChange{Day: utcToday()},
		Now:                  time.Now(),
	}
	if mutate != nil {
		mutate(&in)
	}
	return in
}

// The handler checks the epoch, the keys and the credential version before it
// calls the database, but a rotation that lands between that read and the
// write must still fail the transaction, and say why.
func TestRotateKeysTransactionRefusesWhatHasMovedUnderIt(t *testing.T) {
	h := noCooldown(t)
	user, cookie := loggedInUser(t, h)
	ctx := t.Context()
	unchanged := func(t *testing.T, epoch uint64) {
		t.Helper()
		u, err := h.db.GetUserByID(ctx, user.userID)
		if err != nil || u.KeyEpoch != epoch {
			t.Fatalf("KeyEpoch = %d (%v), want it left at %d", u.KeyEpoch, err, epoch)
		}
		if getRow(t, "USER#"+user.userID, db.KeyChangeSortKey(epoch+1)) != nil {
			t.Fatalf("KEYCHANGE#%06d was written by a refused rotation", epoch+1)
		}
	}

	if err := h.db.RotateKeys(ctx, rotateKeysInput(t, h, user.userID, func(in *db.RotateKeysInput) { in.ExpectedKeyEpoch = 1 })); !errors.Is(err, db.ErrKeyEpochStale) {
		t.Errorf("epoch ahead of the account (0 held, 1 signed): %v, want ErrKeyEpochStale", err)
	}
	if err := h.db.RotateKeys(ctx, rotateKeysInput(t, h, user.userID, func(in *db.RotateKeysInput) { in.OldWrappingPublicKey = randBytes(32) })); !errors.Is(err, db.ErrKeyEpochStale) {
		t.Errorf("old wrapping key not the current one: %v, want ErrKeyEpochStale", err)
	}
	if err := h.db.RotateKeys(ctx, rotateKeysInput(t, h, user.userID, func(in *db.RotateKeysInput) { in.OldSigningPublicKey = randBytes(32) })); !errors.Is(err, db.ErrKeyEpochStale) {
		t.Errorf("old signing key not the current one: %v, want ErrKeyEpochStale", err)
	}
	if err := h.db.RotateKeys(ctx, rotateKeysInput(t, h, user.userID, func(in *db.RotateKeysInput) { in.Credentials.ExpectedCredentialVersion = 9 })); !errors.Is(err, db.ErrCredentialVersionStale) {
		t.Errorf("credential version behind: %v, want ErrCredentialVersionStale", err)
	}
	unchanged(t, 0)

	// Once the account has rotated, a request signed against the epoch that is
	// now gone is stale: the condition is strict above zero too.
	first := signedRotation(t, user, rotateOpts{})
	if rec := doRotateKeys(t, h, cookie, first.req); rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	if err := h.db.RotateKeys(ctx, rotateKeysInput(t, h, user.userID, func(in *db.RotateKeysInput) { in.ExpectedKeyEpoch = 2 })); !errors.Is(err, db.ErrKeyEpochStale) {
		t.Errorf("epoch ahead of the account (1 held, 2 signed): %v, want ErrKeyEpochStale", err)
	}
	if err := h.db.RotateKeys(ctx, rotateKeysInput(t, h, user.userID, func(in *db.RotateKeysInput) { in.ExpectedKeyEpoch = 0 })); !errors.Is(err, db.ErrKeyEpochStale) {
		t.Errorf("epoch behind the account (1 held, 0 signed): %v, want ErrKeyEpochStale", err)
	}
	unchanged(t, 1)

	// Signed against epoch 0 while the account is at 1 is stale on the PROFILE
	// condition alone, once the KEYCHANGE# row that would also refuse it is out
	// of the way.
	deleteRow(t, "USER#"+user.userID, db.KeyChangeSortKey(1))
	if err := h.db.RotateKeys(ctx, rotateKeysInput(t, h, user.userID, func(in *db.RotateKeysInput) { in.ExpectedKeyEpoch = 0 })); !errors.Is(err, db.ErrKeyEpochStale) {
		t.Errorf("epoch 0 signed, 1 held, no KEYCHANGE# row in the way: %v, want ErrKeyEpochStale", err)
	}
	if u, _ := h.db.GetUserByID(ctx, user.userID); u.KeyEpoch != 1 {
		t.Errorf("KeyEpoch = %d after the refused request, want 1", u.KeyEpoch)
	}

	// PROFILE and RECOVERY each carry the credential version; either one being
	// behind refuses the rotation.
	cv, cvCookie := loggedInUser(t, h)
	_ = cvCookie
	setProfileAttr(t, cv.userID, "PROFILE", "CredentialVersion", 5)
	if err := h.db.RotateKeys(ctx, rotateKeysInput(t, h, cv.userID, func(in *db.RotateKeysInput) { in.Credentials.ExpectedCredentialVersion = 1 })); !errors.Is(err, db.ErrCredentialVersionStale) {
		t.Errorf("PROFILE ahead of the version signed against: %v, want ErrCredentialVersionStale", err)
	}
	if getRow(t, "USER#"+cv.userID, db.KeyChangeSortKey(1)) != nil {
		t.Error("the refused rotation wrote a KEYCHANGE# row")
	}

	// A tombstoned account is refused on PROFILE's own condition, with its
	// RECOVERY item still in place.
	tomb, _ := loggedInUser(t, h)
	setProfileAttrS(t, tomb.userID, "DeletedAt", "2026-01-01T00:00:00Z")
	if err := h.db.RotateKeys(ctx, rotateKeysInput(t, h, tomb.userID, nil)); !errors.Is(err, db.ErrUserNotFound) {
		t.Errorf("a tombstoned PROFILE with RECOVERY intact: %v, want ErrUserNotFound", err)
	}

	// A deleted account is refused by the transaction itself.
	gone, goneCookie := loggedInUser(t, h)
	if rec := doJSON(t, h, http.MethodDelete, "/api/account", goneCookie, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if err := h.db.RotateKeys(ctx, rotateKeysInput(t, h, gone.userID, nil)); !errors.Is(err, db.ErrUserNotFound) {
		t.Errorf("a deleted account: %v, want ErrUserNotFound", err)
	}
	if getRow(t, "USER#"+gone.userID, db.KeyChangeSortKey(1)) != nil {
		t.Error("a deleted account got a KEYCHANGE# row")
	}
}

func setProfileAttr(t *testing.T, userID, sk, attr string, n int) {
	t.Helper()
	if _, err := rawDDB(t).UpdateItem(t.Context(), &dynamodb.UpdateItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: sk},
		},
		UpdateExpression:          aws.String("SET " + attr + " = :v"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": &types.AttributeValueMemberN{Value: strconv.Itoa(n)}},
	}); err != nil {
		t.Fatal(err)
	}
}

func setProfileAttrS(t *testing.T, userID, attr, v string) {
	t.Helper()
	if _, err := rawDDB(t).UpdateItem(t.Context(), &dynamodb.UpdateItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		},
		UpdateExpression:          aws.String("SET " + attr + " = :v"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": &types.AttributeValueMemberS{Value: v}},
	}); err != nil {
		t.Fatal(err)
	}
}

// A handoff row is refused when the account's wrapping key is not the one the
// handler compared it against: a rotation committed between the read and the
// write, and the row would otherwise land beside keys it was not made for.
func TestPutHandoffTransactionRefusesAKeyThatMovedUnderIt(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	user, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, user, cookie)
	err := h.db.PutHandoff(t.Context(), db.PutHandoffInput{
		UserID: user.userID, GroupID: gid, Generation: 0,
		NewWrappingPublicKey: randBytes(32),
		WrappedGroupKey:      models.WrappedKey{EphemeralPub: randBytes(32), Nonce: randBytes(12), Ciphertext: randBytes(48)},
		CurrentWrappingKey:   randBytes(32), // not the account's
	})
	if !errors.Is(err, db.ErrHandoffAccountChanged) {
		t.Fatalf("a stale current key: %v, want ErrHandoffAccountChanged", err)
	}
	if handoffRowExists(t, user.userID, gid) {
		t.Error("the refused write left a row")
	}

	// Nor for an account that has been tombstoned, even one still holding an
	// admin membership (account deletion refuses while any membership exists,
	// so only the transaction stands between a stale request and that state).
	setProfileAttrS(t, user.userID, "DeletedAt", "2026-01-01T00:00:00Z")
	current, err := h.db.GetUserByID(t.Context(), user.userID)
	if err != nil {
		t.Fatal(err)
	}
	err = h.db.PutHandoff(t.Context(), db.PutHandoffInput{
		UserID: user.userID, GroupID: gid, Generation: 0,
		NewWrappingPublicKey: randBytes(32),
		WrappedGroupKey:      models.WrappedKey{EphemeralPub: randBytes(32), Nonce: randBytes(12), Ciphertext: randBytes(48)},
		CurrentWrappingKey:   current.WrappingPublicKey,
	})
	if !errors.Is(err, db.ErrHandoffAccountChanged) {
		t.Fatalf("a tombstoned account: %v, want ErrHandoffAccountChanged", err)
	}
	if handoffRowExists(t, user.userID, gid) {
		t.Error("the write for a tombstoned account left a row")
	}
}

// A handoff PUT or DELETE between the handler's check and the commit used to
// leave a committed rotation with no usable row, and the sweep then deleted the
// replaced one. HANDOFFSEQ makes the commit fail instead.
func TestRotateKeysFailsWhenAHandoffChangedAfterTheCheck(t *testing.T) {
	h := noCooldown(t)
	user, cookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, user, cookie)
	ctx := t.Context()
	keyA, keyB := randBytes(32), randBytes(32)
	if rec := doPutHandoff(t, h, cookie, gid, handoffBody(keyA, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put A: %d %s", rec.Code, rec.Body.String())
	}
	seq, err := h.db.GetHandoffSeq(ctx, user.userID) // what checkHandoffs read
	if err != nil {
		t.Fatal(err)
	}
	rotateToA := func(seq int64) error {
		return h.db.RotateKeys(ctx, rotateKeysInput(t, h, user.userID, func(in *db.RotateKeysInput) {
			in.NewWrappingPublicKey = keyA
			in.ExpectedHandoffSeq = seq
		}))
	}

	// Tab two replaces the row with one for a different key.
	if rec := doPutHandoff(t, h, cookie, gid, handoffBody(keyB, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put B: %d %s", rec.Code, rec.Body.String())
	}
	if err := rotateToA(seq); !errors.Is(err, db.ErrHandoffChanged) {
		t.Fatalf("a PUT after the check: %v, want ErrHandoffChanged", err)
	}
	if got := bytesAttrB64(getRow(t, "USER#"+user.userID, "HANDOFF#"+gid), "NewWrappingPublicKey"); got != pinB64(keyB) {
		t.Error("the row for B was lost")
	}
	if u, _ := h.db.GetUserByID(ctx, user.userID); u.KeyEpoch != 0 {
		t.Errorf("KeyEpoch = %d, the refused rotation committed", u.KeyEpoch)
	}

	// A DELETE after the check fails it too.
	seq, _ = h.db.GetHandoffSeq(ctx, user.userID)
	if rec := doJSON(t, h, http.MethodDelete, "/api/account/rotation-handoff/"+gid, cookie, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if err := rotateToA(seq); !errors.Is(err, db.ErrHandoffChanged) {
		t.Fatalf("a DELETE after the check: %v, want ErrHandoffChanged", err)
	}

	// Nothing moved since this read, so the same rotation commits.
	if rec := doPutHandoff(t, h, cookie, gid, handoffBody(keyA, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put A again: %d %s", rec.Code, rec.Body.String())
	}
	seq, _ = h.db.GetHandoffSeq(ctx, user.userID)
	if err := rotateToA(seq); err != nil {
		t.Fatalf("an unchanged seq: %v", err)
	}
}

// The seq starts absent (0), so the first rotation of an account that never
// wrote a handoff still commits.
func TestRotateKeysWithNoHandoffsEverWrittenCommits(t *testing.T) {
	h := noCooldown(t)
	user, _ := loggedInUser(t, h)
	seq, err := h.db.GetHandoffSeq(t.Context(), user.userID)
	if err != nil || seq != 0 {
		t.Fatalf("seq = %d (%v), want 0", seq, err)
	}
	if err := h.db.RotateKeys(t.Context(), rotateKeysInput(t, h, user.userID, nil)); err != nil {
		t.Fatalf("rotate: %v", err)
	}
}

// The public read of the chain must not pull the client-supplied rosters.
func TestListKeyChangesWithoutRosterLeavesItOut(t *testing.T) {
	h := noCooldown(t)
	user, cookie := loggedInUser(t, h)
	rot := signedRotation(t, user, rotateOpts{roster: [][]byte{randBytes(16), randBytes(16)}})
	if rec := doRotateKeys(t, h, cookie, rot.req); rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	bare, err := h.db.ListKeyChanges(t.Context(), user.userID, false)
	if err != nil || len(bare) != 1 {
		t.Fatalf("without roster: %d rows (%v)", len(bare), err)
	}
	full, err := h.db.ListKeyChanges(t.Context(), user.userID, true)
	if err != nil || len(full) != 1 {
		t.Fatalf("with roster: %d rows (%v)", len(full), err)
	}
	if len(bare[0].Roster) != 0 || len(full[0].Roster) != 2 {
		t.Errorf("roster lengths = %d without, %d with; want 0 and 2", len(bare[0].Roster), len(full[0].Roster))
	}
	b, f := bare[0], full[0]
	if b.KeyEpoch != 1 || b.Day != f.Day || !bytes.Equal(b.OldSignature, f.OldSignature) || !bytes.Equal(b.NewSignature, f.NewSignature) ||
		!bytes.Equal(b.RosterDigest, f.RosterDigest) || !bytes.Equal(b.NewWrappingPublicKey, f.NewWrappingPublicKey) ||
		!bytes.Equal(b.OldSigningPublicKey, f.OldSigningPublicKey) || !bytes.Equal(b.OldWrappingPublicKey, f.OldWrappingPublicKey) ||
		!bytes.Equal(b.NewSigningPublicKey, f.NewSigningPublicKey) {
		t.Errorf("the projection dropped a served attribute: %+v vs %+v", b, f)
	}
}
