package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
)

// A rotated admin starts their own re-key from the handoff row (#62): no one
// is removed, the row goes in the same transaction, and the record the start
// leaves is signed under its own context.

func selfRekeyBody(t *testing.T, user registeredUser, gid string, gen int64) selfRekeyRequest {
	t.Helper()
	sig, err := crypto.Sign(user.signPriv, crypto.ContextRotationRekey, crypto.RotationRekeyPayload(gid, user.userID, user.userID, gen, crypto.RekeyReasonSelf))
	if err != nil {
		t.Fatal(err)
	}
	return selfRekeyRequest{
		Generation:     gen,
		Link:           wrappedBlob{Nonce: b64(12), Ciphertext: b64(48)},
		WrappedKey:     wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		StartSignature: base64.StdEncoding.EncodeToString(sig),
	}
}

func TestSelfRekeyStartsARotationThatRemovesNoOneAndConsumesTheRow(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	member := registerTestUser(t, h)
	addMember(t, gid, member, "member")
	next, nextCookie := rotateUser(t, h, owner, ownerCookie, gid)
	ok := selfRekeyBody(t, next, gid, 1)

	// A signature made for a removal, over the same fields, is not a re-key.
	asRemoval, err := crypto.Sign(next.signPriv, crypto.ContextRotationStart, crypto.RotationStartPayload(gid, next.userID, next.userID, 1))
	if err != nil {
		t.Fatal(err)
	}
	removalContext := ok
	removalContext.StartSignature = base64.StdEncoding.EncodeToString(asRemoval)
	wrongReason, err := crypto.Sign(next.signPriv, crypto.ContextRotationRekey, crypto.RotationRekeyPayload(gid, next.userID, next.userID, 1, crypto.RekeyReasonApproval))
	if err != nil {
		t.Fatal(err)
	}
	approvalReason := ok
	approvalReason.StartSignature = base64.StdEncoding.EncodeToString(wrongReason)
	wrongGen := ok
	wrongGen.Generation = 2 // signed for 1, so only the generation check can refuse it

	for name, tc := range map[string]struct {
		cookie *http.Cookie
		body   selfRekeyRequest
		status int
		code   string
	}{
		"unauthenticated":        {nil, ok, http.StatusUnauthorized, ""},
		"removal-context sig":    {nextCookie, removalContext, http.StatusBadRequest, "bad_signature"},
		"approval-reason sig":    {nextCookie, approvalReason, http.StatusBadRequest, "bad_signature"},
		"wrong generation":       {nextCookie, wrongGen, http.StatusBadRequest, ""},
		"signed by the old keys": {nextCookie, selfRekeyBody(t, owner, gid, 1), http.StatusBadRequest, "bad_signature"},
	} {
		rec := doRotationCall(t, h, tc.cookie, http.MethodPost, gid, "rekey", tc.body)
		if rec.Code != tc.status || (tc.code != "" && errCode(t, rec) != tc.code) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if getRow(t, "GROUP#"+gid, "ROTATION") != nil || getRow(t, "GROUP#"+gid, "GENKEY#000000") != nil {
		t.Fatal("a refused re-key wrote a marker or a link")
	}
	if !handoffRowExists(t, owner.userID, gid) {
		t.Fatal("a refused re-key deleted the handoff row")
	}

	// A plain member has nothing to re-key.
	memberCookie := loginCookie(t, h, member)
	if rec := doRotationCall(t, h, memberCookie, http.MethodPost, gid, "rekey", selfRekeyBody(t, member, gid, 1)); rec.Code != http.StatusForbidden {
		t.Errorf("member: %d %s", rec.Code, rec.Body.String())
	}

	if rec := doRotationCall(t, h, nextCookie, http.MethodPost, gid, "rekey", ok); rec.Code != http.StatusNoContent {
		t.Fatalf("re-key: %d %s", rec.Code, rec.Body.String())
	}
	m := getRow(t, "GROUP#"+gid, "ROTATION")
	if strAttr(m, "StartedBy") != owner.userID || strAttr(m, "RekeyedUserID") != owner.userID || strAttr(m, "RekeyReason") != crypto.RekeyReasonSelf || bytesAttrB64(m, "StartSignature") != ok.StartSignature {
		t.Fatalf("marker = %v", m)
	}
	if _, has := m["RemovedUserID"]; has {
		t.Error("a re-key marker names a removed member; takeover and resume would exclude them")
	}
	link := getRow(t, "GROUP#"+gid, "GENKEY#000000")
	if strAttr(link, "RemoverUserID") != owner.userID || strAttr(link, "RekeyedUserID") != owner.userID || strAttr(link, "RekeyReason") != crypto.RekeyReasonSelf {
		t.Fatalf("link = %v", link)
	}
	for name, row := range map[string]map[string]types.AttributeValue{"marker": m, "link": link} {
		if _, has := row["CreatedAt"]; has {
			t.Errorf("re-key %s carries CreatedAt; see issue #258", name)
		}
	}
	if g := numAttr(getRow(t, "GROUP#"+gid, "MEMBER#"+owner.userID), "Generation"); g != "1" {
		t.Fatalf("caller generation = %s, want 1", g)
	}
	if got := wrapEpochOf(t, gid, owner.userID); got != "1" {
		t.Errorf("WrapEpoch after the re-key = %s, want 1", got)
	}
	if g := numAttr(getRow(t, "GROUP#"+gid, "MEMBER#"+member.userID), "Generation"); g != "0" {
		t.Errorf("member generation = %s, want 0 (re-wrapped by the job)", g)
	}
	if getRow(t, "GROUP#"+gid, "MEMBER#"+member.userID) == nil {
		t.Error("the re-key removed a member")
	}
	if handoffRowExists(t, owner.userID, gid) {
		t.Error("the start left the handoff row behind")
	}

	// One rotation at a time.
	if rec := doRotationCall(t, h, nextCookie, http.MethodPost, gid, "rekey", selfRekeyBody(t, next, gid, 2)); rec.Code != http.StatusConflict || errCode(t, rec) != "rotation_in_progress" {
		t.Errorf("second start: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSelfRekeyNeedsAFreshHandoffRow(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	next, nextCookie := rotateUser(t, h, owner, ownerCookie, gid)
	body := selfRekeyBody(t, next, gid, 1)

	refused := func(name string) {
		t.Helper()
		rec := doRotationCall(t, h, nextCookie, http.MethodPost, gid, "rekey", body)
		if rec.Code != http.StatusConflict || errCode(t, rec) != "handoff_stale" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
		if getRow(t, "GROUP#"+gid, "ROTATION") != nil || getRow(t, "GROUP#"+gid, "GENKEY#000000") != nil {
			t.Fatalf("%s: a refused re-key wrote a marker or a link", name)
		}
		if g := numAttr(getRow(t, "GROUP#"+gid, "MEMBER#"+owner.userID), "Generation"); g != "0" {
			t.Fatalf("%s: caller generation = %s, want 0", name, g)
		}
	}

	// A row naming another key (an abandoned attempt's) is not this account's.
	setHandoff(t, owner.userID, gid, "NewWrappingPublicKey", &types.AttributeValueMemberB{Value: randBytes(32)})
	refused("row names another key")
	setHandoff(t, owner.userID, gid, "NewWrappingPublicKey", &types.AttributeValueMemberB{Value: next.wrapPub})

	// A row for another generation than the caller's entry is stale.
	setHandoff(t, owner.userID, gid, "Generation", &types.AttributeValueMemberN{Value: "5"})
	refused("row holds another generation")
	setHandoff(t, owner.userID, gid, "Generation", &types.AttributeValueMemberN{Value: "0"})

	// No row at all: nothing to re-key from.
	deleteRow(t, "USER#"+owner.userID, "HANDOFF#"+gid)
	refused("row gone")
}

func setHandoff(t *testing.T, userID, gid, attr string, v types.AttributeValue) {
	t.Helper()
	_, err := rawDDB(t).UpdateItem(t.Context(), &dynamodb.UpdateItemInput{
		TableName: aws.String(testTableName()),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + userID},
			"SK": &types.AttributeValueMemberS{Value: "HANDOFF#" + gid},
		},
		UpdateExpression:          aws.String("SET #a = :v"),
		ExpressionAttributeNames:  map[string]string{"#a": attr},
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": v},
	})
	if err != nil {
		t.Fatal(err)
	}
}

// An Open group has no way to re-key, by its own definition; its self-wrap is a
// different endpoint.
func TestSelfRekeyRefusesAnOpenGroup(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	next, nextCookie := rotateUser(t, h, owner, ownerCookie, gid)
	rec := doRotationCall(t, h, nextCookie, http.MethodPost, gid, "rekey", selfRekeyBody(t, next, gid, 1))
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != "rotation_not_applicable" {
		t.Fatalf("open group: %d %s", rec.Code, rec.Body.String())
	}
	if !handoffRowExists(t, owner.userID, gid) || getRow(t, "GROUP#"+gid, "ROTATION") != nil {
		t.Fatal("a refused re-key changed the row or wrote a marker")
	}
}

// The rotation and the chain serve the re-key record, so a verifier can tell
// the link from a removal's.
func TestSelfRekeyRecordIsServed(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	next, nextCookie := rotateUser(t, h, owner, ownerCookie, gid)
	if rec := doRotationCall(t, h, nextCookie, http.MethodPost, gid, "rekey", selfRekeyBody(t, next, gid, 1)); rec.Code != http.StatusNoContent {
		t.Fatalf("re-key: %d %s", rec.Code, rec.Body.String())
	}
	rec := doJSON(t, h, http.MethodGet, "/api/groups/"+gid, nextCookie, nil)
	var g struct {
		Rotation rotationState `json:"rotation"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil {
		t.Fatal(err)
	}
	if g.Rotation.RekeyedUserID != owner.userID || g.Rotation.RekeyReason != "self" || g.Rotation.RemovedUserID != "" {
		t.Errorf("group rotation = %+v", g.Rotation)
	}
	links := decodeKeychain(t, doKeychain(t, h, nextCookie, gid, "from=0&to=1")).Links
	if len(links) != 1 || links[0].RemoverUserID != owner.userID || links[0].RekeyedUserID != owner.userID || links[0].RekeyReason != "self" || links[0].RemovedUserID != "" {
		t.Errorf("keychain = %+v", links)
	}
}
