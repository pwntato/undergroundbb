package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/models"
)

// Direct messages (#73). Every test builds its own users, so none depends on another's leftovers.

type dmFixture struct {
	h               *Handler
	sender          registeredUser
	senderCookie    *http.Cookie
	recipient       registeredUser
	recipientCookie *http.Cookie
}

func newDMFixture(t *testing.T) dmFixture {
	t.Helper()
	h := New(config.FromEnv(), testDB(t))
	s, sc := loggedInUser(t, h)
	r, rc := loggedInUser(t, h)
	return dmFixture{h: h, sender: s, senderCookie: sc, recipient: r, recipientCookie: rc}
}

// dmRequestFor builds a genuinely signed create request for a DM from sender to recipient.
func dmRequestFor(t *testing.T, sender, recipient registeredUser) createGroupRequest {
	t.Helper()
	req := signedCreateGroupRequest(t, sender)
	req.RevocationMode = "open"
	req.NameCiphertext, req.DescriptionCiphertext = wrappedBlob{}, wrappedBlob{}
	body := &dmRequestBody{
		RecipientUserID: recipient.userID,
		RequestID:       newRequestID(t),
		WrappedGroupKey: wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
	}
	body.Admission.Day = time.Now().UTC().Format("2006-01-02")
	payload := crypto.AdmissionPayload(req.GroupID, sender.userID, recipient.userID, recipient.signPub, recipient.wrapPub,
		body.RequestID, req.RootGrantSortKey, body.Admission.Day, 0)
	sig, err := crypto.Sign(sender.signPriv, crypto.ContextAdmission, payload)
	if err != nil {
		t.Fatal(err)
	}
	body.Admission.Signature = base64.StdEncoding.EncodeToString(sig)
	req.DM = body
	return req
}

func (f dmFixture) send(t *testing.T) createGroupRequest {
	t.Helper()
	req := dmRequestFor(t, f.sender, f.recipient)
	if rec := doCreateGroup(t, f.h, f.senderCookie, req); rec.Code != http.StatusCreated {
		t.Fatalf("create DM: %d %s", rec.Code, rec.Body.String())
	}
	return req
}

func (f dmFixture) accept(t *testing.T, req createGroupRequest) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, f.h, http.MethodPost, "/api/dms/"+req.GroupID+"/accept?requestId="+req.DM.RequestID, f.recipientCookie, nil)
}

func (f dmFixture) decline(t *testing.T, req createGroupRequest) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, f.h, http.MethodPost, "/api/dms/"+req.GroupID+"/decline?requestId="+req.DM.RequestID, f.recipientCookie, nil)
}

func (f dmFixture) post(t *testing.T, cookie *http.Cookie, gid string, author registeredUser) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := signedPost(t, gid, author, postOpts{})
	return doPost(t, f.h, cookie, gid, body)
}

func rawItemExists(t *testing.T, pk, sk string) bool {
	t.Helper()
	out, err := rawDDB(t).GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(testTableName()), ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: pk}, "SK": &types.AttributeValueMemberS{Value: sk}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.Item != nil
}

func getPair(t *testing.T, a, b string) *models.DMPair {
	t.Helper()
	out, err := rawDDB(t).GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: aws.String(testTableName()), ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: db.DMPairPK(a, b)}, "SK": &types.AttributeValueMemberS{Value: "PAIR"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Item == nil {
		return nil
	}
	var p models.DMPair
	if err := attributevalue.UnmarshalMap(out.Item, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

func TestCreateDMWritesTheSendersSideOnly(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)

	g, err := f.h.db.GetGroup(t.Context(), req.GroupID)
	if err != nil || g == nil {
		t.Fatalf("GetGroup = %v, %v", g, err)
	}
	if g.GroupType != "dm" || g.RevocationMode != models.RevocationOpen || g.Visibility != models.VisibilityPrivate {
		t.Errorf("group = type %q mode %q visibility %q", g.GroupType, g.RevocationMode, g.Visibility)
	}
	if g.NameCiphertext != nil || g.NamePlaintext != "" {
		t.Error("a DM has no name")
	}
	if g.DMPairPK != db.DMPairPK(f.sender.userID, f.recipient.userID) {
		t.Errorf("DMPairPK = %q", g.DMPairPK)
	}
	if m, _ := f.h.db.GetMembership(t.Context(), req.GroupID, f.sender.userID); m == nil || m.Role != models.RoleAdmin {
		t.Errorf("sender membership = %+v", m)
	}
	// The recipient's membership row, and so their graph edge, does not exist yet.
	if m, _ := f.h.db.GetMembership(t.Context(), req.GroupID, f.recipient.userID); m != nil {
		t.Errorf("recipient already has a membership row: %+v", m)
	}
	ids, err := f.h.db.ListMemberGroupIDs(t.Context(), f.recipient.userID)
	if err != nil || len(ids) != 0 {
		t.Errorf("recipient's group list = %v, %v", ids, err)
	}
	slot, err := f.h.db.GetDMRequest(t.Context(), req.GroupID, f.recipient.userID)
	if err != nil || slot == nil {
		t.Fatalf("slot = %v, %v", slot, err)
	}
	if slot.SenderUserID != f.sender.userID || slot.RequestID != req.DM.RequestID ||
		string(slot.RecipientEd25519) != string(f.recipient.signPub) || string(slot.RecipientX25519) != string(f.recipient.wrapPub) {
		t.Errorf("slot = %+v", slot)
	}
	if slot.GSI1PK != "USER#"+f.recipient.userID || slot.GSI1SK != "DMREQ#"+req.GroupID {
		t.Errorf("slot GSI1 = %q / %q", slot.GSI1PK, slot.GSI1SK)
	}
	if slot.AdmissionGrantRef != req.RootGrantSortKey {
		t.Errorf("admission grant ref = %q, want the sender's root grant %q", slot.AdmissionGrantRef, req.RootGrantSortKey)
	}
	if p := getPair(t, f.sender.userID, f.recipient.userID); p == nil || p.Status != models.DMPairPending || p.GroupID != req.GroupID || p.TTL != 0 {
		t.Errorf("pair = %+v", p)
	}
	if !rawItemExists(t, "USER#"+f.sender.userID, "DMOUT#"+req.GroupID) {
		t.Error("the sender's pending pointer is missing")
	}

	rec := doJSON(t, f.h, http.MethodGet, "/api/dms/incoming", f.recipientCookie, nil)
	var in struct{ DMs []dmIncomingEntry }
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &in) != nil || len(in.DMs) != 1 {
		t.Fatalf("incoming = %d %s", rec.Code, rec.Body.String())
	}
	if e := in.DMs[0]; e.GroupID != req.GroupID || e.SenderUserID != f.sender.userID || e.RequestID != req.DM.RequestID || e.AdmissionSig != req.DM.Admission.Signature {
		t.Errorf("incoming entry = %+v", e)
	}
	// The sender sees nothing incoming, and a stranger sees nothing.
	if rec := doJSON(t, f.h, http.MethodGet, "/api/dms/incoming", f.senderCookie, nil); rec.Body.String() != `{"dms":[]}`+"\n" {
		t.Errorf("sender's incoming = %s", rec.Body.String())
	}
}

func TestCreateDMRefusals(t *testing.T) {
	f := newDMFixture(t)
	stranger, _ := loggedInUser(t, f.h)
	cases := []struct {
		name   string
		mutate func(*createGroupRequest)
		status int
		code   string
	}{
		{"to yourself", func(r *createGroupRequest) { *r = dmRequestFor(t, f.sender, f.sender) }, 400, ""},
		{"to nobody", func(r *createGroupRequest) { r.DM.RecipientUserID = newRequestID(t) }, 404, "recipient_not_found"},
		{"public", func(r *createGroupRequest) { r.Visibility = "public" }, 400, ""},
		{"rotating", func(r *createGroupRequest) { r.RevocationMode = "rotating" }, 400, ""},
		{"with a name", func(r *createGroupRequest) { r.NameCiphertext = wrappedBlob{Nonce: b64(12), Ciphertext: b64(32)} }, 400, ""},
		{"with a plaintext name", func(r *createGroupRequest) { r.NamePlaintext = "x" }, 400, ""},
		{"bad request id", func(r *createGroupRequest) { r.DM.RequestID = "nope" }, 400, ""},
		{"short wrap", func(r *createGroupRequest) { r.DM.WrappedGroupKey.Ciphertext = b64(10) }, 400, ""},
		{"bad day", func(r *createGroupRequest) { r.DM.Admission.Day = "2026-13-45" }, 400, ""},
		{"day far in the past", func(r *createGroupRequest) { r.DM.Admission.Day = "2020-01-01" }, 400, "clock_skew"},
		{"admission signed for other keys", func(r *createGroupRequest) {
			p := crypto.AdmissionPayload(r.GroupID, f.sender.userID, f.recipient.userID, stranger.signPub, stranger.wrapPub, r.DM.RequestID, r.RootGrantSortKey, r.DM.Admission.Day, 0)
			s, _ := crypto.Sign(f.sender.signPriv, crypto.ContextAdmission, p)
			r.DM.Admission.Signature = base64.StdEncoding.EncodeToString(s)
		}, 400, "bad_signature"},
		{"admission signed by someone else", func(r *createGroupRequest) {
			p := crypto.AdmissionPayload(r.GroupID, f.sender.userID, f.recipient.userID, f.recipient.signPub, f.recipient.wrapPub, r.DM.RequestID, r.RootGrantSortKey, r.DM.Admission.Day, 0)
			s, _ := crypto.Sign(stranger.signPriv, crypto.ContextAdmission, p)
			r.DM.Admission.Signature = base64.StdEncoding.EncodeToString(s)
		}, 400, "bad_signature"},
		{"admission for another grant ref", func(r *createGroupRequest) {
			p := crypto.AdmissionPayload(r.GroupID, f.sender.userID, f.recipient.userID, f.recipient.signPub, f.recipient.wrapPub, r.DM.RequestID, "GRANT#other", r.DM.Admission.Day, 0)
			s, _ := crypto.Sign(f.sender.signPriv, crypto.ContextAdmission, p)
			r.DM.Admission.Signature = base64.StdEncoding.EncodeToString(s)
		}, 400, "bad_signature"},
		{"admission for another generation", func(r *createGroupRequest) {
			p := crypto.AdmissionPayload(r.GroupID, f.sender.userID, f.recipient.userID, f.recipient.signPub, f.recipient.wrapPub, r.DM.RequestID, r.RootGrantSortKey, r.DM.Admission.Day, 1)
			s, _ := crypto.Sign(f.sender.signPriv, crypto.ContextAdmission, p)
			r.DM.Admission.Signature = base64.StdEncoding.EncodeToString(s)
		}, 400, "bad_signature"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := dmRequestFor(t, f.sender, f.recipient)
			c.mutate(&req)
			rec := doCreateGroup(t, f.h, f.senderCookie, req)
			if rec.Code != c.status || (c.code != "" && errCode(t, rec) != c.code) {
				t.Errorf("status %d code %q, want %d %q; body %s", rec.Code, errCode(t, rec), c.status, c.code, rec.Body.String())
			}
			if g, _ := f.h.db.GetGroup(t.Context(), req.GroupID); g != nil {
				t.Error("a refused request still created the group")
			}
		})
	}
	if getPair(t, f.sender.userID, f.recipient.userID) != nil {
		t.Error("a refused request left a pair marker")
	}
}

func TestCreateDMPendingCap(t *testing.T) {
	f := newDMFixture(t)
	for i := 0; i < db.MaxPendingDMsPerSender; i++ {
		if _, err := rawDDB(t).PutItem(context.Background(), &dynamodb.PutItemInput{TableName: aws.String(testTableName()), Item: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + f.sender.userID},
			"SK": &types.AttributeValueMemberS{Value: "DMOUT#fake" + strconv.Itoa(i)},
		}}); err != nil {
			t.Fatal(err)
		}
	}
	req := dmRequestFor(t, f.sender, f.recipient)
	if rec := doCreateGroup(t, f.h, f.senderCookie, req); rec.Code != http.StatusTooManyRequests || errCode(t, rec) != "too_many_pending_dms" {
		t.Errorf("at the cap: %d %s", rec.Code, rec.Body.String())
	}
	// One below the cap is fine.
	if _, err := rawDDB(t).DeleteItem(context.Background(), &dynamodb.DeleteItemInput{TableName: aws.String(testTableName()), Key: map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "USER#" + f.sender.userID}, "SK": &types.AttributeValueMemberS{Value: "DMOUT#fake0"},
	}}); err != nil {
		t.Fatal(err)
	}
	if rec := doCreateGroup(t, f.h, f.senderCookie, req); rec.Code != http.StatusCreated {
		t.Errorf("below the cap: %d %s", rec.Code, rec.Body.String())
	}
}

func TestOneDMPerPairInEitherDirection(t *testing.T) {
	f := newDMFixture(t)
	first := f.send(t)

	again := dmRequestFor(t, f.sender, f.recipient)
	rec := doCreateGroup(t, f.h, f.senderCookie, again)
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusConflict || body["code"] != "dm_exists" || body["groupId"] != first.GroupID {
		t.Errorf("same direction: %d %s", rec.Code, rec.Body.String())
	}
	if g, _ := f.h.db.GetGroup(t.Context(), again.GroupID); g != nil {
		t.Error("the refused second DM left a group behind")
	}

	back := dmRequestFor(t, f.recipient, f.sender)
	rec = doCreateGroup(t, f.h, f.recipientCookie, back)
	body = map[string]string{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusConflict || body["code"] != "dm_exists" || body["groupId"] != first.GroupID {
		t.Errorf("other direction: %d %s", rec.Code, rec.Body.String())
	}
	// Still exists once accepted.
	if rec := f.accept(t, first); rec.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
	}
	rec = doCreateGroup(t, f.h, f.recipientCookie, dmRequestFor(t, f.recipient, f.sender))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "dm_exists" {
		t.Errorf("after accept: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSenderCanWriteBeforeTheRecipientOpensIt(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	if rec := f.post(t, f.senderCookie, req.GroupID, f.sender); rec.Code != http.StatusCreated {
		t.Fatalf("sender post while pending: %d %s", rec.Code, rec.Body.String())
	}
	// The recipient is not a member, so cannot write or read.
	if rec := f.post(t, f.recipientCookie, req.GroupID, f.recipient); rec.Code != http.StatusNotFound {
		t.Errorf("recipient post before opening: %d", rec.Code)
	}
}

func TestAcceptDM(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	if rec := f.accept(t, req); rec.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
	}
	m, err := f.h.db.GetMembership(t.Context(), req.GroupID, f.recipient.userID)
	if err != nil || m == nil {
		t.Fatalf("recipient membership = %v, %v", m, err)
	}
	if m.Role != models.RoleMember || m.Generation != 0 || m.WrappedGroupKey.Ciphertext == nil || m.GSI1PK != "USER#"+f.recipient.userID || m.GSI1SK != "GROUP#"+req.GroupID {
		t.Errorf("membership = %+v", m)
	}
	if string(m.WrappedGroupKey.EphemeralPub) != mustB64(t, req.DM.WrappedGroupKey.EphemeralPub) {
		t.Error("the stored wrap is not the one the sender made")
	}
	if !rawItemExists(t, "GROUP#"+req.GroupID, "ADMISSION#"+f.recipient.userID) {
		t.Error("no admission record for the recipient")
	}
	if rawItemExists(t, "GROUP#"+req.GroupID, "DMREQ#"+f.recipient.userID) {
		t.Error("the pending slot survived")
	}
	if rawItemExists(t, "USER#"+f.sender.userID, "DMOUT#"+req.GroupID) {
		t.Error("the sender's pending pointer survived")
	}
	if p := getPair(t, f.sender.userID, f.recipient.userID); p == nil || p.Status != models.DMPairActive {
		t.Errorf("pair = %+v", p)
	}
	if rec := f.post(t, f.recipientCookie, req.GroupID, f.recipient); rec.Code != http.StatusCreated {
		t.Errorf("recipient post after opening: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.accept(t, req); rec.Code != http.StatusNotFound {
		t.Errorf("second accept: %d", rec.Code)
	}
	if rec := doJSON(t, f.h, http.MethodGet, "/api/dms/incoming", f.recipientCookie, nil); rec.Body.String() != `{"dms":[]}`+"\n" {
		t.Errorf("incoming after accept = %s", rec.Body.String())
	}
}

func TestAcceptDMRefusals(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	stranger, strangerCookie := loggedInUser(t, f.h)
	_ = stranger
	path := "/api/dms/" + req.GroupID + "/accept?requestId="

	t.Run("someone it was not sent to", func(t *testing.T) {
		if rec := doJSON(t, f.h, http.MethodPost, path+req.DM.RequestID, strangerCookie, nil); rec.Code != http.StatusNotFound {
			t.Errorf("status %d", rec.Code)
		}
	})
	t.Run("the sender cannot accept for the recipient", func(t *testing.T) {
		if rec := doJSON(t, f.h, http.MethodPost, path+req.DM.RequestID, f.senderCookie, nil); rec.Code != http.StatusNotFound {
			t.Errorf("status %d", rec.Code)
		}
	})
	t.Run("a different request id", func(t *testing.T) {
		if rec := doJSON(t, f.h, http.MethodPost, path+newRequestID(t), f.recipientCookie, nil); rec.Code != http.StatusConflict || errCode(t, rec) != "request_changed" {
			t.Errorf("status %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("no request id", func(t *testing.T) {
		if rec := doJSON(t, f.h, http.MethodPost, "/api/dms/"+req.GroupID+"/accept", f.recipientCookie, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("status %d", rec.Code)
		}
	})
	t.Run("not signed in", func(t *testing.T) {
		if rec := doJSON(t, f.h, http.MethodPost, path+req.DM.RequestID, nil, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("status %d", rec.Code)
		}
	})
	if m, _ := f.h.db.GetMembership(t.Context(), req.GroupID, f.recipient.userID); m != nil {
		t.Error("a refused accept still wrote the membership")
	}
	if m, _ := f.h.db.GetMembership(t.Context(), req.GroupID, stranger.userID); m != nil {
		t.Error("a stranger got a membership")
	}
}

func TestAcceptDMWhenTheRecipientsKeysMoved(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	// Their epoch moves on (a key rotation) after the sender wrapped to the old key.
	_, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:        aws.String(testTableName()),
		Key:              map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: "USER#" + f.recipient.userID}, "SK": &types.AttributeValueMemberS{Value: "PROFILE"}},
		UpdateExpression: aws.String("SET KeyEpoch = :e"), ExpressionAttributeValues: map[string]types.AttributeValue{":e": &types.AttributeValueMemberN{Value: "5"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := f.accept(t, req)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "keys_changed" {
		t.Errorf("accept after a rotation: %d %s", rec.Code, rec.Body.String())
	}
	if m, _ := f.h.db.GetMembership(t.Context(), req.GroupID, f.recipient.userID); m != nil {
		t.Error("a wrap to a replaced key was stored")
	}
}

func TestDeclineDM(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	if rec := f.post(t, f.senderCookie, req.GroupID, f.sender); rec.Code != http.StatusCreated {
		t.Fatalf("post: %d", rec.Code)
	}
	if rec := f.decline(t, req); rec.Code != http.StatusOK {
		t.Fatalf("decline: %d %s", rec.Code, rec.Body.String())
	}
	if g, _ := f.h.db.GetGroup(t.Context(), req.GroupID); g != nil {
		t.Error("the declined group still exists")
	}
	for _, k := range [][2]string{
		{"GROUP#" + req.GroupID, "MEMBER#" + f.sender.userID},
		{"GROUP#" + req.GroupID, "DMREQ#" + f.recipient.userID},
		{"USER#" + f.sender.userID, "DMOUT#" + req.GroupID},
	} {
		if rawItemExists(t, k[0], k[1]) {
			t.Errorf("%v survived the decline", k)
		}
	}
	p := getPair(t, f.sender.userID, f.recipient.userID)
	if p == nil || p.Status != models.DMPairDeclined || p.DeclinedBy != f.recipient.userID {
		t.Fatalf("pair = %+v", p)
	}
	if d := time.Until(time.Unix(p.TTL, 0)); d < 6*24*time.Hour || d > 8*24*time.Hour {
		t.Errorf("cool-off = %v, want about 7 days", d)
	}
	if rec := f.accept(t, req); rec.Code != http.StatusNotFound {
		t.Errorf("accept after decline: %d", rec.Code)
	}

	t.Run("the sender is kept out for the cool-off", func(t *testing.T) {
		again := dmRequestFor(t, f.sender, f.recipient)
		rec := doCreateGroup(t, f.h, f.senderCookie, again)
		if rec.Code != http.StatusConflict || errCode(t, rec) != "dm_cooling_off" {
			t.Errorf("%d %s", rec.Code, rec.Body.String())
		}
		if g, _ := f.h.db.GetGroup(t.Context(), again.GroupID); g != nil {
			t.Error("a refused DM left a group behind")
		}
	})
	t.Run("the sender may try again after it", func(t *testing.T) {
		setPairTTL(t, f.sender.userID, f.recipient.userID, time.Now().Add(-time.Hour).Unix())
		if rec := doCreateGroup(t, f.h, f.senderCookie, dmRequestFor(t, f.sender, f.recipient)); rec.Code != http.StatusCreated {
			t.Errorf("%d %s", rec.Code, rec.Body.String())
		}
	})
}

func TestDecliningDoesNotBlockTheDecliner(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	if rec := f.decline(t, req); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	// The person who refused may still start the conversation themselves.
	if rec := doCreateGroup(t, f.h, f.recipientCookie, dmRequestFor(t, f.recipient, f.sender)); rec.Code != http.StatusCreated {
		t.Errorf("decliner's own DM: %d %s", rec.Code, rec.Body.String())
	}
	if p := getPair(t, f.sender.userID, f.recipient.userID); p == nil || p.Status != models.DMPairPending || p.SenderUserID != f.recipient.userID || p.DeclinedBy != "" {
		t.Errorf("pair after the decliner's own DM = %+v", p)
	}
}

func TestDeclineDMRefusals(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	if rec := doJSON(t, f.h, http.MethodPost, "/api/dms/"+req.GroupID+"/decline?requestId="+req.DM.RequestID, f.senderCookie, nil); rec.Code != http.StatusNotFound {
		t.Errorf("the sender declining their own: %d", rec.Code)
	}
	if rec := doJSON(t, f.h, http.MethodPost, "/api/dms/"+req.GroupID+"/decline?requestId="+newRequestID(t), f.recipientCookie, nil); rec.Code != http.StatusConflict {
		t.Errorf("wrong request id: %d", rec.Code)
	}
	if g, _ := f.h.db.GetGroup(t.Context(), req.GroupID); g == nil {
		t.Error("a refused decline deleted the group")
	}
}

func TestSenderLeavingAPendingDMWithdrawsIt(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	rec := doJSON(t, f.h, http.MethodPost, "/api/groups/"+req.GroupID+"/leave", f.senderCookie, nil)
	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("leave: %d %s", rec.Code, rec.Body.String())
	}
	if g, _ := f.h.db.GetGroup(t.Context(), req.GroupID); g != nil {
		t.Error("the group survived")
	}
	if getPair(t, f.sender.userID, f.recipient.userID) != nil {
		t.Error("the pair marker survived a withdrawal (it would block a new DM)")
	}
	if rawItemExists(t, "USER#"+f.sender.userID, "DMOUT#"+req.GroupID) {
		t.Error("the pending pointer survived (it would count against the cap)")
	}
	if rawItemExists(t, "GROUP#"+req.GroupID, "DMREQ#"+f.recipient.userID) {
		t.Error("the recipient's slot survived")
	}
	if rec := f.accept(t, req); rec.Code != http.StatusNotFound {
		t.Errorf("accept after withdrawal: %d", rec.Code)
	}
	if rec := doCreateGroup(t, f.h, f.senderCookie, dmRequestFor(t, f.sender, f.recipient)); rec.Code != http.StatusCreated {
		t.Errorf("a fresh DM after withdrawing: %d %s", rec.Code, rec.Body.String())
	}
}

func TestLeavingAnActiveDMLeavesTheOtherReadOnly(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	if rec := f.accept(t, req); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	// The sender is the group's only admin: leaving must still work, a DM has no roles.
	if rec := doJSON(t, f.h, http.MethodPost, "/api/groups/"+req.GroupID+"/leave", f.senderCookie, nil); rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("sender leave: %d %s", rec.Code, rec.Body.String())
	}
	if m, _ := f.h.db.GetMembership(t.Context(), req.GroupID, f.sender.userID); m != nil {
		t.Error("the sender's membership survived")
	}
	if rawItemExists(t, "GROUP#"+req.GroupID, "ADMISSION#"+f.sender.userID) {
		t.Error("the sender's admission survived")
	}
	rec := f.post(t, f.recipientCookie, req.GroupID, f.recipient)
	if rec.Code != http.StatusConflict || errCode(t, rec) != "dm_read_only" {
		t.Errorf("post to a DM the other person left: %d %s", rec.Code, rec.Body.String())
	}
	if g, _ := f.h.db.GetGroup(t.Context(), req.GroupID); g == nil {
		t.Error("the group went away with one member still in it")
	}
	// The pair is free again: a new conversation can start.
	fresh := dmRequestFor(t, f.sender, f.recipient)
	if rec := doCreateGroup(t, f.h, f.senderCookie, fresh); rec.Code != http.StatusCreated {
		t.Errorf("new DM after leaving: %d %s", rec.Code, rec.Body.String())
	}
	// The last person out deletes the old one, and leaves the new pair marker alone.
	if rec := doJSON(t, f.h, http.MethodPost, "/api/groups/"+req.GroupID+"/leave", f.recipientCookie, nil); rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("recipient leave: %d %s", rec.Code, rec.Body.String())
	}
	if g, _ := f.h.db.GetGroup(t.Context(), req.GroupID); g != nil {
		t.Error("the emptied DM survived")
	}
	if p := getPair(t, f.sender.userID, f.recipient.userID); p == nil || p.GroupID != fresh.GroupID {
		t.Errorf("the old group's cleanup removed the new DM's marker: %+v", p)
	}
}

func TestADMWithAPendingSlotIsStillWritableAfterNothingChanges(t *testing.T) {
	// Guard for the gate itself: an ordinary group is never read-only, even with one member.
	h := New(config.FromEnv(), testDB(t))
	u, c := loggedInUser(t, h)
	gid := createTestGroupWithMembers(t, h, u, c)
	if rec := (dmFixture{h: h}).post(t, c, gid, u); rec.Code != http.StatusCreated {
		t.Errorf("one-member ordinary group: %d %s", rec.Code, rec.Body.String())
	}
}

func TestDeletingTheRecipientsAccountClearsTheirIncomingDMs(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	if err := f.h.db.DeleteAccount(t.Context(), f.recipient.userID); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	if rawItemExists(t, "GROUP#"+req.GroupID, "DMREQ#"+f.recipient.userID) {
		t.Error("the slot to a deleted account survived")
	}
	if rawItemExists(t, "USER#"+f.sender.userID, "DMOUT#"+req.GroupID) {
		t.Error("the sender's pending pointer survived (it would count against their cap)")
	}
	// The sender's one-member conversation can still be withdrawn.
	if rec := doJSON(t, f.h, http.MethodPost, "/api/groups/"+req.GroupID+"/leave", f.senderCookie, nil); rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Errorf("sender leave: %d %s", rec.Code, rec.Body.String())
	}
	// And a new DM to a deleted account is refused.
	if rec := doCreateGroup(t, f.h, f.senderCookie, dmRequestFor(t, f.sender, f.recipient)); rec.Code != http.StatusNotFound {
		t.Errorf("DM to a deleted account: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAStalePairMarkerDoesNotBlockForever(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	// A group whose cleanup failed: delete the group's rows but leave the marker.
	out, err := rawDDB(t).Query(context.Background(), &dynamodb.QueryInput{
		TableName: aws.String(testTableName()), KeyConditionExpression: aws.String("PK = :p"), ConsistentRead: aws.Bool(true),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": &types.AttributeValueMemberS{Value: "GROUP#" + req.GroupID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range out.Items {
		if _, err := rawDDB(t).DeleteItem(context.Background(), &dynamodb.DeleteItemInput{TableName: aws.String(testTableName()), Key: map[string]types.AttributeValue{"PK": it["PK"], "SK": it["SK"]}}); err != nil {
			t.Fatal(err)
		}
	}
	if p := getPair(t, f.sender.userID, f.recipient.userID); p == nil {
		t.Fatal("setup: no marker")
	}
	if rec := doCreateGroup(t, f.h, f.senderCookie, dmRequestFor(t, f.sender, f.recipient)); rec.Code != http.StatusCreated {
		t.Errorf("DM over a stale marker: %d %s", rec.Code, rec.Body.String())
	}
}

func mustB64(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func setPairTTL(t *testing.T, a, b string, ttl int64) {
	t.Helper()
	_, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:        aws.String(testTableName()),
		Key:              map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: db.DMPairPK(a, b)}, "SK": &types.AttributeValueMemberS{Value: "PAIR"}},
		UpdateExpression: aws.String("SET #t = :t"), ExpressionAttributeNames: map[string]string{"#t": "TTL"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":t": &types.AttributeValueMemberN{Value: strconv.FormatInt(ttl, 10)}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAcceptDMWhenTheRecipientsKeysWereReplacedWithoutAnEpochBump(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	// The server now holds different public keys for the recipient than the ones the sender signed
	// and wrapped to. The epoch is untouched, so only the key comparison can catch it.
	for _, attr := range []string{"SigningPublicKey", "WrappingPublicKey"} {
		other := make([]byte, 32)
		_, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
			TableName:        aws.String(testTableName()),
			Key:              map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: "USER#" + f.recipient.userID}, "SK": &types.AttributeValueMemberS{Value: "PROFILE"}},
			UpdateExpression: aws.String("SET " + attr + " = :k"), ExpressionAttributeValues: map[string]types.AttributeValue{":k": &types.AttributeValueMemberB{Value: other}},
		})
		if err != nil {
			t.Fatal(err)
		}
		rec := f.accept(t, req)
		if rec.Code != http.StatusConflict || errCode(t, rec) != "keys_changed" {
			t.Errorf("%s replaced: %d %s", attr, rec.Code, rec.Body.String())
		}
		// Put the real key back for the next round.
		orig := f.recipient.signPub
		if attr == "WrappingPublicKey" {
			orig = f.recipient.wrapPub
		}
		if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
			TableName:        aws.String(testTableName()),
			Key:              map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: "USER#" + f.recipient.userID}, "SK": &types.AttributeValueMemberS{Value: "PROFILE"}},
			UpdateExpression: aws.String("SET " + attr + " = :k"), ExpressionAttributeValues: map[string]types.AttributeValue{":k": &types.AttributeValueMemberB{Value: orig}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if m, _ := f.h.db.GetMembership(t.Context(), req.GroupID, f.recipient.userID); m != nil {
		t.Error("a membership was written for replaced keys")
	}
	if rec := f.accept(t, req); rec.Code != http.StatusOK {
		t.Errorf("with the real keys back: %d %s", rec.Code, rec.Body.String())
	}
}

// A DM the other person has left takes no new content of any kind: post, comment or reaction.
func TestReadOnlyDMRefusesCommentsAndReactionsToo(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	postBody, _ := signedPost(t, req.GroupID, f.sender, postOpts{})
	if rec := doPost(t, f.h, f.senderCookie, req.GroupID, postBody); rec.Code != http.StatusCreated {
		t.Fatalf("post: %d %s", rec.Code, rec.Body.String())
	}
	pid := pidOf(req.GroupID, postBody.SortKey)
	if rec := f.accept(t, req); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	// While both are in, the recipient can comment and react.
	if rec := doComment(t, f.h, f.recipientCookie, pid, signedComment(t, req.GroupID, f.recipient, copts{})); rec.Code != http.StatusCreated {
		t.Fatalf("comment while both are in: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReaction(t, f.h, http.MethodPut, f.recipientCookie, pid, "0000", sealedReaction(t, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("reaction while both are in: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, f.h, http.MethodPost, "/api/groups/"+req.GroupID+"/leave", f.senderCookie, nil); rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("leave: %d", rec.Code)
	}
	rec := doComment(t, f.h, f.recipientCookie, pid, signedComment(t, req.GroupID, f.recipient, copts{path: "0002"}))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "dm_read_only" {
		t.Errorf("comment on a read-only DM: %d %s", rec.Code, rec.Body.String())
	}
	rec = doReaction(t, f.h, http.MethodPut, f.recipientCookie, pid, "0000", sealedReaction(t, 0))
	if rec.Code != http.StatusConflict || errCode(t, rec) != "dm_read_only" {
		t.Errorf("reaction on a read-only DM: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRecipientLeavingRemovesTheirAdmissionRecord(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	if rec := f.accept(t, req); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	if !rawItemExists(t, "GROUP#"+req.GroupID, "ADMISSION#"+f.recipient.userID) {
		t.Fatal("setup: no admission record")
	}
	if rec := doJSON(t, f.h, http.MethodPost, "/api/groups/"+req.GroupID+"/leave", f.recipientCookie, nil); rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("leave: %d", rec.Code)
	}
	if rawItemExists(t, "GROUP#"+req.GroupID, "ADMISSION#"+f.recipient.userID) {
		t.Error("the leaver's admission record survived")
	}
	if rec := f.post(t, f.senderCookie, req.GroupID, f.sender); rec.Code != http.StatusConflict {
		t.Errorf("the sender writing to a DM the recipient left: %d", rec.Code)
	}
}

// A DM is exactly two people: nobody can invite a third, by creating an invite or by completing
// one that already existed.
func TestNoInvitesIntoADM(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	if rec := f.accept(t, req); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	t.Run("the sender cannot create an invite", func(t *testing.T) {
		inv := signedCreateInviteRequest(t, f.sender, req.GroupID, time.Now().Add(24*time.Hour))
		rec := doJSON(t, f.h, http.MethodPost, "/api/groups/"+req.GroupID+"/invites", f.senderCookie, inv)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status %d %s", rec.Code, rec.Body.String())
		}
		if rawItemExists(t, "INVITE#"+inv.InviteID, "META") {
			t.Error("a refused invite was stored")
		}
	})

	t.Run("an invite that already existed cannot complete into a DM", func(t *testing.T) {
		// An ordinary group with an accepted invite, then its META is turned into a DM's: the only
		// way to reach CompleteInvite with a DM, since createInvite no longer allows one.
		creator, creatorCookie, invitee, groupID, inviteID := acceptedInviteFixture(t, f.h)
		if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
			TableName:        aws.String(testTableName()),
			Key:              map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: "GROUP#" + groupID}, "SK": &types.AttributeValueMemberS{Value: "META"}},
			UpdateExpression: aws.String("SET GroupType = :dm"), ExpressionAttributeValues: map[string]types.AttributeValue{":dm": &types.AttributeValueMemberS{Value: "dm"}},
		}); err != nil {
			t.Fatal(err)
		}
		adm := signedAdmission(t, f.h, creator, groupID, inviteID, invitee)
		rec := doJSON(t, f.h, http.MethodPost, "/api/invites/"+inviteID+"/complete", creatorCookie, completeBody(adm))
		if rec.Code == http.StatusOK {
			t.Errorf("completing into a DM succeeded: %s", rec.Body.String())
		}
		if m, _ := f.h.db.GetMembership(t.Context(), groupID, invitee.userID); m != nil {
			t.Error("a third member was written into a DM")
		}
	})
}

// Both people leaving at the same moment must end with the group deleted, never with a group that
// has no members and so can never be deleted.
func TestBothLeavingAtOnceDeletesTheDM(t *testing.T) {
	for i := 0; i < 15; i++ {
		other := newDMFixture(t) // fresh pair each round
		req := other.send(t)
		if rec := other.accept(t, req); rec.Code != http.StatusOK {
			t.Fatal(rec.Body.String())
		}
		done := make(chan int, 2)
		leave := func(c *http.Cookie) {
			rec := doJSON(t, other.h, http.MethodPost, "/api/groups/"+req.GroupID+"/leave", c, nil)
			done <- rec.Code
		}
		go leave(other.senderCookie)
		go leave(other.recipientCookie)
		codes := []int{<-done, <-done}
		for _, c := range codes {
			if c >= 500 {
				t.Fatalf("round %d: a leave answered %d", i, c)
			}
		}
		// A refused leave (409 conflict_retry) is retried, as the client does.
		for _, c := range []*http.Cookie{other.senderCookie, other.recipientCookie} {
			if g, _ := other.h.db.GetGroup(t.Context(), req.GroupID); g == nil {
				break
			}
			doJSON(t, other.h, http.MethodPost, "/api/groups/"+req.GroupID+"/leave", c, nil)
		}
		if g, _ := other.h.db.GetGroup(t.Context(), req.GroupID); g != nil {
			ids, _ := other.h.db.ListMemberGroupIDs(t.Context(), other.sender.userID)
			t.Fatalf("round %d (codes %v): the group survived with sender in %v", i, codes, ids)
		}
	}
}

func TestWriteDMCreateErrorMapsTheRaceToARetryable409(t *testing.T) {
	rec := httptest.NewRecorder()
	if !writeDMCreateError(rec, db.ErrDMRaced) {
		t.Fatal("ErrDMRaced was not handled")
	}
	if rec.Code != http.StatusConflict || errCode(t, rec) != "dm_conflict" {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}

// A session cookie that outlived the recipient's account deletion gets the same 410 createGroup
// gives, not a 500.
func TestAcceptDMByADeletedAccountIsGone(t *testing.T) {
	f := newDMFixture(t)
	req := f.send(t)
	// Tombstoned in place (keys and epoch intact) so the handler's key comparison passes and the
	// transaction's own check is what refuses.
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:        aws.String(testTableName()),
		Key:              map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: "USER#" + f.recipient.userID}, "SK": &types.AttributeValueMemberS{Value: "PROFILE"}},
		UpdateExpression: aws.String("SET DeletedAt = :d"), ExpressionAttributeValues: map[string]types.AttributeValue{":d": &types.AttributeValueMemberS{Value: "2026-11-08T00:00:00Z"}},
	}); err != nil {
		t.Fatal(err)
	}
	rec := f.accept(t, req)
	if rec.Code != http.StatusGone || errCode(t, rec) != "account_deleted" {
		t.Errorf("%d %s", rec.Code, rec.Body.String())
	}
}
