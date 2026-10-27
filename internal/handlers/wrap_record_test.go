package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
)

// wrapFields signs a wrap record as the wrapper would for the entry a request
// writes (#280): the generation and member key epoch of that wrap.
func wrapFields(t *testing.T, wrapper registeredUser, gid, memberID string, gen int64, epoch uint64, reason, day string) wrapRecordFields {
	t.Helper()
	sig, err := crypto.Sign(wrapper.signPriv, crypto.ContextWrapRecord, crypto.WrapRecordPayload(gid, wrapper.userID, memberID, gen, epoch, reason, day))
	if err != nil {
		t.Fatal(err)
	}
	return wrapRecordFields{WrapSignature: base64.StdEncoding.EncodeToString(sig), WrapDay: day}
}

// wantNoWrapRecord fails if the member's row carries any part of a record.
func wantNoWrapRecord(t *testing.T, gid, userID string) {
	t.Helper()
	row := getRow(t, "GROUP#"+gid, "MEMBER#"+userID)
	for _, a := range []string{"WrapperUserID", "WrapReason", "WrapDay", "WrapSignature"} {
		if _, has := row[a]; has {
			t.Fatalf("member row has %s, want no wrap record: %v", a, row)
		}
	}
}

// wantWrapRecord fails unless the row carries exactly this record.
func wantWrapRecord(t *testing.T, gid, userID, wrapper, reason, day string, f wrapRecordFields) {
	t.Helper()
	row := getRow(t, "GROUP#"+gid, "MEMBER#"+userID)
	if strAttr(row, "WrapperUserID") != wrapper || strAttr(row, "WrapReason") != reason || strAttr(row, "WrapDay") != day || bytesAttrB64(row, "WrapSignature") != f.WrapSignature {
		t.Fatalf("wrap record = %v, want wrapper %s reason %s day %s", row, wrapper, reason, day)
	}
}

// rosterRecord reads the record the roster serves for one member, nil when it serves none.
func rosterRecord(t *testing.T, h *Handler, cookie *http.Cookie, gid, userID string) *wrapRecordEntry {
	t.Helper()
	rec := doJSON(t, h, http.MethodGet, "/api/groups/"+gid+"/members", cookie, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("roster: %d %s", rec.Code, rec.Body.String())
	}
	var out listMembersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, m := range out.Members {
		if m.UserID == userID {
			return m.WrapRecord
		}
	}
	t.Fatalf("%s not on the roster", userID)
	return nil
}

func TestRewrapStoresAndServesTheApproversRecord(t *testing.T) {
	f := startRotation(t) // owner (admin) at generation 1; carol and dave at 0
	rotateUser(t, f.h, f.carol, loginCookie(t, f.h, f.carol))
	call := func(body approveRewrapRequest) *httptest.ResponseRecorder {
		return doApprove(t, f.h, f.ownerCookie, f.gid, f.carol.userID, body)
	}
	today := utcToday()
	good := func() approveRewrapRequest {
		b := approveBody(1, 1)
		b.wrapRecordFields = wrapFields(t, f.owner, f.gid, f.carol.userID, 1, 1, crypto.RekeyReasonApproval, today)
		return b
	}

	onlySig := good()
	onlySig.WrapDay = ""
	onlyDay := good()
	onlyDay.WrapSignature = ""
	staleDay := good()
	staleDay.wrapRecordFields = wrapFields(t, f.owner, f.gid, f.carol.userID, 1, 1, crypto.RekeyReasonApproval, time.Now().UTC().AddDate(0, 0, -3).Format("2006-01-02"))
	for name, tc := range map[string]struct {
		body approveRewrapRequest
		code string
	}{
		"signature without a day":     {onlySig, ""},
		"day without a signature":     {onlyDay, ""},
		"a day that has passed":       {staleDay, "signed_day_stale"},
		"signed for another member":   {withFields(approveBody(1, 1), wrapFields(t, f.owner, f.gid, f.dave.userID, 1, 1, crypto.RekeyReasonApproval, today)), "bad_signature"},
		"signed for another epoch":    {withFields(approveBody(1, 1), wrapFields(t, f.owner, f.gid, f.carol.userID, 1, 2, crypto.RekeyReasonApproval, today)), "bad_signature"},
		"signed for another gen":      {withFields(approveBody(1, 1), wrapFields(t, f.owner, f.gid, f.carol.userID, 0, 1, crypto.RekeyReasonApproval, today)), "bad_signature"},
		"signed as a self wrap":       {withFields(approveBody(1, 1), wrapFields(t, f.owner, f.gid, f.carol.userID, 1, 1, crypto.RekeyReasonSelf, today)), "bad_signature"},
		"signed by another account":   {withFields(approveBody(1, 1), wrapFields(t, f.dave, f.gid, f.carol.userID, 1, 1, crypto.RekeyReasonApproval, today)), "bad_signature"},
		"signed with a re-key digest": {withFields(approveBody(1, 1), rekeySigAsWrap(t, f.owner, f.gid, f.carol.userID, today)), "bad_signature"},
	} {
		rec := call(tc.body)
		if rec.Code != http.StatusBadRequest || (tc.code != "" && errCode(t, rec) != tc.code) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if memberGen(t, f.gid, f.carol) != "0" || wrapEpochOf(t, f.gid, f.carol.userID) != "absent" {
		t.Fatal("a refused wrap record still wrote the entry")
	}
	wantNoWrapRecord(t, f.gid, f.carol.userID)

	ok := good()
	if rec := call(ok); rec.Code != http.StatusNoContent {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	wantWrapRecord(t, f.gid, f.carol.userID, f.owner.userID, crypto.RekeyReasonApproval, today, ok.wrapRecordFields)
	got := rosterRecord(t, f.h, f.ownerCookie, f.gid, f.carol.userID)
	if got == nil || got.WrapperUserID != f.owner.userID || got.Reason != crypto.RekeyReasonApproval || got.Day != today || got.Signature != ok.WrapSignature {
		t.Fatalf("roster record = %+v", got)
	}
	if rosterRecord(t, f.h, f.ownerCookie, f.gid, f.dave.userID) != nil {
		t.Error("the roster serves a record for a member nobody wrapped")
	}
}

func withFields(b approveRewrapRequest, f wrapRecordFields) approveRewrapRequest {
	b.wrapRecordFields = f
	return b
}

// rekeySigAsWrap is a valid re-key signature for the same parties, put in the
// wrap-record fields: another context, so it must not verify.
func rekeySigAsWrap(t *testing.T, wrapper registeredUser, gid, memberID, day string) wrapRecordFields {
	t.Helper()
	sig, err := crypto.Sign(wrapper.signPriv, crypto.ContextRotationRekey, crypto.RotationRekeyPayload(gid, wrapper.userID, memberID, 1, crypto.RekeyReasonApproval))
	if err != nil {
		t.Fatal(err)
	}
	return wrapRecordFields{WrapSignature: base64.StdEncoding.EncodeToString(sig), WrapDay: day}
}

func TestAWrapFromAClientThatSignsNothingClearsTheOldRecord(t *testing.T) {
	h := noCooldown(t)
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	carol := registerTestUser(t, h)
	addMember(t, gid, carol, "member")
	today := utcToday()

	carol1, carolCookie := rotateUser(t, h, carol, loginCookie(t, h, carol), gid)
	first := approveBody(0, 1)
	first.wrapRecordFields = wrapFields(t, owner, gid, carol.userID, 0, 1, crypto.RekeyReasonApproval, today)
	if rec := doApprove(t, h, ownerCookie, gid, carol.userID, first); rec.Code != http.StatusNoContent {
		t.Fatalf("first approve: %d %s", rec.Code, rec.Body.String())
	}
	wantWrapRecord(t, gid, carol.userID, owner.userID, crypto.RekeyReasonApproval, today, first.wrapRecordFields)

	// She rotates again and an older client approves with no record: the earlier
	// one must not sit beside the new wrap. The first rotation's row is still
	// waiting, and a second rotation is refused until it is gone.
	if rec := doJSON(t, h, http.MethodDelete, "/api/account/rotation-handoff/"+gid, carolCookie, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete the handoff row: %d %s", rec.Code, rec.Body.String())
	}
	rot := signedRotation(t, carol1, rotateOpts{epoch: 1, credVersion: 2})
	if rec := doPutHandoff(t, h, carolCookie, gid, handoffBody(rot.next.wrapPub, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put the second row: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRotateKeys(t, h, carolCookie, rot.req); rec.Code != http.StatusOK {
		t.Fatalf("second rotation: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doApprove(t, h, ownerCookie, gid, carol.userID, approveBody(0, 2)); rec.Code != http.StatusNoContent {
		t.Fatalf("second approve: %d %s", rec.Code, rec.Body.String())
	}
	if got := wrapEpochOf(t, gid, carol.userID); got != "2" {
		t.Fatalf("WrapEpoch = %s, want 2", got)
	}
	wantNoWrapRecord(t, gid, carol.userID)
	if rosterRecord(t, h, ownerCookie, gid, carol.userID) != nil {
		t.Error("the roster still serves the cleared record")
	}
}

func TestSelfWrapStoresTheMembersOwnRecord(t *testing.T) {
	h := noCooldown(t)
	owner, _ := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, loginCookie(t, h, owner))
	carol, carolCookie := loggedInUser(t, h)
	addMember(t, gid, carol, "member")
	rot := signedRotation(t, carol, rotateOpts{})
	if rec := doPutHandoff(t, h, carolCookie, gid, handoffBody(rot.next.wrapPub, 0)); rec.Code != http.StatusNoContent {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRotateKeys(t, h, carolCookie, rot.req); rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	nextCookie := loginCookie(t, h, rot.next)
	today := utcToday()

	// Signed by the old keys, or as an approval, or for another epoch.
	for name, f := range map[string]wrapRecordFields{
		"old keys":      wrapFields(t, carol, gid, carol.userID, 0, 1, crypto.RekeyReasonSelf, today),
		"as approval":   wrapFields(t, rot.next, gid, carol.userID, 0, 1, crypto.RekeyReasonApproval, today),
		"another epoch": wrapFields(t, rot.next, gid, carol.userID, 0, 2, crypto.RekeyReasonSelf, today),
	} {
		b := selfWrapBody(0)
		b.wrapRecordFields = f
		if rec := doRotationCall(t, h, nextCookie, http.MethodPost, gid, "selfwrap", b); rec.Code != http.StatusBadRequest || errCode(t, rec) != "bad_signature" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if !handoffRowExists(t, carol.userID, gid) || wrapEpochOf(t, gid, carol.userID) == "1" {
		t.Fatal("a refused self-wrap consumed the row or wrote the entry")
	}

	b := selfWrapBody(0)
	b.wrapRecordFields = wrapFields(t, rot.next, gid, carol.userID, 0, 1, crypto.RekeyReasonSelf, today)
	if rec := doRotationCall(t, h, nextCookie, http.MethodPost, gid, "selfwrap", b); rec.Code != http.StatusNoContent {
		t.Fatalf("selfwrap: %d %s", rec.Code, rec.Body.String())
	}
	wantWrapRecord(t, gid, carol.userID, carol.userID, crypto.RekeyReasonSelf, today, b.wrapRecordFields)
}

func TestApproveRekeyAndSelfRekeyStoreRecordsAtTheNewGeneration(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	carol := registerTestUser(t, h)
	addMember(t, gid, carol, "member")
	rotateUser(t, h, carol, loginCookie(t, h, carol)) // dormant, entry still at the owner's generation
	today := utcToday()

	// The member's entry is written at generation 1, one past the admin's 0.
	body := approveRekeyBody(t, owner, gid, carol.userID, 1, crypto.RekeyReasonApproval, 1)
	body.wrapRecordFields = wrapFields(t, owner, gid, carol.userID, 0, 1, crypto.RekeyReasonApproval, today) // signed for the old generation
	if code := doApproveRekey(t, h, ownerCookie, gid, carol.userID, body); code != http.StatusBadRequest {
		t.Fatalf("a record for the old generation: %d %s", code, lastApproveRekey)
	}
	if getRow(t, "GROUP#"+gid, "ROTATION") != nil {
		t.Fatal("a refused record started the rotation")
	}
	body.wrapRecordFields = wrapFields(t, owner, gid, carol.userID, 1, 1, crypto.RekeyReasonApproval, today)
	if code := doApproveRekey(t, h, ownerCookie, gid, carol.userID, body); code != http.StatusNoContent {
		t.Fatalf("approve: %d %s", code, lastApproveRekey)
	}
	wantWrapRecord(t, gid, carol.userID, owner.userID, crypto.RekeyReasonApproval, today, body.wrapRecordFields)
	// The admin's own entry moved too, but nobody signed for it.
	wantNoWrapRecord(t, gid, owner.userID)
}

func TestSelfRekeyStoresTheAdminsOwnRecord(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	next, nextCookie := rotateUser(t, h, owner, ownerCookie, gid)
	today := utcToday()

	// The admin's own entry is written at generation 1, to their epoch 1.
	wrongEpoch := selfRekeyBody(t, next, gid, 1)
	wrongEpoch.wrapRecordFields = wrapFields(t, next, gid, next.userID, 1, 2, crypto.RekeyReasonSelf, today)
	if rec := doRotationCall(t, h, nextCookie, http.MethodPost, gid, "rekey", wrongEpoch); rec.Code != http.StatusBadRequest || errCode(t, rec) != "bad_signature" {
		t.Fatalf("a record for another epoch: %d %s", rec.Code, rec.Body.String())
	}
	if getRow(t, "GROUP#"+gid, "ROTATION") != nil || !handoffRowExists(t, owner.userID, gid) {
		t.Fatal("a refused record started the re-key or consumed the row")
	}

	ok := selfRekeyBody(t, next, gid, 1)
	ok.wrapRecordFields = wrapFields(t, next, gid, next.userID, 1, 1, crypto.RekeyReasonSelf, today)
	if rec := doRotationCall(t, h, nextCookie, http.MethodPost, gid, "rekey", ok); rec.Code != http.StatusNoContent {
		t.Fatalf("re-key: %d %s", rec.Code, rec.Body.String())
	}
	wantWrapRecord(t, gid, owner.userID, owner.userID, crypto.RekeyReasonSelf, today, ok.wrapRecordFields)
}
