package handlers

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
)

func approveRekeyBody(t *testing.T, admin registeredUser, gid, memberID string, gen int64, reason string, kep uint64) approveRekeyRequest {
	t.Helper()
	sig, err := crypto.Sign(admin.signPriv, crypto.ContextRotationRekey, crypto.RotationRekeyPayload(gid, admin.userID, memberID, gen, reason))
	if err != nil {
		t.Fatal(err)
	}
	return approveRekeyRequest{
		Generation:       gen,
		Link:             wrappedBlob{Nonce: b64(12), Ciphertext: b64(48)},
		WrappedKey:       wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		MemberWrappedKey: wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
		MemberKeyEpoch:   kep,
		StartSignature:   base64.StdEncoding.EncodeToString(sig),
	}
}

func doApproveRekey(t *testing.T, h *Handler, cookie *http.Cookie, gid, memberID string, body any) int {
	t.Helper()
	rec := doJSON(t, h, http.MethodPost, "/api/groups/"+gid+"/rotation/approve/"+memberID, cookie, body)
	lastApproveRekey = rec.Body.String()
	return rec.Code
}

var lastApproveRekey string

func wantApproveRekey(t *testing.T, got, status int, code string) {
	t.Helper()
	if got != status || (code != "" && !bytesContain([]byte(lastApproveRekey), `"`+code+`"`)) {
		t.Fatalf("got %d %s, want %d %s", got, lastApproveRekey, status, code)
	}
}

func TestApproveRekeyStartsARotationAndWrapsTheApprovedMember(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createPrivateGroup(t, h, owner, ownerCookie)
	carol, dave := registerTestUser(t, h), registerTestUser(t, h)
	addMember(t, gid, carol, "member")
	addMember(t, gid, dave, "member")
	rotateUser(t, h, carol, loginCookie(t, h, carol)) // dormant, entry still at the owner's generation

	ok := approveRekeyBody(t, owner, gid, carol.userID, 1, crypto.RekeyReasonApproval, 1)
	nothingWritten := func() {
		t.Helper()
		if getRow(t, "GROUP#"+gid, "ROTATION") != nil || getRow(t, "GROUP#"+gid, "GENKEY#000000") != nil {
			t.Fatal("a refused approval wrote a marker or a link")
		}
		if memberGen(t, gid, carol) != "0" || wrapEpochOf(t, gid, carol.userID) != "absent" || memberGen(t, gid, owner) != "0" {
			t.Fatal("a refused approval moved an entry")
		}
	}

	selfReason := approveRekeyBody(t, owner, gid, carol.userID, 1, crypto.RekeyReasonSelf, 1)
	otherMember := approveRekeyBody(t, owner, gid, dave.userID, 1, crypto.RekeyReasonApproval, 1)
	// Signed for 2, so only the generation check can refuse it.
	wrongGen := approveRekeyBody(t, owner, gid, carol.userID, 2, crypto.RekeyReasonApproval, 1)
	staleEpoch := approveRekeyBody(t, owner, gid, carol.userID, 1, crypto.RekeyReasonApproval, 0)
	badKey := ok
	badKey.MemberWrappedKey.Nonce = "AA=="

	wantApproveRekey(t, doApproveRekey(t, h, nil, gid, carol.userID, ok), http.StatusUnauthorized, "")
	wantApproveRekey(t, doApproveRekey(t, h, ownerCookie, gid, carol.userID, selfReason), http.StatusBadRequest, "bad_signature")
	wantApproveRekey(t, doApproveRekey(t, h, ownerCookie, gid, carol.userID, otherMember), http.StatusBadRequest, "bad_signature")
	wantApproveRekey(t, doApproveRekey(t, h, ownerCookie, gid, carol.userID, wrongGen), http.StatusBadRequest, "")
	wantApproveRekey(t, doApproveRekey(t, h, ownerCookie, gid, carol.userID, badKey), http.StatusBadRequest, "")
	wantApproveRekey(t, doApproveRekey(t, h, ownerCookie, gid, owner.userID, approveRekeyBody(t, owner, gid, owner.userID, 1, crypto.RekeyReasonApproval, 1)), http.StatusBadRequest, "")
	wantApproveRekey(t, doApproveRekey(t, h, ownerCookie, gid, carol.userID, staleEpoch), http.StatusConflict, "wrap_epoch_stale")
	// Dave never rotated: nothing to approve.
	wantApproveRekey(t, doApproveRekey(t, h, ownerCookie, gid, dave.userID, approveRekeyBody(t, owner, gid, dave.userID, 1, crypto.RekeyReasonApproval, 0)), http.StatusConflict, "member_not_dormant")
	wantApproveRekey(t, doApproveRekey(t, h, ownerCookie, gid, "not-a-uuid", ok), http.StatusNotFound, "")
	// A real account that is not a member.
	stranger := registerTestUser(t, h)
	wantApproveRekey(t, doApproveRekey(t, h, ownerCookie, gid, stranger.userID, approveRekeyBody(t, owner, gid, stranger.userID, 1, crypto.RekeyReasonApproval, 0)), http.StatusNotFound, "")
	// A plain member cannot start a rotation.
	daveCookie := loginCookie(t, h, dave)
	wantApproveRekey(t, doApproveRekey(t, h, daveCookie, gid, carol.userID, approveRekeyBody(t, dave, gid, carol.userID, 1, crypto.RekeyReasonApproval, 1)), http.StatusForbidden, "")
	_, outsiderCookie := loggedInUser(t, h)
	wantApproveRekey(t, doApproveRekey(t, h, outsiderCookie, gid, carol.userID, ok), http.StatusNotFound, "")
	nothingWritten()

	// A member behind the admin's generation needs only a plain wrap.
	setMemberGeneration(t, gid, owner.userID, 1)
	wantApproveRekey(t, doApproveRekey(t, h, ownerCookie, gid, carol.userID, approveRekeyBody(t, owner, gid, carol.userID, 2, crypto.RekeyReasonApproval, 1)), http.StatusConflict, "rekey_not_required")
	setMemberGeneration(t, gid, owner.userID, 0)
	nothingWritten()

	wantApproveRekey(t, doApproveRekey(t, h, ownerCookie, gid, carol.userID, ok), http.StatusNoContent, "")
	m := getRow(t, "GROUP#"+gid, "ROTATION")
	if strAttr(m, "StartedBy") != owner.userID || strAttr(m, "RekeyedUserID") != carol.userID || strAttr(m, "RekeyReason") != crypto.RekeyReasonApproval || bytesAttrB64(m, "StartSignature") != ok.StartSignature {
		t.Fatalf("marker = %v", m)
	}
	if _, has := m["RemovedUserID"]; has {
		t.Error("an approval marker names a removed member")
	}
	link := getRow(t, "GROUP#"+gid, "GENKEY#000000")
	if strAttr(link, "RemoverUserID") != owner.userID || strAttr(link, "RekeyedUserID") != carol.userID || strAttr(link, "RekeyReason") != crypto.RekeyReasonApproval {
		t.Fatalf("link = %v", link)
	}
	if memberGen(t, gid, owner) != "1" || memberGen(t, gid, carol) != "1" || wrapEpochOf(t, gid, carol.userID) != "1" {
		t.Fatalf("owner gen %s, carol gen %s WrapEpoch %s; want 1, 1, 1", memberGen(t, gid, owner), memberGen(t, gid, carol), wrapEpochOf(t, gid, carol.userID))
	}
	if memberGen(t, gid, dave) != "0" {
		t.Error("the start moved a member the job re-wraps")
	}
	// One rotation at a time.
	wantApproveRekey(t, doApproveRekey(t, h, ownerCookie, gid, carol.userID, approveRekeyBody(t, owner, gid, carol.userID, 2, crypto.RekeyReasonApproval, 1)), http.StatusConflict, "rotation_in_progress")
}

func TestApproveRekeyRefusesAnOpenGroup(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	carol := registerTestUser(t, h)
	addMember(t, gid, carol, "member")
	rotateUser(t, h, carol, loginCookie(t, h, carol))
	wantApproveRekey(t, doApproveRekey(t, h, ownerCookie, gid, carol.userID, approveRekeyBody(t, owner, gid, carol.userID, 1, crypto.RekeyReasonApproval, 1)), http.StatusBadRequest, "rotation_not_applicable")
	if getRow(t, "GROUP#"+gid, "ROTATION") != nil {
		t.Fatal("a refused approval wrote a marker")
	}
}
