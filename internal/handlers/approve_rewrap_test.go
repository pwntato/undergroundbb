package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
)

func doApprove(t *testing.T, h *Handler, cookie *http.Cookie, gid, uid string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, h, http.MethodPost, "/api/groups/"+gid+"/rewrap/"+uid, cookie, body)
}

func approveBody(gen int64, kep uint64) approveRewrapRequest {
	return approveRewrapRequest{
		Generation: gen, KeyEpoch: kep,
		WrappedKey: wrappedKey{EphemeralPub: b64(32), Nonce: b64(12), Ciphertext: b64(48)},
	}
}

func TestApproveRewrapEndpoint(t *testing.T) {
	f := startRotation(t) // owner (admin) at generation 1; carol and dave at 0
	carolNext, _ := rotateUser(t, f.h, f.carol, loginCookie(t, f.h, f.carol))
	call := func(cookie *http.Cookie, uid string, body any) *httptest.ResponseRecorder {
		return doApprove(t, f.h, cookie, f.gid, uid, body)
	}
	wantCode := func(rec *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		if rec.Code != status || (code != "" && errCode(t, rec) != code) {
			t.Fatalf("got %d %s, want %d %s", rec.Code, rec.Body.String(), status, code)
		}
	}

	// Refusals write nothing.
	wantCode(call(nil, carolNext.userID, approveBody(1, 1)), http.StatusUnauthorized, "")
	wantCode(call(f.ownerCookie, f.carol.userID, approveBody(1, 0)), http.StatusConflict, "wrap_epoch_stale")
	wantCode(call(f.ownerCookie, f.dave.userID, approveBody(1, 0)), http.StatusConflict, "member_not_dormant")
	wantCode(call(f.ownerCookie, f.owner.userID, approveBody(1, 1)), http.StatusBadRequest, "")
	wantCode(call(f.ownerCookie, f.carol.userID, approveBody(0, 1)), http.StatusBadRequest, "")
	bad := approveBody(1, 1)
	bad.WrappedKey.Nonce = "AA=="
	wantCode(call(f.ownerCookie, f.carol.userID, bad), http.StatusBadRequest, "")
	wantCode(call(f.ownerCookie, "not-a-uuid", approveBody(1, 1)), http.StatusNotFound, "")
	wantCode(call(f.ownerCookie, f.bobGone.userID, approveBody(1, 0)), http.StatusNotFound, "")
	daveCookie := loginCookie(t, f.h, f.dave)
	wantCode(call(daveCookie, f.carol.userID, approveBody(0, 1)), http.StatusForbidden, "")
	outsider, outsiderCookie := loggedInUser(t, f.h)
	_ = outsider
	wantCode(call(outsiderCookie, f.carol.userID, approveBody(1, 1)), http.StatusNotFound, "")
	if memberGen(t, f.gid, f.carol) != "0" || wrapEpochOf(t, f.gid, f.carol.userID) != "absent" {
		t.Fatal("a refused approval wrote the member")
	}

	// A member at the generation the approver holds needs the re-key.
	setMemberGeneration(t, f.gid, f.carol.userID, 1)
	wantCode(call(f.ownerCookie, f.carol.userID, approveBody(1, 1)), http.StatusConflict, "rekey_required")
	setMemberGeneration(t, f.gid, f.carol.userID, 0)

	wantCode(call(f.ownerCookie, f.carol.userID, approveBody(1, 1)), http.StatusNoContent, "")
	if memberGen(t, f.gid, f.carol) != "1" || wrapEpochOf(t, f.gid, f.carol.userID) != "1" {
		t.Fatalf("carol = gen %s, WrapEpoch %s, want 1 and 1", memberGen(t, f.gid, f.carol), wrapEpochOf(t, f.gid, f.carol.userID))
	}
}

func TestApproveRewrapEndpointOpenGroupWrapsTheCurrentKey(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	owner, ownerCookie := loggedInUser(t, h)
	gid := createOpenGroup(t, h, owner, ownerCookie)
	carol := registerTestUser(t, h)
	addMember(t, gid, carol, "member")
	rotateUser(t, h, carol, loginCookie(t, h, carol))

	// Carol's entry is at the generation the owner holds, and an Open group has
	// no re-key: the wrap replaces the copy the old keys hold.
	if rec := doApprove(t, h, ownerCookie, gid, carol.userID, approveBody(0, 1)); rec.Code != http.StatusNoContent {
		t.Fatalf("open approve: %d %s", rec.Code, rec.Body.String())
	}
	if got := wrapEpochOf(t, gid, carol.userID); got != "1" {
		t.Errorf("WrapEpoch = %s, want 1", got)
	}
}
