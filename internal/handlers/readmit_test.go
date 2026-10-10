package handlers

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/config"
)

// Re-admitting a member (#178): a fresh admission by a current admin or
// ambassador replaces a record that can no longer verify.

func readmitBody(t *testing.T, h *Handler, signer registeredUser, gid string, subject registeredUser, gen int64) readmitRequest {
	t.Helper()
	inviteID := newUUID(t)
	day := time.Now().UTC().Format("2006-01-02")
	adm := signedAdmissionAt(t, h, signer, gid, inviteID, subject, "", day, gen)
	return readmitRequest{InviteID: inviteID, Generation: gen, InviterGrantRef: adm.InviterGrantRef, Day: day, Signature: adm.Signature}
}

func doReadmit(t *testing.T, h *Handler, cookie *http.Cookie, gid, subjectID string, body any) int {
	t.Helper()
	rec := doJSON(t, h, http.MethodPost, "/api/groups/"+gid+"/members/"+subjectID+"/readmit", cookie, body)
	return rec.Code
}

func admissionRow(t *testing.T, gid, userID string) map[string]types.AttributeValue {
	t.Helper()
	return getRow(t, "GROUP#"+gid, "ADMISSION#"+userID)
}

func TestReadmitEndpoint(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	gid, owner, bob, carol, ownerCookie, bobCookie, carolCookie := rotatingGroupWith(t, h)
	dave, _ := loggedInUser(t, h)
	addMember(t, gid, dave, "member")
	putAdmissionRow(t, gid, dave.userID) // the stale record: no signature, no inviter
	stale := strAttr(admissionRow(t, gid, dave.userID), "InviterUserID")

	ok := readmitBody(t, h, owner, gid, dave, 0)
	wrongGen := readmitBody(t, h, owner, gid, dave, 1)
	wrongGen.Generation = 1 // signed for 1, but the owner is at 0
	badID := ok
	badID.InviteID = "not-a-uuid"
	staleRef := ok
	staleRef.InviterGrantRef = "GRANT#" + owner.userID + "#2020-01-01#0000000000000001"
	badDay := ok
	badDay.Day = time.Now().UTC().AddDate(0, 0, -5).Format("2006-01-02")
	bySomeoneElse := readmitBody(t, h, bob, gid, dave, 0) // signed by bob, sent by the owner
	bySomeoneElse.InviterGrantRef = ok.InviterGrantRef
	forOtherKeys := readmitBody(t, h, owner, gid, carol, 0) // signed over carol's keys, sent for dave

	for name, tc := range map[string]struct {
		cookie  *http.Cookie
		subject string
		body    readmitRequest
		status  int
	}{
		"unauthenticated":              {nil, dave.userID, ok, http.StatusUnauthorized},
		"plain member":                 {carolCookie, dave.userID, ok, http.StatusForbidden},
		"yourself":                     {ownerCookie, owner.userID, ok, http.StatusBadRequest},
		"not a member":                 {ownerCookie, newUUID(t), ok, http.StatusNotFound},
		"malformed member id":          {ownerCookie, "nope", ok, http.StatusNotFound},
		"bad invite id":                {ownerCookie, dave.userID, badID, http.StatusBadRequest},
		"wrong generation":             {ownerCookie, dave.userID, wrongGen, http.StatusBadRequest},
		"stale grant ref":              {ownerCookie, dave.userID, staleRef, http.StatusConflict},
		"day out of tolerance":         {ownerCookie, dave.userID, badDay, http.StatusBadRequest},
		"signed by someone else":       {ownerCookie, dave.userID, bySomeoneElse, http.StatusBadRequest},
		"signed over another's keys":   {ownerCookie, dave.userID, forOtherKeys, http.StatusBadRequest},
		"admin without a stored grant": {bobCookie, dave.userID, readmitBody(t, h, bob, gid, dave, 0), http.StatusConflict},
	} {
		if got := doReadmit(t, h, tc.cookie, gid, tc.subject, tc.body); got != tc.status {
			t.Errorf("%s: status %d, want %d", name, got, tc.status)
		}
	}
	if strAttr(admissionRow(t, gid, dave.userID), "InviterUserID") != stale {
		t.Fatal("a refused re-admission replaced the admission")
	}

	if got := doReadmit(t, h, ownerCookie, gid, dave.userID, ok); got != http.StatusNoContent {
		t.Fatalf("re-admit: %d", got)
	}
	row := admissionRow(t, gid, dave.userID)
	if strAttr(row, "InviterUserID") != owner.userID || strAttr(row, "InviteID") != ok.InviteID || strAttr(row, "Day") != ok.Day {
		t.Fatalf("the stored admission is not the owner's fresh one: %v", row)
	}
}

func TestReadmitEndpointAmbassadorAndRunningRotation(t *testing.T) {
	f := leftRotating(t) // a rotation is running: carol left, owner and bob are admins
	amb, ambCookie := loggedInUser(t, f.h)
	addMember(t, f.gid, amb, "ambassador")
	const ref = "GRANT#00000000-0000-4000-8000-000000000001#2026-01-01#0000000000000001"
	if _, err := rawDDB(t).UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName:                 aws.String(testTableName()),
		Key:                       map[string]types.AttributeValue{"PK": &types.AttributeValueMemberS{Value: "GROUP#" + f.gid}, "SK": &types.AttributeValueMemberS{Value: "MEMBER#" + amb.userID}},
		UpdateExpression:          aws.String("SET GrantSortKey = :r"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":r": &types.AttributeValueMemberS{Value: ref}},
	}); err != nil {
		t.Fatal(err)
	}
	putAdmissionRow(t, f.gid, f.dave.userID)
	if getRow(t, "GROUP#"+f.gid, "ROTATION") == nil {
		t.Fatal("fixture: no rotation is running")
	}
	body := readmitBody(t, f.h, amb, f.gid, f.dave, 0)
	if body.InviterGrantRef != ref {
		t.Fatalf("grant ref = %q", body.InviterGrantRef)
	}
	if got := doReadmit(t, f.h, ambCookie, f.gid, f.dave.userID, body); got != http.StatusNoContent {
		t.Fatalf("an ambassador's re-admission during a rotation: %d", got)
	}
	if strAttr(admissionRow(t, f.gid, f.dave.userID), "InviterUserID") != amb.userID {
		t.Fatal("the ambassador's admission was not stored")
	}
}
