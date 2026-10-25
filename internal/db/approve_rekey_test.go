package db

import (
	"context"
	"errors"
	"testing"

	"github.com/pwntato/undergroundbb/internal/models"
)

func approveRekeyInput(g, admin, member string, cur int64, adminKep, memberKep uint64) ApproveRekeyInput {
	k := func(tag string) models.WrappedKey {
		return models.WrappedKey{EphemeralPub: []byte("e"), Nonce: []byte("n"), Ciphertext: []byte(tag)}
	}
	return ApproveRekeyInput{
		GroupID: g, AdminUserID: admin, MemberUserID: member, CurrentGeneration: cur,
		Link:            models.WrappedBlob{Nonce: []byte("N"), Ciphertext: []byte("L")},
		AdminWrappedKey: k("ADMIN"), AdminKeyEpoch: adminKep,
		MemberWrappedKey: k("MEMBER"), MemberKeyEpoch: memberKep,
		Reason: "approval", StartSignature: []byte("sig"),
	}
}

// approveRekeyGroup: admin a1 and member m1, both at generation 0, no marker.
// m1 rotated (KeyEpoch 1) and is dormant.
func approveRekeyGroup(t *testing.T, c *Client) string {
	t.Helper()
	g := newLeaveGroup(t, c)
	putTestMember(t, c, g, "a1", "admin")
	putTestMember(t, c, g, "m1", "member")
	putProfileAtEpoch(t, c, "m1", 1, false)
	return g
}

func TestApproveRekeyWritesTheMarkerTheLinkAndBothEntries(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := approveRekeyGroup(t, c)
	if err := c.ApproveRekey(ctx, approveRekeyInput(g, "a1", "m1", 0, 0, 1)); err != nil {
		t.Fatal(err)
	}
	rot, _ := c.GetRotation(ctx, g)
	if rot == nil || rot.Generation != 1 || rot.StartedBy != "a1" || rot.RekeyedUserID != "m1" || rot.RekeyReason != "approval" || rot.RemovedUserID != "" {
		t.Fatalf("marker = %+v", rot)
	}
	if !itemExists(t, c, "GROUP#"+g, GenKeySortKey(0)) {
		t.Fatal("no link")
	}
	a, m := readMember(t, c, g, "a1"), readMember(t, c, g, "m1")
	if a.Generation != 1 || string(a.WrappedGroupKey.Ciphertext) != "ADMIN" || m.Generation != 1 || m.WrapEpoch != 1 || string(m.WrappedGroupKey.Ciphertext) != "MEMBER" {
		t.Fatalf("admin = %+v, member = %+v", a, m)
	}
}

func TestApproveRekeyRefusals(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	g := approveRekeyGroup(t, c)
	untouched := func() {
		t.Helper()
		if itemExists(t, c, "GROUP#"+g, RotationSortKey) || itemExists(t, c, "GROUP#"+g, GenKeySortKey(0)) {
			t.Fatal("a refused approval wrote a marker or a link")
		}
		if readMember(t, c, g, "a1").Generation != 0 || readMember(t, c, g, "m1").Generation != 0 {
			t.Fatal("a refused approval moved an entry")
		}
	}

	// The admin's own keys moved since the handler read them.
	putProfileAtEpoch(t, c, "a1", 2, false)
	if err := c.ApproveRekey(ctx, approveRekeyInput(g, "a1", "m1", 0, 1, 1)); !errors.Is(err, ErrCallerKeyEpochStale) {
		t.Fatalf("stale admin epoch: %v, want ErrCallerKeyEpochStale", err)
	}
	// The member rotated again.
	if err := c.ApproveRekey(ctx, approveRekeyInput(g, "a1", "m1", 0, 2, 0)); !errors.Is(err, ErrWrapEpochStale) {
		t.Fatalf("stale member epoch: %v, want ErrWrapEpochStale", err)
	}
	// Caught up already.
	setWrapEpoch(t, c, g, "m1", 1)
	if err := c.ApproveRekey(ctx, approveRekeyInput(g, "a1", "m1", 0, 2, 1)); !errors.Is(err, ErrMemberNotDormant) {
		t.Fatalf("caught up: %v, want ErrMemberNotDormant", err)
	}
	setWrapEpoch(t, c, g, "m1", 0)
	// An account that never rotated is not dormant, whatever its WrapEpoch.
	putTestMember(t, c, g, "m4", "member")
	if err := c.ApproveRekey(ctx, approveRekeyInput(g, "a1", "m4", 0, 2, 0)); !errors.Is(err, ErrMemberNotDormant) {
		t.Fatalf("never rotated: %v, want ErrMemberNotDormant", err)
	}
	// A plain member as the admin, and an admin at another generation.
	putTestMember(t, c, g, "m2", "member")
	if err := c.ApproveRekey(ctx, approveRekeyInput(g, "m2", "m1", 0, 0, 1)); !errors.Is(err, ErrRewrapCallerBehind) {
		t.Fatalf("plain member: %v, want ErrRewrapCallerBehind", err)
	}
	if err := c.ApproveRekey(ctx, approveRekeyInput(g, "a1", "m1", 1, 2, 1)); !errors.Is(err, ErrRewrapCallerBehind) {
		t.Fatalf("admin at another generation: %v, want ErrRewrapCallerBehind", err)
	}
	// Gone.
	if err := c.ApproveRekey(ctx, approveRekeyInput(g, "a1", "nobody", 0, 2, 0)); !errors.Is(err, ErrRewrapMemberChanged) {
		t.Fatalf("not a member: %v, want ErrRewrapMemberChanged", err)
	}
	putProfileAtEpoch(t, c, "gone", 1, true)
	putTestMember(t, c, g, "gone", "member")
	if err := c.ApproveRekey(ctx, approveRekeyInput(g, "a1", "gone", 0, 2, 1)); !errors.Is(err, ErrRewrapMemberChanged) {
		t.Fatalf("deleted account: %v, want ErrRewrapMemberChanged", err)
	}
	untouched()

	// Behind the admin's generation: a plain wrap is enough. Past it: moved on.
	setMemberGeneration(t, c, g, "a1", 1)
	if err := c.ApproveRekey(ctx, approveRekeyInput(g, "a1", "m1", 1, 2, 1)); !errors.Is(err, ErrRekeyNotRequired) {
		t.Fatalf("member behind: %v, want ErrRekeyNotRequired", err)
	}
	setMemberGeneration(t, c, g, "m1", 2)
	if err := c.ApproveRekey(ctx, approveRekeyInput(g, "a1", "m1", 1, 2, 1)); !errors.Is(err, ErrRewrapMemberChanged) {
		t.Fatalf("member past: %v, want ErrRewrapMemberChanged", err)
	}
	setMemberGeneration(t, c, g, "a1", 0)
	setMemberGeneration(t, c, g, "m1", 0)

	// One rotation at a time.
	if err := c.ApproveRekey(ctx, approveRekeyInput(g, "a1", "m1", 0, 2, 1)); err != nil {
		t.Fatal(err)
	}
	putTestMember(t, c, g, "m3", "member")
	if err := c.ApproveRekey(ctx, approveRekeyInput(g, "a1", "m3", 1, 2, 1)); !errors.Is(err, ErrRotationInProgress) {
		t.Fatalf("second start: %v, want ErrRotationInProgress", err)
	}
}
