package db

import (
	"context"
	"errors"
	"testing"

	"github.com/pwntato/undergroundbb/internal/models"
)

// designationFixture is a group made by CreateGroup (so the admin has a stored
// root grant) with one member. Ids are unique per run: PROFILE rows persist in
// DynamoDB Local across runs.
func designationFixture(t *testing.T, c *Client) (gid, admin, member, ref string) {
	t.Helper()
	gid, admin, member, ref = newTestGroupWithMember(t, c)
	t.Cleanup(func() { _ = c.sweepPartition(context.Background(), "GROUP#"+gid) })
	return
}

func TestPutDesignationConditions(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid, admin, member, ref := designationFixture(t, c)
	in := func(sk string) PutDesignationInput {
		return PutDesignationInput{
			GroupID: gid, AdminUserID: admin, SortKey: sk, SuccessorUserID: member,
			PeriodDays: 90, AdminGrantRef: ref, AdminHasStoredGrant: true, Signature: []byte{1},
		}
	}
	sk := "DESIGNATION#" + admin + "#2026-02-01#0011223344556677"
	if err := c.PutDesignation(ctx, in(sk)); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := c.PutDesignation(ctx, in(sk)); !errors.Is(err, ErrDesignationKeyTaken) {
		t.Fatalf("same sort key: %v, want ErrDesignationKeyTaken", err)
	}

	stale := in("DESIGNATION#" + admin + "#2026-02-02#0011223344556677")
	stale.AdminGrantRef = "GRANT#" + admin + "#2025-01-01#ffffffffffffffff"
	if err := c.PutDesignation(ctx, stale); !errors.Is(err, ErrDesignationAdminChanged) {
		t.Fatalf("stale ref: %v, want ErrDesignationAdminChanged", err)
	}
	// An admin whose role dropped since they signed.
	setMemberRole(t, c, gid, admin, models.RoleMember)
	if err := c.PutDesignation(ctx, in("DESIGNATION#"+admin+"#2026-02-03#0011223344556677")); !errors.Is(err, ErrDesignationAdminChanged) {
		t.Fatalf("demoted admin: %v, want ErrDesignationAdminChanged", err)
	}
}

func TestPutDesignationSuccessorConditions(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid, admin, member, ref := designationFixture(t, c)
	in := PutDesignationInput{
		GroupID: gid, AdminUserID: admin, SuccessorUserID: member,
		PeriodDays: 90, AdminGrantRef: ref, AdminHasStoredGrant: true, Signature: []byte{1},
	}

	in.SortKey = "DESIGNATION#" + admin + "#2026-02-01#0011223344556677"
	in.SuccessorUserID = "test-ghost-" + randomSuffix(t)
	if err := c.PutDesignation(ctx, in); !errors.Is(err, ErrDesignationSuccessorGone) {
		t.Fatalf("non-member: %v, want ErrDesignationSuccessorGone", err)
	}

	in.SortKey = "DESIGNATION#" + admin + "#2026-02-02#0011223344556677"
	in.SuccessorUserID = member
	putTombstone(t, c, member)
	if err := c.PutDesignation(ctx, in); !errors.Is(err, ErrDesignationSuccessorDeleted) {
		t.Fatalf("deleted successor: %v, want ErrDesignationSuccessorDeleted", err)
	}

	// A revocation names nobody, so neither successor condition applies.
	in.SortKey = "DESIGNATION#" + admin + "#2026-02-03#0011223344556677"
	in.SuccessorUserID = ""
	if err := c.PutDesignation(ctx, in); err != nil {
		t.Fatalf("revocation: %v", err)
	}
}

func TestHasDesignationOnDayAndListDesignations(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid, admin, member, ref := designationFixture(t, c)
	for _, day := range []string{"2026-03-01", "2026-03-02"} {
		if err := c.PutDesignation(ctx, PutDesignationInput{
			GroupID: gid, AdminUserID: admin, SortKey: "DESIGNATION#" + admin + "#" + day + "#0011223344556677",
			SuccessorUserID: member, PeriodDays: 30, AdminGrantRef: ref, AdminHasStoredGrant: true, Signature: []byte{1},
		}); err != nil {
			t.Fatal(err)
		}
	}
	for day, want := range map[string]bool{"2026-03-01": true, "2026-03-02": true, "2026-03-03": false} {
		got, err := c.HasDesignationOnDay(ctx, gid, admin, day)
		if err != nil || got != want {
			t.Errorf("HasDesignationOnDay(%s) = %v, %v, want %v", day, got, err, want)
		}
	}
	// Another admin's designation on the same day is not this admin's.
	if got, _ := c.HasDesignationOnDay(ctx, gid, "test-ghost-"+randomSuffix(t), "2026-03-01"); got {
		t.Error("HasDesignationOnDay matched another admin")
	}

	rows, next, err := c.ListDesignations(ctx, gid, "", 10)
	if err != nil || len(rows) != 2 || next != "" {
		t.Fatalf("list: %d rows, next %q, %v", len(rows), next, err)
	}
	if rows[0].SK >= rows[1].SK {
		t.Errorf("not in sort-key order: %q, %q", rows[0].SK, rows[1].SK)
	}
	// GRANT# rows are not designations (CreateGroup wrote the root grant).
	if rows, _, _ := c.ListDesignations(ctx, gid, "", 10); len(rows) != 2 {
		t.Errorf("a GRANT# row leaked into the designation list: %d rows", len(rows))
	}
}
