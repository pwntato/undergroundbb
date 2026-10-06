package db

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

func claimInput(gid, admin, member, ref, designation, claimKey string) ClaimDesignationInput {
	return ClaimDesignationInput{
		GroupID: gid, AdminUserID: admin, AdminGrantRef: ref, AdminHasStoredGrant: true,
		SuccessorUserID: member, SuccessorOldRole: models.RoleMember,
		DesignationSortKey: designation, ClaimSortKey: claimKey, Signature: []byte{9},
	}
}

func TestClaimDesignationWritesRowAndPromotes(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid, admin, member, ref := designationFixture(t, c)
	desig := "DESIGNATION#" + admin + "#2026-01-01#0011223344556677"
	claim := "GRANT#" + member + "#2026-06-01#8899aabbccddeeff"
	if err := c.ClaimDesignation(ctx, claimInput(gid, admin, member, ref, desig, claim)); err != nil {
		t.Fatal(err)
	}
	m, err := c.GetMembership(ctx, gid, member)
	if err != nil || m.Role != models.RoleAdmin || m.GrantSortKey != claim {
		t.Fatalf("membership: %+v, %v", m, err)
	}
	cited, err := c.ListGrantsCiting(ctx, gid, desig)
	if err != nil || len(cited) != 1 || cited[0].SK != claim || cited[0].GrantorUserID != admin ||
		cited[0].GrantorGrantRef != ref || cited[0].GrantedRole != models.RoleAdmin || cited[0].SubjectUserID != member {
		t.Fatalf("citing: %+v, %v", cited, err)
	}
	if other, _ := c.ListGrantsCiting(ctx, gid, desig+"x"); len(other) != 0 {
		t.Errorf("ListGrantsCiting matched a different designation: %+v", other)
	}
	to, err := c.ListGrantsTo(ctx, gid, member)
	if err != nil || len(to) != 1 || to[0].SK != claim {
		t.Fatalf("grants to member: %+v, %v", to, err)
	}
	if to, _ := c.ListGrantsTo(ctx, gid, admin); len(to) != 1 {
		t.Errorf("grants to admin = %d, want only the root grant", len(to))
	}
}

func TestClaimDesignationConditions(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	desigOf := func(admin string) string { return "DESIGNATION#" + admin + "#2026-01-01#0011223344556677" }

	t.Run("admin demoted", func(t *testing.T) {
		gid, admin, member, ref := designationFixture(t, c)
		setMemberRole(t, c, gid, admin, models.RoleMember)
		claim := "GRANT#" + member + "#2026-06-01#8899aabbccddeeff"
		err := c.ClaimDesignation(ctx, claimInput(gid, admin, member, ref, desigOf(admin), claim))
		if !errors.Is(err, ErrClaimAdminChanged) {
			t.Fatalf("%v, want ErrClaimAdminChanged", err)
		}
		assertNothingClaimed(t, c, gid, member, claim)
	})
	t.Run("admin on a different grant", func(t *testing.T) {
		gid, admin, member, ref := designationFixture(t, c)
		claim := "GRANT#" + member + "#2026-06-01#8899aabbccddeeff"
		err := c.ClaimDesignation(ctx, claimInput(gid, admin, member, ref+"x", desigOf(admin), claim))
		if !errors.Is(err, ErrClaimAdminChanged) {
			t.Fatalf("%v, want ErrClaimAdminChanged", err)
		}
		assertNothingClaimed(t, c, gid, member, claim)
	})
	t.Run("admin gained a stored grant pointer after the handler read the root fallback", func(t *testing.T) {
		gid, admin, member, ref := designationFixture(t, c)
		claim := "GRANT#" + member + "#2026-06-01#8899aabbccddeeff"
		in := claimInput(gid, admin, member, ref, desigOf(admin), claim)
		in.AdminHasStoredGrant = false // the fixture's admin does have one
		if err := c.ClaimDesignation(ctx, in); !errors.Is(err, ErrClaimAdminChanged) {
			t.Fatalf("%v, want ErrClaimAdminChanged", err)
		}
		assertNothingClaimed(t, c, gid, member, claim)
	})
	t.Run("successor's role changed", func(t *testing.T) {
		gid, admin, member, ref := designationFixture(t, c)
		claim := "GRANT#" + member + "#2026-06-01#8899aabbccddeeff"
		in := claimInput(gid, admin, member, ref, desigOf(admin), claim)
		in.SuccessorOldRole = models.RoleAmbassador // the successor is a plain member
		if err := c.ClaimDesignation(ctx, in); !errors.Is(err, ErrClaimRoleChanged) {
			t.Fatalf("%v, want ErrClaimRoleChanged", err)
		}
		assertNothingClaimed(t, c, gid, member, claim)
	})
	t.Run("successor left", func(t *testing.T) {
		gid, admin, member, ref := designationFixture(t, c)
		if _, err := c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(c.table), Key: memberKey(gid, member)}); err != nil {
			t.Fatal(err)
		}
		claim := "GRANT#" + member + "#2026-06-01#8899aabbccddeeff"
		err := c.ClaimDesignation(ctx, claimInput(gid, admin, member, ref, desigOf(admin), claim))
		if !errors.Is(err, ErrClaimRoleChanged) {
			t.Fatalf("%v, want ErrClaimRoleChanged (an Update with a condition must not create the item)", err)
		}
		if row, _ := c.GetMembership(ctx, gid, member); row != nil {
			t.Error("the claim recreated a member who had left")
		}
	})
	t.Run("successor deleted", func(t *testing.T) {
		gid, admin, member, ref := designationFixture(t, c)
		if _, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "USER#" + member}, "SK": &types.AttributeValueMemberS{Value: "PROFILE"},
			"DeletedAt": &types.AttributeValueMemberS{Value: "2026-01-01T00:00:00Z"},
		}}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = c.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(c.table), Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: "USER#" + member}, "SK": &types.AttributeValueMemberS{Value: "PROFILE"}}})
		})
		claim := "GRANT#" + member + "#2026-06-01#8899aabbccddeeff"
		err := c.ClaimDesignation(ctx, claimInput(gid, admin, member, ref, desigOf(admin), claim))
		if !errors.Is(err, ErrClaimSuccessorDeleted) {
			t.Fatalf("%v, want ErrClaimSuccessorDeleted", err)
		}
		assertNothingClaimed(t, c, gid, member, claim)
	})
	t.Run("claim key taken", func(t *testing.T) {
		gid, admin, member, ref := designationFixture(t, c)
		claim := "GRANT#" + member + "#2026-06-01#8899aabbccddeeff"
		if _, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "GROUP#" + gid}, "SK": &types.AttributeValueMemberS{Value: claim},
		}}); err != nil {
			t.Fatal(err)
		}
		err := c.ClaimDesignation(ctx, claimInput(gid, admin, member, ref, desigOf(admin), claim))
		if !errors.Is(err, ErrClaimKeyTaken) {
			t.Fatalf("%v, want ErrClaimKeyTaken", err)
		}
		if m, _ := c.GetMembership(ctx, gid, member); m.Role != models.RoleMember {
			t.Error("a refused claim promoted the successor")
		}
	})
	t.Run("a second concurrent claim finds the role already changed", func(t *testing.T) {
		gid, admin, member, ref := designationFixture(t, c)
		first := "GRANT#" + member + "#2026-06-01#8899aabbccddeeff"
		second := "GRANT#" + member + "#2026-06-01#0000000000000001"
		if err := c.ClaimDesignation(ctx, claimInput(gid, admin, member, ref, desigOf(admin), first)); err != nil {
			t.Fatal(err)
		}
		err := c.ClaimDesignation(ctx, claimInput(gid, admin, member, ref, desigOf(admin), second))
		if !errors.Is(err, ErrClaimRoleChanged) {
			t.Fatalf("%v, want ErrClaimRoleChanged", err)
		}
		if cited, _ := c.ListGrantsCiting(ctx, gid, desigOf(admin)); len(cited) != 1 {
			t.Errorf("%d rows cite the designation, want 1", len(cited))
		}
	})
}

func assertNothingClaimed(t *testing.T, c *Client, gid, member, claimKey string) {
	t.Helper()
	m, err := c.GetMembership(context.Background(), gid, member)
	if err != nil || m == nil || m.Role != models.RoleMember || m.GrantSortKey != "" {
		t.Fatalf("a refused claim changed the member: %+v, %v", m, err)
	}
	if to, _ := c.ListGrantsTo(context.Background(), gid, member); len(to) != 0 {
		t.Fatalf("a refused claim wrote a row: %+v", to)
	}
	_ = claimKey
}

func TestListAdminDesignationsAndAdminMembers(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	gid, admin, member, ref := designationFixture(t, c)
	mine := "DESIGNATION#" + admin + "#2026-03-01#0011223344556677"
	theirs := "DESIGNATION#" + member + "#2026-03-01#0011223344556677"
	for _, sk := range []string{mine, theirs} {
		if err := c.PutDesignation(ctx, PutDesignationInput{
			GroupID: gid, AdminUserID: admin, SortKey: sk, SuccessorUserID: member, PeriodDays: 30,
			AdminGrantRef: ref, AdminHasStoredGrant: true, Signature: []byte{1},
		}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := c.ListAdminDesignations(ctx, gid, admin)
	if err != nil || len(rows) != 1 || rows[0].SK != mine {
		t.Fatalf("ListAdminDesignations: %+v, %v", rows, err)
	}
	admins, err := c.ListAdminMembers(ctx, gid)
	if err != nil || len(admins) != 1 || admins[0].SK != "MEMBER#"+admin {
		t.Fatalf("ListAdminMembers: %+v, %v", admins, err)
	}
	setMemberRole(t, c, gid, member, models.RoleAdmin)
	if admins, _ := c.ListAdminMembers(ctx, gid); len(admins) != 2 {
		t.Errorf("ListAdminMembers = %d, want 2 after a promotion", len(admins))
	}
}
