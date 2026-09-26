package crypto

import (
	"bytes"
	"testing"
)

func TestTrustAnchorPayloadDeterministic(t *testing.T) {
	p1 := TrustAnchorPayload("creator-1", []byte("pubkey-1"), "group-1")
	p2 := TrustAnchorPayload("creator-1", []byte("pubkey-1"), "group-1")
	if !bytes.Equal(p1, p2) {
		t.Fatal("TrustAnchorPayload is not deterministic")
	}
}

func TestTrustAnchorPayloadDistinguishesEveryField(t *testing.T) {
	base := TrustAnchorPayload("creator-1", []byte("pubkey-1"), "group-1")

	cases := map[string][]byte{
		"creatorUUID":             TrustAnchorPayload("creator-2", []byte("pubkey-1"), "group-1"),
		"creatorSigningPublicKey": TrustAnchorPayload("creator-1", []byte("pubkey-2"), "group-1"),
		"groupID":                 TrustAnchorPayload("creator-1", []byte("pubkey-1"), "group-2"),
	}

	for name, other := range cases {
		if bytes.Equal(base, other) {
			t.Errorf("changing %s did not change the payload", name)
		}
	}
}

// TestTrustAnchorPayloadFieldBoundariesAreUnambiguous mirrors
// TestSignedPayloadFieldBoundariesAreUnambiguous: a naive concatenation
// without length prefixes would let two different field splits collide.
func TestTrustAnchorPayloadFieldBoundariesAreUnambiguous(t *testing.T) {
	p1 := TrustAnchorPayload("ab", []byte("c"), "group-1")
	p2 := TrustAnchorPayload("a", []byte("bc"), "group-1")
	if bytes.Equal(p1, p2) {
		t.Fatal("field boundary is ambiguous: (\"ab\",\"c\") and (\"a\",\"bc\") produced the same payload")
	}
}

// TestTrustAnchorPayloadSignsUnderContext verifies the payload is meant to
// be signed with ContextTrustAnchor specifically, and that a signature over
// it does not verify under a different context even with identical bytes --
// the same replay concern ContextRoleGrant and ContextPost/ContextComment
// each guard against.
func TestTrustAnchorPayloadSignsUnderContext(t *testing.T) {
	pub, priv, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	payload := TrustAnchorPayload("creator-1", pub, "group-1")

	sig, err := Sign(priv, ContextTrustAnchor, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, ContextTrustAnchor, payload, sig) {
		t.Fatal("signature over TrustAnchorPayload failed to verify")
	}

	grantSig, err := Sign(priv, ContextRoleGrant, payload)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(pub, ContextTrustAnchor, payload, grantSig) {
		t.Fatal("a role-grant signature verified as a trust-anchor signature over the same payload bytes")
	}
}

func TestRoleGrantPayloadDeterministic(t *testing.T) {
	p1 := RoleGrantPayload("group-1", "subject-1", "admin", "")
	p2 := RoleGrantPayload("group-1", "subject-1", "admin", "")
	if !bytes.Equal(p1, p2) {
		t.Fatal("RoleGrantPayload is not deterministic")
	}
}

func TestRoleGrantPayloadDistinguishesEveryField(t *testing.T) {
	base := RoleGrantPayload("group-1", "subject-1", "admin", "GRANT#subject-1#2026-09-06#aaaa")

	cases := map[string][]byte{
		"groupID":         RoleGrantPayload("group-2", "subject-1", "admin", "GRANT#subject-1#2026-09-06#aaaa"),
		"subjectUUID":     RoleGrantPayload("group-1", "subject-2", "admin", "GRANT#subject-1#2026-09-06#aaaa"),
		"role":            RoleGrantPayload("group-1", "subject-1", "member", "GRANT#subject-1#2026-09-06#aaaa"),
		"grantorGrantRef": RoleGrantPayload("group-1", "subject-1", "admin", "GRANT#subject-1#2026-09-06#bbbb"),
	}

	for name, other := range cases {
		if bytes.Equal(base, other) {
			t.Errorf("changing %s did not change the payload", name)
		}
	}
}

// TestRoleGrantPayloadRootGrantHasEmptyRef covers the root-grant shape #34
// produces: an empty grantorGrantRef, distinguishable from any non-root
// grant's payload precisely because "" is still one more length-prefixed
// field, not an omitted one -- see TestTrustAnchorPayloadFieldBoundariesAreUnambiguous
// for why an omitted field would be the dangerous version of this.
func TestRoleGrantPayloadRootGrantHasEmptyRef(t *testing.T) {
	root := RoleGrantPayload("group-1", "creator-1", "admin", "")
	nonRoot := RoleGrantPayload("group-1", "creator-1", "admin", "GRANT#creator-1#2026-09-06#aaaa")
	if bytes.Equal(root, nonRoot) {
		t.Fatal("a root grant (empty ref) must not collide with a non-root grant referencing a real predecessor")
	}
}

func TestMemberWrapAADDeterministic(t *testing.T) {
	a1 := MemberWrapAAD("group-1", "member-1", 0)
	a2 := MemberWrapAAD("group-1", "member-1", 0)
	if !bytes.Equal(a1, a2) {
		t.Fatal("MemberWrapAAD is not deterministic")
	}
}

func TestMemberWrapAADDistinguishesEveryField(t *testing.T) {
	base := MemberWrapAAD("group-1", "member-1", 3)

	cases := map[string][]byte{
		"groupID":    MemberWrapAAD("group-2", "member-1", 3),
		"memberUUID": MemberWrapAAD("group-1", "member-2", 3),
		"generation": MemberWrapAAD("group-1", "member-1", 4),
	}

	for name, other := range cases {
		if bytes.Equal(base, other) {
			t.Errorf("changing %s did not change the AAD", name)
		}
	}
}

// TestMemberWrapAADZeroPadsGeneration covers the six-digit zero-padding
// docs/DESIGN.md requires ("GENKEY#000008, not GENKEY#8"), applied here to
// the matching GEN# component of a member wrap's AAD.
func TestMemberWrapAADZeroPadsGeneration(t *testing.T) {
	got := string(MemberWrapAAD("group-1", "member-1", 8))
	want := "GROUP#group-1:MEMBER#member-1:GEN#000008"
	if got != want {
		t.Errorf("MemberWrapAAD(...,8) = %q, want %q", got, want)
	}
}

func TestGroupNameAADDeterministic(t *testing.T) {
	a1 := GroupNameAAD("group-1", GroupNameField, 0)
	a2 := GroupNameAAD("group-1", GroupNameField, 0)
	if !bytes.Equal(a1, a2) {
		t.Fatal("GroupNameAAD is not deterministic")
	}
}

func TestGroupNameAADDistinguishesEveryField(t *testing.T) {
	base := GroupNameAAD("group-1", GroupNameField, 3)

	cases := map[string][]byte{
		"groupID":    GroupNameAAD("group-2", GroupNameField, 3),
		"field":      GroupNameAAD("group-1", GroupDescriptionField, 3),
		"generation": GroupNameAAD("group-1", GroupNameField, 4),
	}

	for name, other := range cases {
		if bytes.Equal(base, other) {
			t.Errorf("changing %s did not change the AAD", name)
		}
	}
}

// TestGroupNameAADZeroPadsGeneration mirrors TestMemberWrapAADZeroPadsGeneration.
func TestGroupNameAADZeroPadsGeneration(t *testing.T) {
	got := string(GroupNameAAD("group-1", GroupNameField, 8))
	want := "GROUP#group-1:NAME:GEN#000008"
	if got != want {
		t.Errorf("GroupNameAAD(...,8) = %q, want %q", got, want)
	}
}

// TestRoleGrantPayloadSignsUnderContext verifies the payload is meant to be
// signed with ContextRoleGrant, with the same cross-context rejection
// TestTrustAnchorPayloadSignsUnderContext checks in the other direction.
func TestRoleGrantPayloadSignsUnderContext(t *testing.T) {
	pub, priv, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	payload := RoleGrantPayload("group-1", "creator-1", "admin", "")

	sig, err := Sign(priv, ContextRoleGrant, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, ContextRoleGrant, payload, sig) {
		t.Fatal("signature over RoleGrantPayload failed to verify")
	}

	anchorSig, err := Sign(priv, ContextTrustAnchor, payload)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(pub, ContextRoleGrant, payload, anchorSig) {
		t.Fatal("a trust-anchor signature verified as a role-grant signature over the same payload bytes")
	}
}
