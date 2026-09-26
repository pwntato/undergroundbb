package crypto

import "fmt"

// TrustAnchorPayload builds the canonical byte string a group's trust-anchor
// signature covers -- see docs/DESIGN.md, "Roles and the chain of trust":
// "The anchor is signed by the creator at group creation" over the creator's
// uuid, their Ed25519 public key at that moment, and the group id. Signing
// the group id as well as the creator's own identity is what stops a
// creator-signed anchor from one group being replayed as the anchor of a
// different group the same creator did not create -- the same relocation
// concern SignedPayload's own doc comment describes for posts and comments,
// applied here to a group's root of trust instead.
//
// Sign this payload under ContextTrustAnchor; verify it the same way. Same
// length-prefixed encoding as SignedPayload, for the same reason (an
// unambiguous concatenation without relying on a separator byte the fields
// themselves might contain) -- and the same permanent-lockout warning
// applies: this encoding must never change once a real group's anchor has
// been signed under it, since every existing chain-walk verification would
// break.
func TrustAnchorPayload(creatorUUID string, creatorSigningPublicKey []byte, groupID string) []byte {
	fields := [][]byte{
		[]byte(creatorUUID),
		creatorSigningPublicKey,
		[]byte(groupID),
	}
	return lengthPrefixedConcat(fields)
}

// RoleGrantPayload builds the canonical byte string a role-grant signature
// covers -- see docs/DESIGN.md, "Roles and the chain of trust." A grant
// binds the group id (so a grant signed for one group cannot be replayed
// into another), the subject uuid and the role granted, and the grantor's
// own current grant reference -- the sort key of the grant that authorized
// the grantor to act, so a chain walk can confirm the grantor held Admin at
// the moment they signed this one. For the root grant a group's creation
// writes (#34), the subject IS the grantor and grantorGrantRef is empty:
// there is no predecessor grant to point at, which is exactly what makes it
// the root -- see Group.TrustAnchorSignature's own doc comment for how a
// verifier is meant to terminate there instead of expecting a predecessor.
//
// Sign this payload under ContextRoleGrant; verify it the same way. Same
// length-prefixed encoding as SignedPayload and TrustAnchorPayload, and the
// same warning: this must never change once a real grant has been signed
// under it.
func RoleGrantPayload(groupID, subjectUUID, role, grantorGrantRef string) []byte {
	fields := [][]byte{
		[]byte(groupID),
		[]byte(subjectUUID),
		[]byte(role),
		[]byte(grantorGrantRef),
	}
	return lengthPrefixedConcat(fields)
}

// MemberWrapAAD builds the AAD for wrapping or unwrapping a single member's
// copy of a group's generation key -- see docs/DESIGN.md's AAD table,
// "Member's wrapped group key | group id + member uuid + generation
// number." Unlike a GENKEY# chain link (member-independent: one wrapped
// value per generation, shared machinery for every member who ever reads
// it), a member's own entry point on their MEMBER# item is wrapped
// specifically to THEM, so the AAD must bind which member it belongs to as
// well as which group and generation -- without the member uuid, an
// attacker with write access could swap two members' wrapped entries at
// the same generation and both AEAD tags would still verify.
//
// The encoding is "GROUP#<gid>:MEMBER#<uid>:GEN#<nnnnnn>" -- the same
// "<PK>:<rest>" shape CredentialWrapAAD uses, with the generation number
// zero-padded to six digits to match GENKEY#'s own sort-key convention
// (docs/DESIGN.md: "The generation number is zero-padded to six digits").
// This is a string AAD, not a length-prefixed byte encoding like
// TrustAnchorPayload/RoleGrantPayload -- CredentialWrapAAD's own doc
// comment already establishes "<PK>:<rest>" as this package's AAD
// convention specifically (as opposed to SignedPayload's own length-prefix
// convention for multi-field SIGNED payloads), and gid/uid/generation
// cannot collide across the `:`/`#` delimiters here for the same reason
// CredentialWrapAAD's fields cannot: gid and uid are both idgen.UUID-shaped
// (never containing `:` or `#`), and the generation number is a fixed
// 6-digit field.
//
// This must never change once a real member wrap exists under it -- the
// same permanent-lockout warning every AAD and signed-payload encoding in
// this package carries.
func MemberWrapAAD(groupID, memberUUID string, generation uint64) []byte {
	return fmt.Appendf(nil, "GROUP#%s:MEMBER#%s:GEN#%06d", groupID, memberUUID, generation)
}

// GroupNameAAD builds the AAD for encrypting or decrypting a private
// group's name or description -- see docs/DESIGN.md's AAD table, "Group
// name/description | group id + generation number." field distinguishes
// the name from the description (two different ciphertexts under the same
// group id and generation, which would otherwise share an AAD and let an
// attacker with write access swap one for the other with both tags still
// verifying).
//
// The encoding is "GROUP#<gid>:<field>:GEN#<nnnnnn>" -- same convention as
// MemberWrapAAD. field is a fixed literal ("NAME" or "DESC", see
// GroupNameField/GroupDescriptionField) rather than caller-supplied, so it
// cannot collide with the generation suffix or introduce an unintended
// delimiter.
//
// This must never change once a real group's name/description exists under
// it.
func GroupNameAAD(groupID string, field GroupTextField, generation uint64) []byte {
	return fmt.Appendf(nil, "GROUP#%s:%s:GEN#%06d", groupID, field, generation)
}

// GroupTextField names which of a group's two encrypted text fields
// GroupNameAAD is being built for.
type GroupTextField string

const (
	GroupNameField        GroupTextField = "NAME"
	GroupDescriptionField GroupTextField = "DESC"
)

// lengthPrefixedConcat concatenates fields using the same 4-byte
// big-endian length-prefix encoding SignedPayload documents and uses
// inline -- factored out here so TrustAnchorPayload and RoleGrantPayload
// share it exactly rather than each re-deriving the same byte layout.
func lengthPrefixedConcat(fields [][]byte) []byte {
	var size int
	for _, f := range fields {
		size += 4 + len(f)
	}
	out := make([]byte, 0, size)
	for _, f := range fields {
		out = appendLengthPrefixed(out, f)
	}
	return out
}
