// Group creation's signed payloads and member-wrap AAD, matching
// internal/crypto/group.go byte-for-byte (see testdata/vectors.json's
// "trust_anchor", "role_grant" and "member_wrap_aad" sections).

import { bytesToHex } from './hex.js'

/**
 * randSuffixBytes is the width of the random component generateGrantSortKey
 * appends -- matches internal/idgen/idgen.go's randSuffixBytes exactly
 * (8 bytes / 16 hex characters), since the two must produce the same shape
 * for a grant sort key the client generates and the server only validates.
 */
const RAND_SUFFIX_BYTES = 8

/**
 * Generates the "GRANT#<uuid>#<YYYY-MM-DD, UTC>#<rand>" sort key a new role
 * grant will be written under -- the client-side counterpart of
 * internal/idgen.go's DaySuffix, needed here because RoleGrantPayload now
 * signs the grant's own address (see that function's own doc comment for
 * why) and the client must therefore choose it before asking the server to
 * verify a signature over it, the same "client decides, server validates
 * the shape" split idgen.DaySuffix's own doc comment describes for every
 * other day-suffixed sort key in this schema.
 *
 * now is UTC, not local time, matching DaySuffix -- otherwise a client in a
 * timezone behind UTC could mint a grant dated "yesterday" from the
 * server's perspective, which the server's own skew check
 * (validateGrantDay) is what actually enforces isn't gamed for real.
 */
export function generateGrantSortKey(subjectUUID: string, now: Date = new Date()): string {
  const day = now.toISOString().slice(0, 10)
  const rand = bytesToHex(crypto.getRandomValues(new Uint8Array(RAND_SUFFIX_BYTES)))
  return `GRANT#${subjectUUID}#${day}#${rand}`
}

/**
 * Builds the canonical byte string a group's trust-anchor signature covers
 * -- see docs/DESIGN.md, "Roles and the chain of trust": "The anchor is
 * signed by the creator at group creation" over the creator's uuid, their
 * Ed25519 public key at that moment, and the group id. Signing the group id
 * as well as the creator's own identity is what stops a creator-signed
 * anchor from one group being replayed as the anchor of a different group
 * the same creator did not create.
 *
 * Sign this payload under ed25519.SigningContext.TrustAnchor; verify it the
 * same way. Same length-prefixed encoding as payload.ts's signedPayload,
 * for the same reason (an unambiguous concatenation without relying on a
 * separator byte the fields themselves might contain). This encoding must
 * never change once a real group's anchor has been signed under it.
 */
export function trustAnchorPayload(
  creatorUUID: string,
  creatorSigningPublicKey: Uint8Array,
  groupId: string,
): Uint8Array {
  const encoder = new TextEncoder()
  return lengthPrefixedConcat([
    encoder.encode(creatorUUID),
    creatorSigningPublicKey,
    encoder.encode(groupId),
  ])
}

/**
 * Builds the canonical byte string a role-grant signature covers -- see
 * docs/DESIGN.md, "Roles and the chain of trust." A grant binds the group
 * id, the subject uuid and the role granted, the grant's own address
 * (grantSortKey, the "GRANT#<uuid>#<YYYY-MM-DD>#<rand>" sort key this exact
 * grant will be written under), and the grantor's own current grant
 * reference (the sort key of the grant that authorized the grantor to act)
 * -- empty for the root grant a group's creation produces, since there is
 * no predecessor grant to point at.
 *
 * grantSortKey is signed, not just chosen by whoever writes the row,
 * because the chain walk relies on the day in a grant's own sort key to
 * pick which of the grantor's superseded signing keys verifies it. Without
 * the address itself in the signed bytes, a copied signature could be
 * replayed onto a new GRANT# row at a different day -- see
 * internal/crypto/group.go's RoleGrantPayload for the full reasoning this
 * must match byte-for-byte.
 *
 * Sign this payload under ed25519.SigningContext.RoleGrant; verify it the
 * same way. Same length-prefixed encoding as trustAnchorPayload, and the
 * same warning: this must never change once a real grant has been signed
 * under it.
 */
export function roleGrantPayload(
  groupId: string,
  subjectUUID: string,
  role: string,
  grantSortKey: string,
  grantorGrantRef: string,
): Uint8Array {
  const encoder = new TextEncoder()
  return lengthPrefixedConcat([
    encoder.encode(groupId),
    encoder.encode(subjectUUID),
    encoder.encode(role),
    encoder.encode(grantSortKey),
    encoder.encode(grantorGrantRef),
  ])
}

function lengthPrefixedConcat(fields: readonly Uint8Array[]): Uint8Array {
  let size = 0
  for (const f of fields) size += 4 + f.length
  const out = new Uint8Array(size)
  let offset = 0
  for (const f of fields) {
    const view = new DataView(out.buffer, out.byteOffset + offset, 4)
    view.setUint32(0, f.length, false)
    out.set(f, offset + 4)
    offset += 4 + f.length
  }
  return out
}

/**
 * Builds the AAD for wrapping or unwrapping a single member's copy of a
 * group's generation key -- see docs/DESIGN.md's AAD table, "Member's
 * wrapped group key | group id + member uuid + generation number." Unlike a
 * GENKEY# chain link (member-independent), a member's own entry point is
 * wrapped specifically to them, so the AAD binds which member it belongs to
 * as well as which group and generation -- without that, an attacker with
 * write access could swap two members' wrapped entries at the same
 * generation and both AEAD tags would still verify.
 *
 * The encoding is `GROUP#<gid>:MEMBER#<uid>:GEN#<nnnnnn>`, generation
 * zero-padded to six digits matching GENKEY#'s own sort-key convention (see
 * docs/DESIGN.md: "The generation number is zero-padded to six digits").
 * Matches internal/crypto/group.go's MemberWrapAAD byte-for-byte. This must
 * never change once a real member wrap exists under it.
 */
export function memberWrapAAD(groupId: string, memberUUID: string, generation: number): Uint8Array {
  const gen = generation.toString().padStart(6, '0')
  return new TextEncoder().encode(`GROUP#${groupId}:MEMBER#${memberUUID}:GEN#${gen}`)
}

/** Which of a group's two encrypted text fields groupNameAAD is being built for. */
export type GroupTextField = 'NAME' | 'DESC'

/**
 * Builds the AAD for encrypting or decrypting a private group's name or
 * description -- see docs/DESIGN.md's AAD table, "Group name/description |
 * group id + which field + generation number." field distinguishes the two
 * ciphertexts sharing the same group id and generation, since without it an
 * attacker with write access could swap a group's name and description with
 * both tags still verifying.
 *
 * The encoding is `GROUP#<gid>:<field>:GEN#<nnnnnn>`, matching
 * internal/crypto/group.go's GroupNameAAD byte-for-byte. This must never
 * change once a real group's name/description exists under it.
 */
export function groupNameAAD(
  groupId: string,
  field: GroupTextField,
  generation: number,
): Uint8Array {
  const gen = generation.toString().padStart(6, '0')
  return new TextEncoder().encode(`GROUP#${groupId}:${field}:GEN#${gen}`)
}
