// AAD for wrapping/unwrapping a user's private keys, matching
// internal/crypto/credential.go byte-for-byte (see
// testdata/vectors.json's "credential_wrap" section).

/**
 * Which of the two independent wraps of a user's private keys a
 * credentialWrapAAD call is for — see docs/DESIGN.md's AAD table, "Wrapped
 * private keys | user uuid + which copy (PROFILE or RECOVERY)". The two
 * copies are unwrapped under different keys (the password-derived key for
 * PROFILE, the recovery-code-derived key for RECOVERY) but the same user's
 * plaintext private keys, so the AAD is what stops one copy's ciphertext
 * from being replayed into the other's slot with its tag still verifying —
 * the exact class of relocation attack the AAD column as a whole defends
 * against.
 */
export type CredentialCopy = 'PROFILE' | 'RECOVERY'

/**
 * Builds the AAD for wrapping or unwrapping userID's private keys under
 * copy, per docs/DESIGN.md's "Wrapped private keys | user uuid + which
 * copy" row. The encoding is `USER#<uuid>:<copy>` — the same `<PK>:<rest>`
 * shape every other AAD in this codebase already uses (see
 * internal/crypto/testdata/gen/main.go's `"GROUP#g1:GENKEY#000004"` and
 * `"GROUP#g1:POST#..."`), with `USER#<uuid>` matching the table's own
 * partition key for this item exactly, the way `GROUP#<gid>` does for group
 * content.
 *
 * This is a client-only concern in the current design: the server stores
 * WrappedPrivateKeys and RecoveryWrappedPrivateKeys as opaque ciphertext and
 * never decrypts either. This function exists anyway, alongside a
 * byte-identical Go counterpart (internal/crypto/credential.go) and a
 * shared test vector, precisely because DESIGN.md calls this AAD choice
 * "unaddable retroactively": no code pinned the exact encoding before the
 * frontend needed it (#30), and a client that guessed differently at
 * register time than it later assumed at login/change-password time would
 * produce a blob only it could never unwrap again, with no server-side
 * check to catch the mismatch before it was too late.
 */
export function credentialWrapAAD(userID: string, copy: CredentialCopy): Uint8Array {
  return new TextEncoder().encode(`USER#${userID}:${copy}`)
}
