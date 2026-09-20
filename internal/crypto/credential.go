package crypto

// CredentialCopy names which of the two independent wraps of a user's
// private keys a CredentialWrapAAD call is for -- see docs/DESIGN.md's AAD
// table, "Wrapped private keys | user uuid + which copy (PROFILE or
// RECOVERY)". The two copies are unwrapped under different keys (the
// password-derived key for PROFILE, the recovery-code-derived key for
// RECOVERY) but the same user's plaintext private keys, so the AAD is what
// stops one copy's ciphertext from being replayed into the other's slot with
// its tag still verifying -- the exact class of relocation attack the AAD
// column as a whole defends against.
type CredentialCopy string

const (
	CredentialCopyProfile  CredentialCopy = "PROFILE"
	CredentialCopyRecovery CredentialCopy = "RECOVERY"
)

// CredentialWrapAAD builds the AAD for wrapping or unwrapping userID's
// private keys under copy, per docs/DESIGN.md's "Wrapped private keys | user
// uuid + which copy" row. The encoding is "USER#<uuid>:<copy>" -- the same
// "<PK>:<rest>" shape every other AAD in this package already uses (see
// testdata/gen/main.go's "GROUP#g1:GENKEY#000004" and "GROUP#g1:POST#..."),
// with USER#<uuid> matching the table's own partition key for this item
// exactly, the way GROUP#<gid> does for group content.
//
// This is a client-only concern in the current design: the server stores
// WrappedPrivateKeys and RecoveryWrappedPrivateKeys as opaque ciphertext and
// never calls Decrypt on either (see package crypto's own doc comment,
// "server never sees... any plaintext"). This function exists anyway,
// alongside a byte-identical TypeScript counterpart
// (web/src/lib/crypto/credential.ts) and a shared test vector, precisely
// because DESIGN.md calls this AAD choice "unaddable retroactively": no code
// pinned the exact encoding before the frontend needed it (#30), and a
// client that guessed differently at register time than it later assumed at
// login/change-password time would produce a blob only it could never
// unwrap again, with no server-side check to catch the mismatch before it
// was too late.
func CredentialWrapAAD(userID string, copy CredentialCopy) []byte {
	return []byte("USER#" + userID + ":" + string(copy))
}
