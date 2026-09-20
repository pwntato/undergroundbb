package crypto

import (
	"crypto/subtle"

	"golang.org/x/crypto/argon2"
)

// CheckRecoveryVerifier reports whether code -- as presented to a recovery
// endpoint -- hashes to verifier under salt and params. The server never
// computes a verifier for storage; that happens client-side, the same way
// Salt/Argon2Params/WrappedPrivateKeys already do for the login and
// recovery wraps (see docs/DESIGN.md's "server never sees a password... or
// any plaintext," which the recovery code is equivalent to -- see
// THREAT_MODEL.md, "It is equivalent to the password, not a lesser
// factor"). The server's only role is the check: recomputing the same
// Argon2id derivation the client used when it created the verifier, and
// comparing.
//
// This is the one place a plaintext recovery code reaches the server at
// all -- "presenting the code" is the gate docs/DESIGN.md describes, and
// the code is submitted here and only here, over TLS, for this one-way
// comparison. See docs/DESIGN.md, "an Argon2id hash of the recovery code
// under its own salt and parameters, derived separately from the wrapping
// key so that holding the verifier does not yield the wrapper."
//
// Constant-time in the comparison, matching Verify's own reasoning
// elsewhere in this package -- a presented recovery code is exactly the
// kind of secret a timing difference should not leak anything about.
func CheckRecoveryVerifier(code string, salt []byte, params Argon2IDParams, verifier []byte) bool {
	got := argon2.IDKey([]byte(code), salt, uint32(params.Iterations), uint32(params.MemoryKiB), uint8(params.Parallelism), uint32(len(verifier)))
	return len(got) == len(verifier) && subtle.ConstantTimeCompare(got, verifier) == 1
}

// Argon2IDParams mirrors models.Argon2Params -- crypto deliberately does
// not import models (the reverse dependency), so this package defines its
// own copy of the same three fields for CheckRecoveryVerifier's signature.
// See models.Argon2Params's own doc comment for why these travel with the
// item instead of being compiled into a client: the same reasoning applies
// to the verifier's params, which the server reads back rather than
// assumes for the identical reason -- a value baked in here could never
// change without breaking every verifier created under the old one.
type Argon2IDParams struct {
	MemoryKiB   int64
	Iterations  int64
	Parallelism int64
}
