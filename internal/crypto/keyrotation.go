package crypto

import (
	"encoding/hex"
	"fmt"
	"strconv"
)

// KeyRotationPayload builds the canonical byte string both signatures of a
// key rotation cover -- see docs/DESIGN.md, "What a rotation writes." The old
// Ed25519 key signs it to prove the caller holds the keys being replaced; the
// new Ed25519 key signs it to prove the caller holds the new private key, so
// nobody can register a public key they cannot use or one lifted from another
// user. Both sign under ContextKeyRotation.
//
// Fields, in order: user uuid, current signing public key, current wrapping
// public key, new signing public key, new wrapping public key, UTC day
// ("2006-01-02"), the current KeyEpoch (decimal), and rosterDigest, the
// RosterDigest of the caller's PIN# and VERIFIED# rows at rotation time. The
// epoch is the value the server holds, which makes a request single-use.
//
// Same length-prefixed encoding as the other payloads in this package, and the
// same warning: this must never change once a real rotation has been signed
// under it.
func KeyRotationPayload(userUUID string, oldSigning, oldWrapping, newSigning, newWrapping []byte, utcDay string, keyEpoch uint64, rosterDigest []byte) []byte {
	return lengthPrefixedConcat([][]byte{
		[]byte(userUUID),
		oldSigning,
		oldWrapping,
		newSigning,
		newWrapping,
		[]byte(utcDay),
		[]byte(strconv.FormatUint(keyEpoch, 10)),
		rosterDigest,
	})
}

// HandoffWrapAAD builds the AAD for a rotation handoff row's wrap of a group
// key to the user's NEW X25519 key -- see docs/DESIGN.md's AAD table,
// "Rotation handoff wrap." It binds the user, the group, the generation and
// the public key the key is wrapped to, so an operator cannot swap two
// HANDOFF# rows (group A's key would land in group B's chain) and a row
// written for one rotation does not open under another.
//
// Same "<PK>:<rest>" string shape as MemberWrapAAD, generation zero-padded to
// six digits; the public key is hex so the AAD stays a printable string.
// Must never change once a real handoff row exists under it.
func HandoffWrapAAD(userUUID, groupID string, generation uint64, newWrappingPublicKey []byte) []byte {
	return fmt.Appendf(nil, "USER#%s:HANDOFF#%s:GEN#%06d:KEY#%s", userUUID, groupID, generation, hex.EncodeToString(newWrappingPublicKey))
}
