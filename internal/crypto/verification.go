package crypto

// VerificationPayload builds the canonical byte string a VERIFIED# signature
// covers -- see docs/DESIGN.md, "Key pinning and verification." A verification
// is the verifying user's signed record that they compared another user's
// fingerprint out of band and it matched.
//
// It signs the fingerprint itself (the 60-digit string Fingerprint returns),
// not the keys: the fingerprint is exactly what the person compared, and it
// covers both current public keys, so a record stops matching the moment either
// key changes and a client simply no longer treats the user as verified.
// Both uuids are signed so a record cannot be copied to another user's row or
// into someone else's partition, and verifierSigningPublicKey is the key it is
// signed under, which a client checks against its own current key and treats
// anything else as tampering, as with pins.
//
// Sign this payload under ContextVerification; verify it the same way. Same
// length-prefixed encoding as the other payloads in this package, and the same
// warning: this must never change once a real verification has been signed
// under it.
func VerificationPayload(verifierUUID, verifiedUUID string, verifierSigningPublicKey []byte, fingerprint string) []byte {
	return lengthPrefixedConcat([][]byte{
		[]byte(verifierUUID),
		[]byte(verifiedUUID),
		verifierSigningPublicKey,
		[]byte(fingerprint),
	})
}
