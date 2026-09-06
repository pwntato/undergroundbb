// Package crypto holds the server's half of the cryptographic protocol.
//
// UndergroundBB is end-to-end encrypted: the browser holds the private keys and
// does all encryption and decryption. The server never sees a password, a
// password-derived key, a group key, or any plaintext. What remains server-side
// is verification only — checking Ed25519 signatures over authentication
// challenges, invites, acceptances and posts against stored public keys.
//
// The primitives here (AES-256-GCM, Ed25519, X25519 key wrapping) are tested
// against fixed vectors shared with the TypeScript implementation (#24).
// Round-trip tests are not enough: they pass even when both sides are wrong
// in the same way, and a silent change to key derivation would lock every
// existing user out permanently.
package crypto
