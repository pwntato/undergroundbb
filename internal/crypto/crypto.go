// Package crypto holds the server's half of the cryptographic protocol.
//
// UndergroundBB is end-to-end encrypted: the browser holds the private keys and
// does all encryption and decryption. The server never sees a password, a
// password-derived key, a group key, or any plaintext. What remains server-side
// is verification only — checking Ed25519 signatures over authentication
// challenges, invites, acceptances and posts against stored public keys.
//
// The primitives here (AES-256-GCM, Ed25519, X25519 key wrapping, plus the
// SignedPayload and Fingerprint encodings) are checked against fixed vectors
// in testdata/vectors.json (vectors_test.go, #20). The TypeScript
// implementation at web/src/lib/crypto (#21, #22) reads this same file
// (web/src/lib/crypto/vectors.test.ts) rather than a copy, so both sides are
// verified against the same expected outputs — closing #24. Round-trip
// tests alone are not enough: they pass even when both sides are wrong in
// the same way, and a silent change to key derivation would lock every
// existing user out permanently.
package crypto
