# Crypto test vectors

`vectors.json` is the shared known-answer file issue #24 asks for: fixed
inputs and their expected outputs, checked in and consumed by both the Go
suite (`internal/crypto/vectors_test.go`, `-run Vector`) and, once #21/#22
land, the TypeScript suite. CI fails if either implementation diverges from
this file.

All byte values are lowercase hex strings. All numbers are decimal. This
file is not meant to be regenerated casually — every value here is either a
literal fixed input (chosen once, arbitrarily) or the result of running this
project's own primitives against a fixed input, and a real code change that
alters any output here is exactly the class of regression this suite exists
to catch. See `docs/DESIGN.md`, "Testing", for what each category pins and
why.

## Categories

- `kdf`: Argon2id `(password, salt, m, t, p) -> key`. The parameters are
  read from the vector file itself, not from a compiled-in constant, so this
  vector fails if the read path or the parameters change — see #20/#21.
- `aead`: AES-256-GCM `(key, nonce, plaintext, aad) -> ciphertext`, plus a
  negative case with a mismatched AAD that must fail to decrypt.
- `signing`: Ed25519 `(private key, context, message) -> signature`, one
  case per `SigningContext`, plus the two `SignedPayload` cases (post and
  comment) built from their constituent fields per `docs/DESIGN.md`.
- `wrapping`: X25519 ECIES `(recipient pub, ephemeral priv, plaintext, aad)
  -> wrapped`, plus the `GENKEY#` chain-link case built from `aead` directly
  (generation N encrypted under generation N+1 — see `docs/DESIGN.md:1131`)
  and its negative direction (generation N cannot decrypt it).
- `fingerprint`: `(Ed25519 pub, X25519 pub) -> fingerprint string`.

## Regenerating

`go run ./internal/crypto/testdata/gen > internal/crypto/testdata/vectors.json`
computes every non-arbitrary value fresh from this package's own code. This
is safe to do BEFORE any of these primitives have shipped data — it becomes
unsafe (a silent lockout) the moment a value here has protected anything
real. See the permanent-lockout warnings on `deriveWrappingKey` and
`SignedPayload` in the package itself.
