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
- `credential_wrap`: `(user id, copy) -> AAD`, plus the AES-256-GCM
  ciphertext that AAD produces under a fixed key/nonce/plaintext — pinning
  `CredentialWrapAAD`'s exact encoding (`docs/DESIGN.md`'s "Wrapped private
  keys" AAD row) so the client's own PROFILE and RECOVERY wraps never drift
  from each other or from a future server-side reader. Two cases, same user
  id and key material, one per copy — proving the two encode to genuinely
  different AAD rather than colliding.
- `key_bundle`: `(Ed25519 seed, X25519 private key) -> encoded bytes`,
  pinning `EncodeKeyBundle`'s plaintext layout for the blob that gets wrapped
  under `WrappedPrivateKeys`/`RecoveryWrappedPrivateKeys` — a 1-byte version
  tag followed by each field length-prefixed, big-endian. This is the
  plaintext *inside* the AEAD, never seen by the server either way, but it
  is exactly as unaddable-retroactively as the AAD above: an encoding change
  after a real wrap exists would make every existing user's blob decode to
  the wrong bytes with nothing able to detect it before the client tried to
  use them as keys.
- `trust_anchor`: `(creator uuid, creator signing public key, group id) ->
  payload`, plus the Ed25519 signature over it — pinning `TrustAnchorPayload`
  (#34), the group-creation counterpart of `signed_payload` above. A group's
  root of trust is verified by every future member's client, so this
  encoding must be byte-identical across Go and TypeScript before any real
  group exists under it.
- `role_grant`: `(group id, subject uuid, role, grantor grant ref) ->
  payload`, plus the Ed25519 signature over it — pinning `RoleGrantPayload`
  (#34). Two cases: a root grant (empty grantor grant ref, no predecessor to
  reference) and a non-root grant referencing a real one, proving the two
  shapes produce genuinely different payloads.
- `member_wrap_aad`: `(group id, member uuid, generation) -> AAD`, plus the
  AES-256-GCM ciphertext that AAD produces under a fixed key/nonce/plaintext
  — pinning `MemberWrapAAD` (#34), the AAD for a single member's own wrapped
  copy of a group's generation key (`docs/DESIGN.md`'s AAD table, "Member's
  wrapped group key"). Unlike a `GENKEY#` chain link, this wrap is
  member-specific, so the AAD binds the member uuid as well as the group id
  and generation number.
- `group_name_aad`: `(group id, field, generation) -> AAD`, plus the
  AES-256-GCM ciphertext that AAD produces under a fixed key/nonce/plaintext
  — pinning `GroupNameAAD` (#34), the AAD for a private group's encrypted
  name and description (`docs/DESIGN.md`'s AAD table, "Group
  name/description"). Two cases, same group id and key material, one per
  field — proving the two encode to genuinely different AAD rather than
  colliding, the same shape `credential_wrap` proves for `PROFILE` vs.
  `RECOVERY`.

## Regenerating

`go run ./internal/crypto/testdata/gen > internal/crypto/testdata/vectors.json`
computes every non-arbitrary value fresh from this package's own code. This
is safe to do BEFORE any of these primitives have shipped data — it becomes
unsafe (a silent lockout) the moment a value here has protected anything
real. See the permanent-lockout warnings on `deriveWrappingKey` and
`SignedPayload` in the package itself.
