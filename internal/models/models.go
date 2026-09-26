// Package models defines the record types stored in the single DynamoDB table.
//
// The table is single-table design: every record carries PK/SK plus a Type
// discriminator, with GSI1 supporting the secondary access patterns. Concrete
// types land alongside the features that need them (M3 onward); this package
// currently defines only the shape every record shares.
package models

// Record is the field set common to every item in the table. Concrete record
// types embed it.
type Record struct {
	PK   string `dynamodbav:"PK"`
	SK   string `dynamodbav:"SK"`
	Type string `dynamodbav:"Type"`

	// GSI1PK and GSI1SK are set only on records participating in GSI1.
	GSI1PK string `dynamodbav:"GSI1PK,omitempty"`
	GSI1SK string `dynamodbav:"GSI1SK,omitempty"`

	// CreatedAt is an RFC 3339 timestamp.
	CreatedAt string `dynamodbav:"CreatedAt,omitempty"`
}

// User is the USER#<uuid> / PROFILE item — see docs/DESIGN.md, "The user item
// is mixed, not wholly encrypted."
//
// It is a mixed item, not wholly encrypted: Username and the public keys are
// plaintext the system reads directly (login lookup, signature verification,
// the GET /api/users/:id projection). The Argon2id salt and parameters travel
// with the item rather than a client constant, per DESIGN.md's "storing them
// is the part that cannot be added later" — a client deriving from its own
// compiled-in numbers could never have them changed without locking out every
// existing user. WrappedPrivateKeys and PreferencesBlob are opaque ciphertext
// the server never decrypts.
type User struct {
	Record

	// Username is stored as typed and displayed as typed. Uniqueness is
	// case-insensitive and enforced by the USERNAME#<lower> claim item, not
	// by this field.
	Username string `dynamodbav:"Username"`

	// SigningPublicKey is the user's current Ed25519 public key, raw bytes.
	SigningPublicKey []byte `dynamodbav:"SigningPublicKey"`
	// WrappingPublicKey is the user's current X25519 public key, raw bytes.
	WrappingPublicKey []byte `dynamodbav:"WrappingPublicKey"`

	// SupersededSigningKeys holds prior Ed25519 public keys with the interval
	// each was current for, so a signature written before a rotation can
	// still be verified. Empty until #62 (key rotation) exists.
	SupersededSigningKeys []SupersededKey `dynamodbav:"SupersededSigningKeys,omitempty"`

	// Salt is the Argon2id salt used to derive the password key that wraps
	// PrivateKeys. Client-generated, opaque to the server.
	Salt []byte `dynamodbav:"Salt"`
	// Argon2Params are the Argon2id parameters Salt was used with -- read by
	// the client on login rather than assumed, so a future increase in cost
	// only applies going forward. See docs/DESIGN.md, "The Argon2id
	// parameters are m=64 MiB, t=3, p=1."
	Argon2Params Argon2Params `dynamodbav:"Argon2Params"`
	// WrappedPrivateKeys is the AES-256-GCM-wrapped Ed25519 + X25519 private
	// keys, opaque ciphertext the server stores and serves but never opens.
	WrappedPrivateKeys WrappedBlob `dynamodbav:"WrappedPrivateKeys"`

	// PreferencesBlob is the encrypted theme/font preferences, sealed under a
	// key derived from the user's X25519 private key rather than the
	// password -- see docs/DESIGN.md, so preferences survive a password
	// change or recovery. Absent at signup; a fresh account has no
	// preferences to encrypt yet.
	PreferencesBlob *WrappedBlob `dynamodbav:"PreferencesBlob,omitempty"`

	// CredentialVersion is bumped by every credential re-wrap (password
	// change or recovery reset) and gates that rewrite's transaction
	// condition -- see docs/DESIGN.md, "the fourth [contested write] is the
	// credential re-wrap." Registration sets it to 1.
	CredentialVersion int64 `dynamodbav:"CredentialVersion"`

	// FailedVerifyCount counts failed Ed25519 signature verifications at
	// login step 4 -- NOT wrong passwords, which fail inside the browser at
	// step 3 and never reach the server. See docs/DESIGN.md, "This means the
	// server cannot count wrong passwords." Incremented on a failed step 4,
	// cleared on a successful one. A failed conditional delete on the
	// CHALLENGE item (replay or a flooded/overwritten nonce) is explicitly
	// NOT a signature failure and must not touch this field -- see issue
	// #27's round-24 review comment.
	FailedVerifyCount int64 `dynamodbav:"FailedVerifyCount,omitempty"`
	// LockUntil is an RFC 3339 timestamp compared on read, not a TTL --
	// PROFILE never expires and must outlive the lock. Empty/absent means
	// not locked. Set after the 5th failure within the counting window: see
	// docs/DESIGN.md, "five-attempts-in-five-minutes."
	LockUntil string `dynamodbav:"LockUntil,omitempty"`
}

// SupersededKey is a prior Ed25519 public key and the interval it was
// current for, retained so a signature written before a rotation can still
// be verified against the key that was live when it was made.
type SupersededKey struct {
	PublicKey []byte `dynamodbav:"PublicKey"`
	// From and Until are RFC 3339 timestamps. Until is empty for the key that
	// was current when superseded (i.e. up to the moment of rotation).
	From  string `dynamodbav:"From"`
	Until string `dynamodbav:"Until"`
}

// Argon2Params are the Argon2id tuning parameters a wrapped blob was derived
// under. See docs/DESIGN.md, "The Argon2id parameters are m=64 MiB, t=3,
// p=1, and they are stored on the item rather than compiled into the
// client."
type Argon2Params struct {
	MemoryKiB   int64 `dynamodbav:"MemoryKiB"`
	Iterations  int64 `dynamodbav:"Iterations"`
	Parallelism int64 `dynamodbav:"Parallelism"`
}

// WrappedBlob is an opaque AES-256-GCM-wrapped payload: a nonce and the
// ciphertext (tag appended, per crypto.Encrypt's convention). The server
// stores and serves it but has no way to open it -- it holds no key that
// could. Used where the wrapping key is derived directly (Argon2id from a
// password or recovery code) rather than via X25519 ECDH -- see
// WrappedKey's own doc comment for why an ECIES wrap needs a third field
// this type does not have.
type WrappedBlob struct {
	Nonce      []byte `dynamodbav:"Nonce"`
	Ciphertext []byte `dynamodbav:"Ciphertext"`
}

// WrappedKey is an opaque X25519-ECIES-wrapped payload -- crypto.Wrap's
// output (crypto.Wrapped), stored exactly as produced: an ephemeral X25519
// public key alongside the AES-256-GCM nonce and ciphertext. Distinct from
// WrappedBlob because unwrapping an ECIES wrap needs the ephemeral public
// key from THIS SPECIFIC wrap to redo the ECDH -- crypto.Unwrap's own doc
// comment is explicit that "the returned Wrapped value carries the
// ephemeral public key alongside the nonce and ciphertext -- it is
// everything Unwrap needs." WrappedBlob's two fields are correct for
// WrappedPrivateKeys and RecoveryWrappedPrivateKeys, where the wrapping key
// comes directly from Argon2id and no ECDH (and therefore no ephemeral
// keypair) is ever involved -- conflating the two here would silently drop
// the one field an ECIES unwrap cannot function without. Used for
// Group.GenerationKeyWrapped, Membership.WrappedGroupKey, and every future
// GENKEY# chain link.
type WrappedKey struct {
	EphemeralPub []byte `dynamodbav:"EphemeralPub"`
	Nonce        []byte `dynamodbav:"Nonce"`
	Ciphertext   []byte `dynamodbav:"Ciphertext"`
}

// Recovery is the USER#<uuid> / RECOVERY item -- a second copy of the
// private keys, wrapped under a key derived from a recovery code the client
// generates, independent of the password. See docs/DESIGN.md, "The
// recovery copy is a separate item, not an attribute of the profile."
//
// Salt and Argon2Params are this item's own, unrelated to User's -- the
// recovery derivation has no dependence on the password, which is the whole
// point of the item.
type Recovery struct {
	Record

	Salt               []byte       `dynamodbav:"Salt"`
	Argon2Params       Argon2Params `dynamodbav:"Argon2Params"`
	WrappedPrivateKeys WrappedBlob  `dynamodbav:"WrappedPrivateKeys"`

	// VerifierSalt, VerifierArgon2Params and Verifier gate this item's own
	// release: an Argon2id hash of the recovery code, computed client-side
	// under its own salt and parameters -- separate from Salt/Argon2Params
	// above, which wrap the private keys, so that holding the verifier does
	// not yield the wrapping key. See docs/DESIGN.md, "The server holds a
	// verifier... derived separately from the wrapping key so that holding
	// the verifier does not yield the wrapper," and issue #31's round-28
	// review comment.
	//
	// The server never computes a verifier, only checks one
	// (crypto.CheckRecoveryVerifier) against a plaintext code presented at
	// recovery time -- consistent with every other credential field on this
	// item, and with docs/DESIGN.md's "server never sees a password... or
	// any plaintext," which the recovery code is equivalent to (see
	// THREAT_MODEL.md, "the recovery code," "equivalent to the password").
	// Set at registration and replaced, alongside a freshly issued code, by
	// every credential re-wrap.
	VerifierSalt         []byte       `dynamodbav:"VerifierSalt"`
	VerifierArgon2Params Argon2Params `dynamodbav:"VerifierArgon2Params"`
	Verifier             []byte       `dynamodbav:"Verifier"`

	// CredentialVersion mirrors User.CredentialVersion -- both items rewrite
	// together on every credential change, under the same transaction
	// condition. Registration sets it to 1.
	CredentialVersion int64 `dynamodbav:"CredentialVersion"`

	// LastRewrapToken is the client-generated IdempotencyToken the most
	// recent db.RewrapCredentials call carried, or empty if that call didn't
	// set one or none has landed since registration. Opaque to this package
	// beyond that.
	//
	// Exists so recoveryCodeReset (internal/handlers/recovery.go) can
	// recognize its own lost-response retry: resolveRecovery re-checks the
	// presented code against THIS item's own Verifier on every call, so once
	// a reset has landed, a retry presenting the same (now stale) code fails
	// resolveRecovery's check before ever reaching RewrapCredentials -- there
	// is no separate "stale version, but let me check if it's my own write"
	// step to catch it the way issue #124's fix catches Register's retry.
	// The token is the fallback: when resolveRecovery's code check fails,
	// recoveryCodeReset additionally checks whether this field matches a
	// token the retry presents, at the CredentialVersion the client's
	// original request itself would have produced -- see db.IsOwnRewrap's
	// own doc comment for the full check. Issue #130.
	LastRewrapToken []byte `dynamodbav:"LastRewrapToken,omitempty"`

	// FailedVerifyCount and LockUntil are this item's own lockout pair,
	// deliberately separate from User's fields of the same name -- see
	// resolveRecovery's doc comment (internal/handlers/recovery.go) for why
	// a wrong recovery code must never touch the login lockout: reusing that
	// counter would let a recovery-guessing attacker lock a user out of
	// logging in, and would corrupt a counter DESIGN.md scopes to step-4
	// signature failures specifically. Same shape and semantics as User's
	// pair (rolling window via LockUntil-as-window-marker, RFC 3339 compared
	// on read, not a TTL) but counts failed verifier checks in
	// resolveRecovery instead. Issue #136.
	FailedVerifyCount int64  `dynamodbav:"FailedVerifyCount,omitempty"`
	LockUntil         string `dynamodbav:"LockUntil,omitempty"`
}

// Challenge is the USER#<uuid> / CHALLENGE item -- a single slot per user,
// overwritten on every POST /api/auth/challenge rather than keyed by nonce.
// See docs/DESIGN.md, "The challenge is a single slot per user," and issue
// #27's round-22 comment: keying by nonce would let an unauthenticated
// caller inflate a chosen user's partition without bound, since only a TTL
// (eventual, not immediate) would ever remove the items.
//
// Holds nothing but the nonce -- see docs/DESIGN.md, "The challenge item
// holds a random number and nothing else: no key material, nothing derived
// from the password." TTL is the table's actual DynamoDB TTL attribute
// (terraform/dynamodb.tf: attribute_name = "TTL") -- a short-lived item is
// exactly what TTL is for here, unlike User.LockUntil, which must outlive
// its own item and so is a plain compared-on-read timestamp instead.
type Challenge struct {
	Record

	Nonce []byte `dynamodbav:"Nonce"`
	TTL   int64  `dynamodbav:"TTL"`
}

// UsernameClaim is the USERNAME#<lower> / CLAIM item that makes a username
// unique case-insensitively and resolves a login's username to a uuid. See
// docs/DESIGN.md, "The claim is only a claim because the write is
// conditional on attribute_not_exists(PK)."
type UsernameClaim struct {
	Record

	// UserID is the uuid this username resolves to -- what makes the claim a
	// lookup and not merely a lock.
	UserID string `dynamodbav:"UserID"`
}

// Revocation mode values. See Group.RevocationMode and docs/DESIGN.md,
// "Revocation mode."
const (
	RevocationRotating = "rotating"
	RevocationOpen     = "open"
)

// Group visibility values. See Group.Visibility and docs/DESIGN.md,
// "Visibility -- private and public groups."
const (
	VisibilityPrivate = "private"
	VisibilityPublic  = "public"
)

// Group is the GROUP#<gid> / META item -- see docs/DESIGN.md, "Data model"
// and "Roles and the chain of trust." TTL never: a group's own record does
// not expire, only the posts inside it do, per group policy.
//
// Name and Description are plaintext for a public group and opaque
// ciphertext (AES-256-GCM under the group key) for a private one -- this
// package stores whichever the client sent and does not interpret either,
// since only a member holding the group key can tell the difference. The
// wire and db layers are what choose which of NamePlaintext/NameCiphertext
// is populated, matching Visibility.
type Group struct {
	Record

	// CreatorUserID and CreatorSigningPublicKey anchor the chain of trust:
	// a grant-chain walk terminates by checking that the root GRANT# is
	// self-signed by this key, belonging to this uuid. Both are stored
	// rather than inferred from "no predecessor" -- see DESIGN.md's own
	// reasoning for why an inferred root is forgeable by the server. The key
	// is the one that was current AT CREATION, which may since have been
	// superseded by a rotation; verifying an old root grant's signature
	// means checking it against this key, not the creator's current one.
	CreatorUserID           string `dynamodbav:"CreatorUserID"`
	CreatorSigningPublicKey []byte `dynamodbav:"CreatorSigningPublicKey"`
	// TrustAnchorSignature is the creator's Ed25519 signature (under
	// crypto.ContextTrustAnchor) over CreatorUserID + CreatorSigningPublicKey
	// + the group id -- see DESIGN.md, "The anchor is signed by the creator
	// at group creation." Without this, an unsigned anchor field would only
	// move the operator's freedom to fabricate a chain root from
	// verification time to a rewritten attribute; a client must check this
	// signature before trusting CreatorUserID/CreatorSigningPublicKey at all.
	TrustAnchorSignature []byte `dynamodbav:"TrustAnchorSignature"`

	// Visibility is VisibilityPrivate or VisibilityPublic, chosen at
	// creation and not changeable afterward -- switching a group's
	// visibility would mean re-encrypting or newly encrypting its name and
	// description, and DESIGN.md does not describe that migration.
	Visibility string `dynamodbav:"Visibility"`

	// NamePlaintext and DescriptionPlaintext hold a PUBLIC group's name and
	// description as typed. Empty (and absent from GSI1) for a private
	// group -- see DESIGN.md, "Private groups write no entry at all."
	NamePlaintext        string `dynamodbav:"NamePlaintext,omitempty"`
	DescriptionPlaintext string `dynamodbav:"DescriptionPlaintext,omitempty"`

	// NameCiphertext and DescriptionCiphertext hold a PRIVATE group's name
	// and description, AES-256-GCM under the group key at Generation 0 (the
	// only generation that exists at creation) -- see the AAD table in
	// DESIGN.md, "Group name/description" (AAD: group id + generation
	// number). Absent for a public group.
	NameCiphertext        *WrappedBlob `dynamodbav:"NameCiphertext,omitempty"`
	DescriptionCiphertext *WrappedBlob `dynamodbav:"DescriptionCiphertext,omitempty"`

	// RevocationMode is RevocationRotating or RevocationOpen, chosen at
	// creation. May later convert Rotating -> Open (not built by this
	// issue) but never the reverse -- see DESIGN.md, "Revocation mode."
	RevocationMode string `dynamodbav:"RevocationMode"`

	// ExpirationDays is the group's message-expiration policy in days, or 0
	// to mean "never expire" -- only valid when this deployment's
	// config.AllowGroupExpirationOff permits it. See DESIGN.md, "Message
	// expiration," and config.Config.AllowGroupExpirationOff.
	ExpirationDays int64 `dynamodbav:"ExpirationDays"`

	// Type is "dm" for a direct-message group, absent/empty for an ordinary
	// group -- see DESIGN.md, "Direct messages": "type is a plaintext
	// attribute on the group's META item, not a separate row." Not settable
	// through this issue's create-group endpoint (#73 builds DMs); the field
	// exists on the model now because it lives on this same item, not
	// because #34 populates it.
	Type string `dynamodbav:"GroupType,omitempty"`

	// GenerationKey is the group's symmetric key at Generation 0, wrapped to
	// the creator's own X25519 public key -- ECIES via crypto.Wrap (see
	// WrappedKey's own doc comment for why this is a WrappedKey, not a
	// WrappedBlob), AAD bound per MemberWrapAAD (group id + member uuid +
	// generation number). Every member holds their own wrapped copy on their
	// MEMBER# item instead; this copy is the creator's, stored here because
	// MEMBER# is written in the same transaction and the creator IS the
	// first member. Kept separate from the eventual GENKEY# chain (which
	// wraps each generation's key under its successor, member-independent)
	// -- this field is member-keyed like every other member's wrap, not
	// generation-keyed like GENKEY#.
	GenerationKeyWrapped WrappedKey `dynamodbav:"GenerationKeyWrapped"`
}

// Group roles. See Membership.Role and docs/DESIGN.md, "Roles and the chain
// of trust."
const (
	RoleAdmin      = "admin"
	RoleAmbassador = "ambassador"
	RoleMember     = "member"
)

// Membership is the GROUP#<gid> / MEMBER#<uuid> item -- see docs/DESIGN.md,
// "Data model." GSI1PK is USER#<uuid>, GSI1SK is GROUP#<gid>, which is what
// makes "list my groups" (#35) one GSI1 Query. TTL never: a membership
// itself does not expire, independent of the group's message-retention
// policy.
type Membership struct {
	Record

	// Role is RoleAdmin, RoleAmbassador or RoleMember, gating write access on
	// the hot path with a plain GetItem -- see DESIGN.md, "the current role
	// lives on the membership item and gates writes... this history [the
	// GRANT# chain] is read only by the chain walk, which is already the
	// slow path."
	Role string `dynamodbav:"Role"`

	// Generation is the newest key generation this member's WrappedGroupKey
	// is wrapped for. Always 0 at creation, since Generation 0 is the only
	// generation a brand-new group has.
	Generation int64 `dynamodbav:"Generation"`

	// WrappedGroupKey is this member's own ECIES-wrapped copy of the group
	// key at Generation, per MemberWrapAAD (group id + member uuid +
	// generation number) -- a WrappedKey, not a WrappedBlob, for the same
	// reason Group.GenerationKeyWrapped is (see that field's and
	// WrappedKey's own doc comments). For the creator's own membership item
	// (the only one #34 writes), this is the same plaintext as
	// Group.GenerationKeyWrapped, independently wrapped -- see that field's
	// own doc comment for why they are stored as two separate fields rather
	// than one shared blob.
	WrappedGroupKey WrappedKey `dynamodbav:"WrappedGroupKey"`
}

// RoleGrant is a GROUP#<gid> / GRANT#<uuid>#<YYYY-MM-DD, UTC>#<rand> item --
// see docs/DESIGN.md, "Roles and the chain of trust": "Grants are
// append-only, and that is what makes the chain walkable." SubjectUserID is
// duplicated off the sort key (rather than parsed back out of it) so a
// grant-chain walk's Query result can read it directly. TTL never -- "GRANT#
// items must stay verifiable back to the group creator forever."
type RoleGrant struct {
	Record

	// SubjectUserID is who this grant is FOR -- the uuid receiving or
	// having their role changed. For the root grant #34 writes, this is the
	// creator's own uuid: a self-grant, which is what anchors the chain (see
	// Group.TrustAnchorSignature's own doc comment).
	SubjectUserID string `dynamodbav:"SubjectUserID"`
	// GrantedRole is the role this grant confers -- RoleAdmin for the root
	// grant, since the creator is always Admin.
	GrantedRole string `dynamodbav:"GrantedRole"`

	// GrantorUserID and GrantorSigningPublicKey identify who signed this
	// grant and under which key -- for the root grant, identical to
	// SubjectUserID and the group's CreatorSigningPublicKey, since it is
	// self-signed. A later grant chain (#37) will have these differ from
	// SubjectUserID/GrantedRole's subject.
	GrantorUserID           string `dynamodbav:"GrantorUserID"`
	GrantorSigningPublicKey []byte `dynamodbav:"GrantorSigningPublicKey"`

	// Signature is the grantor's Ed25519 signature (under
	// crypto.ContextRoleGrant) over the grant's content -- group id, subject
	// uuid, granted role, and (for a non-root grant) a pointer to the
	// grantor's own current grant, so a chain walk can verify each link was
	// signed by someone who held Admin at the time. The exact signed payload
	// is defined where the signing helper lives (internal/crypto), not here;
	// this field only stores the resulting opaque bytes.
	Signature []byte `dynamodbav:"Signature"`
}
