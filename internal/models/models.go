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

	// DeletedAt is an RFC 3339 timestamp, set once by account deletion (#77).
	// A deleted account's PROFILE is a tombstone, never removed: user uuids
	// are never reused (see docs/DESIGN.md, the AAD table), and the public
	// keys stay so grants and signatures the user made can still be verified.
	// Username, salt, wrapped private keys, preferences and lock state are
	// removed; the USERNAME claim and RECOVERY item are deleted.
	DeletedAt string `dynamodbav:"DeletedAt,omitempty"`
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
// Membership.WrappedGroupKey and every future GENKEY# chain link.
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

	// RootGrantSortKey is the address of this group's root GRANT# item
	// ("GRANT#<uuid>#<YYYY-MM-DD>#<rand>") -- stored on META (PR #142 round
	// 2 review) so a lost-response retry of group creation can echo back
	// the actually-written root grant's address instead of the retry
	// request's own freshly re-signed one, which points at a row that was
	// never written (the client re-signs a fresh grantSortKey on every
	// attempt, including a resumed one -- see db.isOwnGroupCreation's own
	// doc comment). Unlike GenerationKeyWrapped (removed from this struct
	// in the same review round for going stale at rotation), this value
	// never changes after creation: the root grant is permanent and
	// append-only, so a copy here carries none of that staleness risk.
	RootGrantSortKey string `dynamodbav:"RootGrantSortKey"`

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
	// and description, AES-256-GCM under the group key at NameGeneration
	// (0 at creation) -- see the AAD table in DESIGN.md, "Group
	// name/description" (AAD: group id + field + generation number). Absent
	// for a public group.
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

	// NameGeneration is the key generation NameCiphertext and
	// DescriptionCiphertext are encrypted under (DESIGN.md: "META records
	// the generation it was encrypted under"). Zero at creation, which is
	// also what an absent attribute reads as, so groups created before this
	// field existed need no migration. Always zero for a public group.
	NameGeneration int64 `dynamodbav:"NameGeneration"`

	// Version counts successful settings edits (PUT /api/groups/{id}), for
	// optimistic concurrency between admins. Absent reads as zero.
	Version int64 `dynamodbav:"Version"`

	// Type is "dm" for a direct-message group, absent/empty for an ordinary
	// group -- see DESIGN.md, "Direct messages": "type is a plaintext
	// attribute on the group's META item, not a separate row." Not settable
	// through this issue's create-group endpoint (#73 builds DMs); the field
	// exists on the model now because it lives on this same item, not
	// because #34 populates it.
	//
	// Named GroupType, not Type, despite the dynamodbav tag matching either
	// way -- Group embeds Record, which already has its own Type field (the
	// item's kind, "Group"); a same-named GroupType.Type would shadow
	// Record.Type in Go (g.Type would mean this field, g.Record.Type the
	// item kind), silently breaking any future g.Type == "Group" or
	// g.Type = "dm" check on the wrong field. attributevalue itself
	// marshals both correctly regardless of the Go field name -- this is
	// purely for readers and future writers of this struct, not a wire
	// concern.
	GroupType string `dynamodbav:"GroupType,omitempty"`
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
	// generation number) -- a WrappedKey, not a WrappedBlob, since unwrapping
	// an ECIES wrap needs the ephemeral public key from this specific wrap
	// (WrappedKey's own doc comment). This member's MEMBER# item is the only
	// place their wrapped entry point to the group key lives -- there is no
	// second copy on META (db.CreateGroupInput.GenerationKeyWrapped's own
	// doc comment: PR #142 review dropped that duplicate, since a copy on
	// META would go stale at the first rotation while still looking current
	// to anyone who fetched it).
	WrappedGroupKey WrappedKey `dynamodbav:"WrappedGroupKey"`

	// GrantSortKey is the sort key of the GRANT# row that most recently set
	// this member's Role -- exact "current grant" bookkeeping, since two
	// grants signed on the same UTC day sort by their random suffix, not by
	// order of issue. It is what a grantor's next grant must reference as
	// its grantorGrantRef (RoleGrant.GrantorGrantRef). Absent for a member
	// who has never been granted anything (an invited plain Member), and
	// for a group creator on groups created before this field existed --
	// there the current grant is Group.RootGrantSortKey.
	GrantSortKey string `dynamodbav:"GrantSortKey,omitempty"`
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
	// GrantorGrantRef is the sort key of the grantor's own current grant when
	// this one was signed -- the grantorGrantRef input to
	// crypto.RoleGrantPayload, stored so a verifier can rebuild the signed
	// bytes. Empty for the root grant.
	GrantorGrantRef string `dynamodbav:"GrantorGrantRef,omitempty"`

	// Signature is the grantor's Ed25519 signature (under
	// crypto.ContextRoleGrant) over the grant's content -- group id, subject
	// uuid, granted role, and (for a non-root grant) a pointer to the
	// grantor's own current grant, so a chain walk can verify each link was
	// signed by someone who held Admin at the time. The exact signed payload
	// is defined where the signing helper lives (internal/crypto), not here;
	// this field only stores the resulting opaque bytes.
	Signature []byte `dynamodbav:"Signature"`
}

// Invite is the INVITE#<iid> / META item -- see docs/DESIGN.md, "Invites --
// the signed handshake" and issues #38/#39/#40. Written at step 1
// (creation) with no invitee identity at all -- GSI1PK/GSI1SK are left
// unset, since GET /api/invites/:id is unauthenticated by design and an
// invite is a link handed to someone who may not have an account yet. The
// GSI1PK "USER#<invitee>" / GSI1SK "INVITE#<YYYY-MM-DD, UTC>#<rand>" entry
// is added at step 2 (acceptance), once there is a uuid to point at -- see
// InvitedUserID's own doc comment for why the write that adds it also names
// this field.
//
// TTL is the signed ExpiresAt before acceptance, and after it the completion
// deadline PLUS a grace window (db.abandonedGraceDuration), both rounded to
// the end of their UTC day per the global TTL-rounding rule. It must never be
// set to the deadline itself: that would sweep the rows the moment it passes,
// the silent abandonment #83 prevents. The deadline is CompletionDeadline. See
// docs/DESIGN.md, "Invites -- the signed handshake," #38's own issue comments,
// and RoundUpToEndOfUTCDay. This package stores
// whichever the caller computed; the rounding and deadline arithmetic live
// in the db layer (db.AcceptInvite), matching this schema's usual "db
// computes storage values, models just holds them" split.
type Invite struct {
	Record

	// TTL is the DynamoDB TTL attribute -- the signed ExpiresAt (as a Unix
	// epoch) before acceptance, replaced at acceptance with the completion
	// deadline plus db.abandonedGraceDuration, rounded up to the end of its UTC
	// day (db.RoundUpToEndOfUTCDay, db.AcceptInvite). It is NOT the deadline
	// after acceptance -- that is CompletionDeadline. See this struct's own
	// doc comment.
	TTL int64 `dynamodbav:"TTL"`
	// CompletionDeadline is set at acceptance (Unix seconds, rounded to the
	// end of a UTC day like every stored TTL). It is the DEADLINE, kept apart
	// from TTL so that passing it surfaces the invite as overdue instead of
	// deleting it: TTL is the deadline plus db.abandonedGraceDuration, the
	// window in which both parties see it as overdue. Zero on an unaccepted
	// invite and on rows written before this field existed; use
	// EffectiveCompletionDeadline.
	CompletionDeadline int64 `dynamodbav:"CompletionDeadline,omitempty"`

	GroupID string `dynamodbav:"GroupID"`

	InviterUserID           string `dynamodbav:"InviterUserID"`
	InviterSigningPublicKey []byte `dynamodbav:"InviterSigningPublicKey"`
	// CreationSignature is the inviter's Ed25519 signature (crypto.Sign
	// under crypto.ContextInvite, over crypto.InviteCreationPayload) proving
	// InviterUserID actually holds InviterSigningPublicKey's private half at
	// the moment this invite was created. Stored so GET /api/invites/:id can
	// hand it back to an accountless invitee's client, which independently
	// verifies it before ever trusting InviterSigningPublicKey -- the same
	// "the server's own check is not what protects the invitee" reasoning
	// Group.TrustAnchorSignature's doc comment gives for a group's anchor.
	CreationSignature []byte `dynamodbav:"CreationSignature"`

	// ExpiresAt is the RFC 3339 (UTC) deadline the inviter signed at step 1
	// -- part of what CreationSignature covers, so the server cannot alter
	// an invite's advertised lifetime without invalidating the signature.
	// This is a plain string field, read on accept (before checking TTL,
	// which is only eventually consistent -- see #39's own issue comments)
	// -- distinct from the TTL attribute, which starts out numerically equal
	// to this value but is REPLACED at acceptance with a completion
	// deadline, while this field never changes.
	ExpiresAt string `dynamodbav:"ExpiresAt"`

	// InvitedUserID is empty until step 2 (acceptance) and, once set, never
	// changes -- see docs/DESIGN.md's "single-use" requirement: the
	// acceptance write is conditional on this field being ABSENT, so a
	// second holder of the same link (a forwarded message, a screenshot)
	// gets an explicit "already accepted" error rather than silently
	// overwriting the first acceptance. This is what makes the invite a
	// bearer token bound to exactly one accepter rather than a permissive
	// multi-use join link (a different object this schema does not have).
	InvitedUserID string `dynamodbav:"InvitedUserID,omitempty"`
	// InvitedEd25519PublicKey and InvitedX25519PublicKey are the keys the
	// invitee signed in AcceptanceSignature -- what step 3 wraps the group
	// key to, never a key the server could otherwise offer unilaterally.
	InvitedEd25519PublicKey []byte `dynamodbav:"InvitedEd25519PublicKey,omitempty"`
	InvitedX25519PublicKey  []byte `dynamodbav:"InvitedX25519PublicKey,omitempty"`
	// AcceptanceSignature is the invitee's Ed25519 signature (crypto.Sign
	// under crypto.ContextInvite, over crypto.InviteAcceptancePayload) over
	// {invite_id, ed25519_pub, x25519_pub} -- what step 3 verifies before
	// ever wrapping the group key to the keys named above. Stored (rather
	// than only checked once at accept time and discarded) so step 3's
	// completion query can re-verify it independently, the same
	// defense-in-depth reasoning every other signature in this schema gets:
	// the inviter's own client verifying this is what actually protects the
	// handshake, not the server having checked it first.
	AcceptanceSignature []byte `dynamodbav:"AcceptanceSignature,omitempty"`
	// InviteMAC is MAC_k(crypto.InviteAcceptancePayload(...)) -- k being the
	// per-invite secret carried in the invite link's own URL fragment,
	// never sent to any server (crypto.DeriveInviteMACKey's own doc
	// comment). This server stores and serves it back opaquely: it cannot
	// derive k and has no way to check this value itself, and does not try
	// to. Its only purpose is reaching the inviter's own client at step 3
	// (PendingInviteCompletions), the one party who CAN re-derive k and
	// verify it, closing the gap AcceptanceSignature alone leaves open --
	// see that same doc comment for what that gap is.
	InviteMAC []byte `dynamodbav:"InviteMAC,omitempty"`
}

// SentInvite is the USER#<inviter> / SENT#<iid> item -- the inviter's own
// copy of an invite they created, addressed by their own partition rather
// than the invite id, so step 3 (db.PendingInviteCompletions) can find "my
// invites that have been accepted and are awaiting completion" with a plain
// Query -- something neither INVITE#<iid> (needs the id you're trying to
// discover) nor a GSI keyed to the invitee can answer. See docs/DESIGN.md,
// "Invites -- the signed handshake," on why this second row exists at all.
//
// Deleted once step 3 completes -- so a Query against this partition prefix
// always returns pending work, never a history (docs/DESIGN.md: "the
// inviter's client lists USER#<inviter>/SENT# and completes anything
// accepted, deleting each row as it completes"). Carries no GSI1 entry: it
// is only ever read by its own owner's direct Query on PK, matching
// docs/DESIGN.md's schema table ("blank GSI1PK/GSI1SK").
//
// Duplicates GroupID, InvitedUserID, InvitedEd25519PublicKey,
// InvitedX25519PublicKey and AcceptanceSignature off the INVITE# row rather
// than requiring a second read to fetch them -- step 3's completion query
// already has to read this row to discover the invite exists at all, and
// everything it needs to wrap the group key and write the membership is
// naturally available here without a second GetItem per pending invite.
type SentInvite struct {
	Record

	// TTL mirrors Invite.TTL -- both rows take their lifetime from the same
	// signed ExpiresAt and are updated together at acceptance.
	TTL int64 `dynamodbav:"TTL"`
	// CompletionDeadline mirrors Invite.CompletionDeadline.
	CompletionDeadline int64 `dynamodbav:"CompletionDeadline,omitempty"`

	GroupID string `dynamodbav:"GroupID"`
	// InviteID recovers the INVITE#<iid> row's address -- duplicated off
	// this item's own SK ("SENT#<iid>") rather than parsed back out of it
	// everywhere a caller needs it, matching RoleGrant.SubjectUserID's own
	// reasoning for storing what the sort key would otherwise require
	// parsing.
	InviteID string `dynamodbav:"InviteID"`

	// InvitedUserID, InvitedEd25519PublicKey, InvitedX25519PublicKey and
	// AcceptanceSignature are empty/nil until acceptance, then set together
	// in the same TransactWriteItems that sets INVITE#<iid>'s own copies --
	// see db.AcceptInvite.
	InvitedUserID           string `dynamodbav:"InvitedUserID,omitempty"`
	InvitedEd25519PublicKey []byte `dynamodbav:"InvitedEd25519PublicKey,omitempty"`
	InvitedX25519PublicKey  []byte `dynamodbav:"InvitedX25519PublicKey,omitempty"`
	AcceptanceSignature     []byte `dynamodbav:"AcceptanceSignature,omitempty"`
	// InviteMAC duplicates Invite.InviteMAC -- see that field's own doc
	// comment. This is the copy PendingInviteCompletions actually reads
	// (this row, not INVITE#<iid>, is what step 3's discovery query
	// scans), so the inviter's client can re-derive k and verify it before
	// ever wrapping the group key.
	InviteMAC []byte `dynamodbav:"InviteMAC,omitempty"`
}

// EffectiveCompletionDeadline is the accepted invite's completion deadline as
// Unix seconds. Rows accepted before CompletionDeadline existed carried the
// deadline in TTL, so fall back to it.
func (i Invite) EffectiveCompletionDeadline() int64 {
	if i.CompletionDeadline != 0 {
		return i.CompletionDeadline
	}
	return i.TTL
}

// EffectiveCompletionDeadline: see Invite.EffectiveCompletionDeadline.
func (s SentInvite) EffectiveCompletionDeadline() int64 {
	if s.CompletionDeadline != 0 {
		return s.CompletionDeadline
	}
	return s.TTL
}

// Pin is the USER#<pinner> / PIN#<pinned uuid> item -- issue #63, docs/DESIGN.md
// "Key pinning and verification". It is the pinning user's own signed record of
// the key set they saw for another user, stored under the pinner's partition
// and keyed by the pinned user's uuid (never their username). The server
// verifies the signature at write and never again: the reader is the pinner's
// client, which must verify it itself, since a stored signature the client does
// not check protects against nothing. No CreatedAt: a full-resolution write
// time next to a signed record is the timing leak #147 tracks.
type Pin struct {
	Record

	// SigningPublicKeys is the pinned user's Ed25519 key set as the pinner saw
	// it: current and superseded, as a set (order is not significant).
	SigningPublicKeys [][]byte `dynamodbav:"SigningPublicKeys"`
	// WrappingPublicKey is the pinned user's current X25519 key.
	WrappingPublicKey []byte `dynamodbav:"WrappingPublicKey"`
	// PinnerSigningPublicKey is the key Signature was made under. Untrusted on
	// read: a client verifies only under its own current key and treats any
	// other value as tampering, until #62 adds a signed continuity link.
	PinnerSigningPublicKey []byte `dynamodbav:"PinnerSigningPublicKey"`
	Signature              []byte `dynamodbav:"Signature"`
}

// GenerationKey is one link of a group's key chain: GROUP#<gid> /
// GENKEY#<nnnnnn> holds generation n's key wrapped under generation n+1's,
// written once per rotation for the whole group. SK carries n zero-padded to
// six digits. Never carries a TTL: deleting a middle link would strand every
// older generation (docs/DESIGN.md, "GENKEY# items carry no TTL").
//
// Wrapped is AES-256-GCM under the new group key (a WrappedBlob, not a
// WrappedKey: no ECDH is involved), with AAD binding group id and generation.
type GenerationKey struct {
	Record

	Wrapped WrappedBlob `dynamodbav:"Wrapped"`
}

// Rotation is the GROUP#<gid> / ROTATION marker: a key rotation that has
// started and not yet finished. Its existence means new posts still use
// Generation-1 and some members may not yet hold Generation. Nothing on the
// server acts on it; admin clients compare StartedAt to the staleness deadline
// on group load and surface a stalled rotation (docs/DESIGN.md, "The rotation
// marker is the one item with a liveness requirement"). Never carries a TTL.
//
// Progress is deliberately not recorded here: resume is driven by member
// state (Membership.Generation behind this one), because BatchWriteItem's
// UnprocessedItems is a subset, not a prefix.
type Rotation struct {
	Record

	// Generation is the key generation being rotated TO.
	Generation int64 `dynamodbav:"Generation"`
	// StartedAt is an RFC 3339 timestamp.
	StartedAt string `dynamodbav:"StartedAt"`
	// StartedBy is the admin whose browser minted the new key and holds it.
	StartedBy string `dynamodbav:"StartedBy"`
}
