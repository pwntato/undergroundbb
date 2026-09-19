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
// could.
type WrappedBlob struct {
	Nonce      []byte `dynamodbav:"Nonce"`
	Ciphertext []byte `dynamodbav:"Ciphertext"`
}

// Recovery is the USER#<uuid> / RECOVERY item -- a second copy of the
// private keys, wrapped under a key derived from a recovery code the client
// generates at signup, independent of the password. See docs/DESIGN.md,
// "The recovery copy is a separate item, not an attribute of the profile."
//
// Salt and Argon2Params are this item's own, unrelated to User's -- the
// recovery derivation has no dependence on the password, which is the whole
// point of the item.
type Recovery struct {
	Record

	Salt               []byte       `dynamodbav:"Salt"`
	Argon2Params       Argon2Params `dynamodbav:"Argon2Params"`
	WrappedPrivateKeys WrappedBlob  `dynamodbav:"WrappedPrivateKeys"`

	// CredentialVersion mirrors User.CredentialVersion -- both items rewrite
	// together on every credential change, under the same transaction
	// condition. Registration sets it to 1.
	CredentialVersion int64 `dynamodbav:"CredentialVersion"`
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
