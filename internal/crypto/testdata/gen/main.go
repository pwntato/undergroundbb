// Command gen regenerates internal/crypto/testdata/vectors.json from this
// project's own crypto primitives, run against fixed inputs. See
// internal/crypto/testdata/README.md for what each category means and why
// this must not be run casually once real data exists under these values.
package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"

	"github.com/pwntato/undergroundbb/internal/crypto"
)

// fixedSeed expands a short label into deterministic key material via
// SHA-256, so every run of this generator produces byte-identical output
// without checking in raw random bytes by hand. This is a test-fixture
// convenience, not a cryptographic derivation used anywhere else in the
// project — it exists only so a reviewer can regenerate and diff.
func fixedSeed(label string) []byte {
	sum := sha256.Sum256([]byte("underground-bb:test-vector-seed:" + label))
	return sum[:]
}

func fixedEd25519Key(label string) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := fixedSeed(label)[:ed25519.SeedSize]
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func fixedX25519Key(label string) *ecdh.PrivateKey {
	seed := fixedSeed(label)
	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		panic(err)
	}
	return priv
}

type kdfVector struct {
	Password string `json:"password"`
	SaltHex  string `json:"salt_hex"`
	M        uint32 `json:"m_kib"`
	T        uint32 `json:"t"`
	P        uint8  `json:"p"`
	KeyHex   string `json:"key_hex"`
}

type aeadVector struct {
	Name          string `json:"name"`
	KeyHex        string `json:"key_hex"`
	NonceHex      string `json:"nonce_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	AADHex        string `json:"aad_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

type aeadNegativeVector struct {
	Name          string `json:"name"`
	KeyHex        string `json:"key_hex"`
	NonceHex      string `json:"nonce_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
	AADHex        string `json:"aad_hex"`
	WrongAADHex   string `json:"wrong_aad_hex"`
}

type signingVector struct {
	Name         string `json:"name"`
	PrivateHex   string `json:"private_key_hex"`
	PublicHex    string `json:"public_key_hex"`
	Context      string `json:"context"`
	MessageHex   string `json:"message_hex"`
	SignatureHex string `json:"signature_hex"`
}

type signedPayloadVector struct {
	Name          string `json:"name"`
	PrivateHex    string `json:"private_key_hex"`
	PublicHex     string `json:"public_key_hex"`
	Context       string `json:"context"`
	AuthorUUID    string `json:"author_uuid"`
	GroupID       string `json:"group_id"`
	SortKey       string `json:"sort_key"`
	Generation    uint64 `json:"generation"`
	UTCDay        string `json:"utc_day"`
	CiphertextHex string `json:"ciphertext_hex"`
	PayloadHex    string `json:"payload_hex"`
	SignatureHex  string `json:"signature_hex"`
}

type wrapVector struct {
	Name              string `json:"name"`
	RecipientPrivHex  string `json:"recipient_private_key_hex"`
	RecipientPubHex   string `json:"recipient_public_key_hex"`
	EphemeralPrivHex  string `json:"ephemeral_private_key_hex"`
	EphemeralPubHex   string `json:"ephemeral_public_key_hex"`
	PlaintextHex      string `json:"plaintext_hex"`
	AADHex            string `json:"aad_hex"`
	WrappedNonceHex   string `json:"wrapped_nonce_hex"`
	WrappedCiphertext string `json:"wrapped_ciphertext_hex"`
}

type genkeyChainVector struct {
	Name            string `json:"name"`
	GenNKeyHex      string `json:"gen_n_key_hex"`
	GenNPlus1KeyHex string `json:"gen_n_plus_1_key_hex"`
	AADHex          string `json:"aad_hex"`
	LinkNonceHex    string `json:"link_nonce_hex"`
	LinkCiphertext  string `json:"link_ciphertext_hex"`
	ForwardMustFail bool   `json:"forward_must_fail"`
}

type fingerprintVector struct {
	Name           string `json:"name"`
	SigningPubHex  string `json:"signing_public_key_hex"`
	WrappingPubHex string `json:"wrapping_public_key_hex"`
	Fingerprint    string `json:"fingerprint"`
}

// credentialWrapVector proves CredentialWrapAAD's encoding byte-for-byte,
// the same way wrapVector proves the GENKEY AAD -- see credential.go's own
// doc comment for why this one specifically needed pinning down rather than
// being left to whatever each implementation happened to guess.
type credentialWrapVector struct {
	Name          string `json:"name"`
	UserID        string `json:"user_id"`
	Copy          string `json:"copy"`
	AADHex        string `json:"aad_hex"`
	KeyHex        string `json:"key_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	NonceHex      string `json:"nonce_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

// keyBundleVector proves EncodeKeyBundle's exact byte layout -- see
// keybundle.go's own doc comment for why this specific encoding, like the
// credential-wrap AAD before it, had no code pinning its format before #33
// needed one.
type keyBundleVector struct {
	Name               string `json:"name"`
	SigningSeedHex     string `json:"signing_seed_hex"`
	WrappingPrivKeyHex string `json:"wrapping_private_key_hex"`
	EncodedHex         string `json:"encoded_hex"`
}

// trustAnchorVector proves TrustAnchorPayload's exact encoding -- issue #34,
// the same reasoning as signedPayloadVector: a group's root of trust is
// verified by every future member's client, so this payload's byte layout
// must be pinned across Go and TypeScript before any real group exists
// under it.
type trustAnchorVector struct {
	Name         string `json:"name"`
	PrivateHex   string `json:"private_key_hex"`
	PublicHex    string `json:"public_key_hex"`
	CreatorUUID  string `json:"creator_uuid"`
	GroupID      string `json:"group_id"`
	PayloadHex   string `json:"payload_hex"`
	SignatureHex string `json:"signature_hex"`
}

// roleGrantVector proves RoleGrantPayload's exact encoding, for both the
// root-grant shape (empty grantorGrantRef) and a non-root grant referencing
// a real predecessor -- see RoleGrantPayload's own doc comment.
type roleGrantVector struct {
	Name            string `json:"name"`
	PrivateHex      string `json:"private_key_hex"`
	PublicHex       string `json:"public_key_hex"`
	GroupID         string `json:"group_id"`
	SubjectUUID     string `json:"subject_uuid"`
	Role            string `json:"role"`
	GrantorGrantRef string `json:"grantor_grant_ref"`
	PayloadHex      string `json:"payload_hex"`
	SignatureHex    string `json:"signature_hex"`
}

// memberWrapVector proves MemberWrapAAD's exact encoding -- the same
// reasoning as credentialWrapVector: pinning the AAD string itself, plus
// the AES-256-GCM ciphertext it produces under a fixed key/nonce/plaintext,
// so a member's own wrapped group-key entry point never drifts between
// implementations.
type memberWrapVector struct {
	Name          string `json:"name"`
	GroupID       string `json:"group_id"`
	MemberUUID    string `json:"member_uuid"`
	Generation    uint64 `json:"generation"`
	AADHex        string `json:"aad_hex"`
	KeyHex        string `json:"key_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	NonceHex      string `json:"nonce_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

// groupNameVector proves GroupNameAAD's exact encoding, for both the name
// and description fields at the same group id and generation -- proving
// the two encode to genuinely different AAD, the same shape
// credentialWrapVector proves for PROFILE vs. RECOVERY.
type groupNameVector struct {
	Name          string `json:"name"`
	GroupID       string `json:"group_id"`
	Field         string `json:"field"`
	Generation    uint64 `json:"generation"`
	AADHex        string `json:"aad_hex"`
	KeyHex        string `json:"key_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	NonceHex      string `json:"nonce_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

type vectorFile struct {
	Version        int                    `json:"version"`
	KDF            []kdfVector            `json:"kdf"`
	AEAD           []aeadVector           `json:"aead"`
	AEADNegative   []aeadNegativeVector   `json:"aead_negative"`
	Signing        []signingVector        `json:"signing"`
	SignedPayload  []signedPayloadVector  `json:"signed_payload"`
	Wrapping       []wrapVector           `json:"wrapping"`
	GenkeyChain    []genkeyChainVector    `json:"genkey_chain"`
	Fingerprint    []fingerprintVector    `json:"fingerprint"`
	CredentialWrap []credentialWrapVector `json:"credential_wrap"`
	KeyBundle      []keyBundleVector      `json:"key_bundle"`
	TrustAnchor    []trustAnchorVector    `json:"trust_anchor"`
	RoleGrant      []roleGrantVector      `json:"role_grant"`
	MemberWrap     []memberWrapVector     `json:"member_wrap_aad"`
	GroupName      []groupNameVector      `json:"group_name_aad"`
}

func main() {
	out := vectorFile{Version: 1}

	// --- KDF ---
	// Argon2id parameters match docs/DESIGN.md's stored values: m=64 MiB, t=3, p=1.
	{
		password := "correct horse battery staple"
		salt := fixedSeed("kdf-salt-1")[:16]
		m := uint32(64 * 1024) // KiB
		t := uint32(3)
		p := uint8(1)
		key := argon2.IDKey([]byte(password), salt, t, m, p, uint32(crypto.KeySize))
		out.KDF = append(out.KDF, kdfVector{
			Password: password,
			SaltHex:  hex.EncodeToString(salt),
			M:        m,
			T:        t,
			P:        p,
			KeyHex:   hex.EncodeToString(key),
		})
	}

	// --- AEAD ---
	{
		key := fixedSeed("aead-key-1")[:crypto.KeySize]
		nonce := fixedSeed("aead-nonce-1")[:crypto.NonceSize]
		plaintext := []byte("the group key rotates on member removal")
		aad := []byte("GROUP#g1:POST#2026-09-06#a1b2:gen3")
		ciphertext, err := crypto.EncryptWithNonce(key, nonce, plaintext, aad)
		if err != nil {
			panic(err)
		}
		out.AEAD = append(out.AEAD, aeadVector{
			Name:          "basic",
			KeyHex:        hex.EncodeToString(key),
			NonceHex:      hex.EncodeToString(nonce),
			PlaintextHex:  hex.EncodeToString(plaintext),
			AADHex:        hex.EncodeToString(aad),
			CiphertextHex: hex.EncodeToString(ciphertext),
		})
		out.AEADNegative = append(out.AEADNegative, aeadNegativeVector{
			Name:          "wrong_aad_must_fail",
			KeyHex:        hex.EncodeToString(key),
			NonceHex:      hex.EncodeToString(nonce),
			CiphertextHex: hex.EncodeToString(ciphertext),
			AADHex:        hex.EncodeToString(aad),
			WrongAADHex:   hex.EncodeToString([]byte("GROUP#g1:POST#2026-09-06#a1b2:gen4")),
		})
	}

	// --- Signing: one case per SigningContext ---
	{
		pub, priv := fixedEd25519Key("signing-key-1")
		contexts := []crypto.SigningContext{
			crypto.ContextLoginChallenge,
			crypto.ContextPost,
			crypto.ContextComment,
			crypto.ContextRoleGrant,
			crypto.ContextInvite,
			crypto.ContextTrustAnchor,
		}
		for _, ctx := range contexts {
			message := []byte("fixed test message for " + string(ctx))
			sig, err := crypto.Sign(priv, ctx, message)
			if err != nil {
				panic(err)
			}
			out.Signing = append(out.Signing, signingVector{
				Name:         string(ctx),
				PrivateHex:   hex.EncodeToString(priv),
				PublicHex:    hex.EncodeToString(pub),
				Context:      string(ctx),
				MessageHex:   hex.EncodeToString(message),
				SignatureHex: hex.EncodeToString(sig),
			})
		}
	}

	// --- SignedPayload: post and comment ---
	{
		pub, priv := fixedEd25519Key("payload-key-1")
		ciphertext := []byte("encrypted post body goes here")

		postPayload := crypto.SignedPayload("author-uuid-1", "group-uuid-1", "POST#2026-09-06#a1b2c3", 3, "2026-09-06", ciphertext)
		postSig, err := crypto.Sign(priv, crypto.ContextPost, postPayload)
		if err != nil {
			panic(err)
		}
		out.SignedPayload = append(out.SignedPayload, signedPayloadVector{
			Name:          "post",
			PrivateHex:    hex.EncodeToString(priv),
			PublicHex:     hex.EncodeToString(pub),
			Context:       string(crypto.ContextPost),
			AuthorUUID:    "author-uuid-1",
			GroupID:       "group-uuid-1",
			SortKey:       "POST#2026-09-06#a1b2c3",
			Generation:    3,
			UTCDay:        "2026-09-06",
			CiphertextHex: hex.EncodeToString(ciphertext),
			PayloadHex:    hex.EncodeToString(postPayload),
			SignatureHex:  hex.EncodeToString(postSig),
		})

		// Comments carry no day in their sort key (materialized path only),
		// so the UTC day here is load-bearing for the payload rather than
		// redundant with it — see docs/DESIGN.md:90-93.
		commentPayload := crypto.SignedPayload("author-uuid-1", "group-uuid-1", "CMT#0001", 3, "2026-09-06", ciphertext)
		commentSig, err := crypto.Sign(priv, crypto.ContextComment, commentPayload)
		if err != nil {
			panic(err)
		}
		out.SignedPayload = append(out.SignedPayload, signedPayloadVector{
			Name:          "comment",
			PrivateHex:    hex.EncodeToString(priv),
			PublicHex:     hex.EncodeToString(pub),
			Context:       string(crypto.ContextComment),
			AuthorUUID:    "author-uuid-1",
			GroupID:       "group-uuid-1",
			SortKey:       "CMT#0001",
			Generation:    3,
			UTCDay:        "2026-09-06",
			CiphertextHex: hex.EncodeToString(ciphertext),
			PayloadHex:    hex.EncodeToString(commentPayload),
			SignatureHex:  hex.EncodeToString(commentSig),
		})
	}

	// --- Wrapping ---
	{
		recipientPriv := fixedX25519Key("wrap-recipient-1")
		ephemeralPriv := fixedX25519Key("wrap-ephemeral-1")
		plaintext := fixedSeed("wrap-plaintext-1")[:crypto.KeySize]
		aad := []byte("GROUP#g1:GENKEY#000004")
		nonce := fixedSeed("wrap-nonce-1")[:crypto.NonceSize]

		wrapped, err := crypto.WrapWithEphemeralAndNonce(recipientPriv.PublicKey(), ephemeralPriv, nonce, plaintext, aad)
		if err != nil {
			panic(err)
		}
		out.Wrapping = append(out.Wrapping, wrapVector{
			Name:              "basic",
			RecipientPrivHex:  hex.EncodeToString(recipientPriv.Bytes()),
			RecipientPubHex:   hex.EncodeToString(recipientPriv.PublicKey().Bytes()),
			EphemeralPrivHex:  hex.EncodeToString(ephemeralPriv.Bytes()),
			EphemeralPubHex:   hex.EncodeToString(ephemeralPriv.PublicKey().Bytes()),
			PlaintextHex:      hex.EncodeToString(plaintext),
			AADHex:            hex.EncodeToString(aad),
			WrappedNonceHex:   hex.EncodeToString(wrapped.Nonce),
			WrappedCiphertext: hex.EncodeToString(wrapped.Ciphertext),
		})
	}

	// --- Credential wrap AAD (#30) ---
	// Two vectors under the SAME userID and key material, differing only in
	// which copy -- proving CredentialWrapAAD produces genuinely different
	// AAD (and therefore a genuinely different ciphertext) for PROFILE vs.
	// RECOVERY, not just a string that happens to round-trip through one
	// path. This is what a relocation between the two items would need to
	// survive, per docs/DESIGN.md's AAD table.
	{
		userID := "11111111-2222-3333-4444-555555555555"
		key := fixedSeed("credential-wrap-key-1")[:crypto.KeySize]
		plaintext := fixedSeed("credential-wrap-plaintext-1")

		for _, tc := range []struct {
			name       string
			copy       crypto.CredentialCopy
			nonceLabel string
		}{
			{"profile", crypto.CredentialCopyProfile, "credential-wrap-nonce-profile-1"},
			{"recovery", crypto.CredentialCopyRecovery, "credential-wrap-nonce-recovery-1"},
		} {
			aad := crypto.CredentialWrapAAD(userID, tc.copy)
			nonce := fixedSeed(tc.nonceLabel)[:crypto.NonceSize]
			ciphertext, err := crypto.EncryptWithNonce(key, nonce, plaintext, aad)
			if err != nil {
				panic(err)
			}
			out.CredentialWrap = append(out.CredentialWrap, credentialWrapVector{
				Name:          tc.name,
				UserID:        userID,
				Copy:          string(tc.copy),
				AADHex:        hex.EncodeToString(aad),
				KeyHex:        hex.EncodeToString(key),
				PlaintextHex:  hex.EncodeToString(plaintext),
				NonceHex:      hex.EncodeToString(nonce),
				CiphertextHex: hex.EncodeToString(ciphertext),
			})
		}
	}

	// --- Key bundle encoding (#33) ---
	// Fixed 32-byte fields chosen from fixedEd25519Key/fixedX25519Key rather
	// than fixedSeed directly, so this vector proves the SAME encoding a real
	// client would produce from real keys, not just that some 32 bytes
	// round-trip through the length-prefixed framing.
	{
		_, signingPriv := fixedEd25519Key("keybundle-signing-1")
		wrappingPriv := fixedX25519Key("keybundle-wrapping-1")

		bundle := crypto.KeyBundle{
			SigningSeed:        signingPriv.Seed(),
			WrappingPrivateKey: wrappingPriv.Bytes(),
		}
		encoded, err := crypto.EncodeKeyBundle(bundle)
		if err != nil {
			panic(err)
		}
		out.KeyBundle = append(out.KeyBundle, keyBundleVector{
			Name:               "basic",
			SigningSeedHex:     hex.EncodeToString(bundle.SigningSeed),
			WrappingPrivKeyHex: hex.EncodeToString(bundle.WrappingPrivateKey),
			EncodedHex:         hex.EncodeToString(encoded),
		})
	}

	// --- GENKEY chain link (the #20-named negative vector) ---
	{
		genN := fixedSeed("genkey-n-1")[:crypto.KeySize]
		genNPlus1 := fixedSeed("genkey-n+1-1")[:crypto.KeySize]
		aad := []byte("GROUP#g1:GENKEY#000001")
		nonce := fixedSeed("genkey-link-nonce-1")[:crypto.NonceSize]
		ciphertext, err := crypto.EncryptWithNonce(genNPlus1, nonce, genN, aad)
		if err != nil {
			panic(err)
		}
		out.GenkeyChain = append(out.GenkeyChain, genkeyChainVector{
			Name:            "gen_n_under_gen_n_plus_1",
			GenNKeyHex:      hex.EncodeToString(genN),
			GenNPlus1KeyHex: hex.EncodeToString(genNPlus1),
			AADHex:          hex.EncodeToString(aad),
			LinkNonceHex:    hex.EncodeToString(nonce),
			LinkCiphertext:  hex.EncodeToString(ciphertext),
			ForwardMustFail: true,
		})
	}

	// --- Fingerprint ---
	{
		signingPub, _ := fixedEd25519Key("fingerprint-signing-1")
		wrappingPriv := fixedX25519Key("fingerprint-wrapping-1")
		fp, err := crypto.Fingerprint(signingPub, wrappingPriv.PublicKey().Bytes())
		if err != nil {
			panic(err)
		}
		out.Fingerprint = append(out.Fingerprint, fingerprintVector{
			Name:           "basic",
			SigningPubHex:  hex.EncodeToString(signingPub),
			WrappingPubHex: hex.EncodeToString(wrappingPriv.PublicKey().Bytes()),
			Fingerprint:    fp,
		})
	}

	// --- Trust anchor (#34) ---
	{
		pub, priv := fixedEd25519Key("trust-anchor-key-1")
		creatorUUID := "creator-uuid-1"
		groupID := "group-uuid-2"

		payload := crypto.TrustAnchorPayload(creatorUUID, pub, groupID)
		sig, err := crypto.Sign(priv, crypto.ContextTrustAnchor, payload)
		if err != nil {
			panic(err)
		}
		out.TrustAnchor = append(out.TrustAnchor, trustAnchorVector{
			Name:         "basic",
			PrivateHex:   hex.EncodeToString(priv),
			PublicHex:    hex.EncodeToString(pub),
			CreatorUUID:  creatorUUID,
			GroupID:      groupID,
			PayloadHex:   hex.EncodeToString(payload),
			SignatureHex: hex.EncodeToString(sig),
		})
	}

	// --- Role grant (#34): root grant (empty ref) and a non-root grant ---
	{
		pub, priv := fixedEd25519Key("role-grant-key-1")
		groupID := "group-uuid-2"
		creatorUUID := "creator-uuid-1"

		rootPayload := crypto.RoleGrantPayload(groupID, creatorUUID, "admin", "")
		rootSig, err := crypto.Sign(priv, crypto.ContextRoleGrant, rootPayload)
		if err != nil {
			panic(err)
		}
		out.RoleGrant = append(out.RoleGrant, roleGrantVector{
			Name:            "root",
			PrivateHex:      hex.EncodeToString(priv),
			PublicHex:       hex.EncodeToString(pub),
			GroupID:         groupID,
			SubjectUUID:     creatorUUID,
			Role:            "admin",
			GrantorGrantRef: "",
			PayloadHex:      hex.EncodeToString(rootPayload),
			SignatureHex:    hex.EncodeToString(rootSig),
		})

		subjectUUID := "member-uuid-1"
		grantRef := "GRANT#" + creatorUUID + "#2026-09-06#a1b2c3d4e5f6a1b2"
		nonRootPayload := crypto.RoleGrantPayload(groupID, subjectUUID, "member", grantRef)
		nonRootSig, err := crypto.Sign(priv, crypto.ContextRoleGrant, nonRootPayload)
		if err != nil {
			panic(err)
		}
		out.RoleGrant = append(out.RoleGrant, roleGrantVector{
			Name:            "non_root",
			PrivateHex:      hex.EncodeToString(priv),
			PublicHex:       hex.EncodeToString(pub),
			GroupID:         groupID,
			SubjectUUID:     subjectUUID,
			Role:            "member",
			GrantorGrantRef: grantRef,
			PayloadHex:      hex.EncodeToString(nonRootPayload),
			SignatureHex:    hex.EncodeToString(nonRootSig),
		})
	}

	// --- Member wrap AAD (#34) ---
	{
		groupID := "group-uuid-2"
		memberUUID := "member-uuid-1"
		var generation uint64 = 0
		key := fixedSeed("member-wrap-key-1")[:crypto.KeySize]
		plaintext := fixedSeed("member-wrap-plaintext-1")[:crypto.KeySize]
		nonce := fixedSeed("member-wrap-nonce-1")[:crypto.NonceSize]

		aad := crypto.MemberWrapAAD(groupID, memberUUID, generation)
		ciphertext, err := crypto.EncryptWithNonce(key, nonce, plaintext, aad)
		if err != nil {
			panic(err)
		}
		out.MemberWrap = append(out.MemberWrap, memberWrapVector{
			Name:          "generation_0",
			GroupID:       groupID,
			MemberUUID:    memberUUID,
			Generation:    generation,
			AADHex:        hex.EncodeToString(aad),
			KeyHex:        hex.EncodeToString(key),
			PlaintextHex:  hex.EncodeToString(plaintext),
			NonceHex:      hex.EncodeToString(nonce),
			CiphertextHex: hex.EncodeToString(ciphertext),
		})
	}

	// --- Group name AAD (#34) ---
	{
		groupID := "group-uuid-2"
		var generation uint64 = 0
		key := fixedSeed("group-name-key-1")[:crypto.KeySize]

		for _, tc := range []struct {
			name       string
			field      crypto.GroupTextField
			plaintext  []byte
			nonceLabel string
		}{
			{"name", crypto.GroupNameField, []byte("Book Club"), "group-name-nonce-name-1"},
			{"description", crypto.GroupDescriptionField, []byte("We read books"), "group-name-nonce-description-1"},
		} {
			aad := crypto.GroupNameAAD(groupID, tc.field, generation)
			nonce := fixedSeed(tc.nonceLabel)[:crypto.NonceSize]
			ciphertext, err := crypto.EncryptWithNonce(key, nonce, tc.plaintext, aad)
			if err != nil {
				panic(err)
			}
			out.GroupName = append(out.GroupName, groupNameVector{
				Name:          tc.name,
				GroupID:       groupID,
				Field:         string(tc.field),
				Generation:    generation,
				AADHex:        hex.EncodeToString(aad),
				KeyHex:        hex.EncodeToString(key),
				PlaintextHex:  hex.EncodeToString(tc.plaintext),
				NonceHex:      hex.EncodeToString(nonce),
				CiphertextHex: hex.EncodeToString(ciphertext),
			})
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
