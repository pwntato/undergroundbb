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

type vectorFile struct {
	Version       int                   `json:"version"`
	KDF           []kdfVector           `json:"kdf"`
	AEAD          []aeadVector          `json:"aead"`
	AEADNegative  []aeadNegativeVector  `json:"aead_negative"`
	Signing       []signingVector       `json:"signing"`
	SignedPayload []signedPayloadVector `json:"signed_payload"`
	Wrapping      []wrapVector          `json:"wrapping"`
	GenkeyChain   []genkeyChainVector   `json:"genkey_chain"`
	Fingerprint   []fingerprintVector   `json:"fingerprint"`
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

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
