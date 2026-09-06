package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/crypto/argon2"
)

// vectorFile mirrors internal/crypto/testdata/vectors.json. Field shapes
// here must match internal/crypto/testdata/gen/main.go's output types
// exactly, since both are the same JSON schema — see testdata/README.md.
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

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("reading testdata/vectors.json: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parsing testdata/vectors.json: %v", err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}

func TestVectorKDF(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.KDF {
		t.Run(tc.Password, func(t *testing.T) {
			salt := mustHex(t, tc.SaltHex)
			want := mustHex(t, tc.KeyHex)
			// Parameters are read from the vector itself, not a compiled-in
			// constant, per docs/DESIGN.md's "Testing" section — this fails
			// if either the numbers or the read path changes.
			got := argon2.IDKey([]byte(tc.Password), salt, tc.T, tc.M, tc.P, uint32(len(want)))
			if !bytes.Equal(got, want) {
				t.Fatalf("Argon2id(m=%d,t=%d,p=%d) = %x, want %x", tc.M, tc.T, tc.P, got, want)
			}
		})
	}
}

func TestVectorAEAD(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.AEAD {
		t.Run(tc.Name, func(t *testing.T) {
			key := mustHex(t, tc.KeyHex)
			nonce := mustHex(t, tc.NonceHex)
			plaintext := mustHex(t, tc.PlaintextHex)
			aad := mustHex(t, tc.AADHex)
			want := mustHex(t, tc.CiphertextHex)

			got, err := EncryptWithNonce(key, nonce, plaintext, aad)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("EncryptWithNonce = %x, want %x", got, want)
			}

			decrypted, err := Decrypt(key, nonce, want, aad)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("Decrypt = %x, want %x", decrypted, plaintext)
			}
		})
	}
}

// TestVectorAEADNegative is the negative case docs/DESIGN.md's "Testing"
// section calls out by name: a mismatched AAD must fail, which is what
// catches an implementation that quietly stops binding ciphertext to its
// address.
func TestVectorAEADNegative(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.AEADNegative {
		t.Run(tc.Name, func(t *testing.T) {
			key := mustHex(t, tc.KeyHex)
			nonce := mustHex(t, tc.NonceHex)
			ciphertext := mustHex(t, tc.CiphertextHex)
			wrongAAD := mustHex(t, tc.WrongAADHex)

			if _, err := Decrypt(key, nonce, ciphertext, wrongAAD); err != ErrDecryptionFailed {
				t.Fatalf("Decrypt with wrong AAD: got err %v, want ErrDecryptionFailed", err)
			}
		})
	}
}

func TestVectorSigning(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.Signing {
		t.Run(tc.Name, func(t *testing.T) {
			priv := ed25519.PrivateKey(mustHex(t, tc.PrivateHex))
			pub := ed25519.PublicKey(mustHex(t, tc.PublicHex))
			message := mustHex(t, tc.MessageHex)
			want := mustHex(t, tc.SignatureHex)

			got, err := Sign(priv, SigningContext(tc.Context), message)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Sign = %x, want %x", got, want)
			}
			if !Verify(pub, SigningContext(tc.Context), message, want) {
				t.Fatal("Verify rejected the vector's own signature")
			}
		})
	}
}

func TestVectorSignedPayload(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.SignedPayload {
		t.Run(tc.Name, func(t *testing.T) {
			priv := ed25519.PrivateKey(mustHex(t, tc.PrivateHex))
			pub := ed25519.PublicKey(mustHex(t, tc.PublicHex))
			ciphertext := mustHex(t, tc.CiphertextHex)
			wantPayload := mustHex(t, tc.PayloadHex)
			wantSig := mustHex(t, tc.SignatureHex)

			gotPayload := SignedPayload(tc.AuthorUUID, tc.GroupID, tc.SortKey, tc.Generation, tc.UTCDay, ciphertext)
			if !bytes.Equal(gotPayload, wantPayload) {
				t.Fatalf("SignedPayload = %x, want %x", gotPayload, wantPayload)
			}

			gotSig, err := Sign(priv, SigningContext(tc.Context), gotPayload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSig, wantSig) {
				t.Fatalf("Sign(payload) = %x, want %x", gotSig, wantSig)
			}
			if !Verify(pub, SigningContext(tc.Context), gotPayload, wantSig) {
				t.Fatal("Verify rejected the vector's own signature over SignedPayload")
			}
		})
	}
}

func TestVectorWrapping(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.Wrapping {
		t.Run(tc.Name, func(t *testing.T) {
			recipientPriv, err := ecdh.X25519().NewPrivateKey(mustHex(t, tc.RecipientPrivHex))
			if err != nil {
				t.Fatal(err)
			}
			ephemeralPriv, err := ecdh.X25519().NewPrivateKey(mustHex(t, tc.EphemeralPrivHex))
			if err != nil {
				t.Fatal(err)
			}
			plaintext := mustHex(t, tc.PlaintextHex)
			aad := mustHex(t, tc.AADHex)
			wantNonce := mustHex(t, tc.WrappedNonceHex)
			wantCiphertext := mustHex(t, tc.WrappedCiphertext)

			wrapped, err := WrapWithEphemeralAndNonce(recipientPriv.PublicKey(), ephemeralPriv, wantNonce, plaintext, aad)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wrapped.Nonce, wantNonce) {
				t.Fatalf("nonce = %x, want %x", wrapped.Nonce, wantNonce)
			}
			if !bytes.Equal(wrapped.Ciphertext, wantCiphertext) {
				t.Fatalf("ciphertext = %x, want %x", wrapped.Ciphertext, wantCiphertext)
			}
			if !bytes.Equal(wrapped.EphemeralPub, ephemeralPriv.PublicKey().Bytes()) {
				t.Fatalf("ephemeral pub = %x, want %x", wrapped.EphemeralPub, ephemeralPriv.PublicKey().Bytes())
			}

			got, err := Unwrap(recipientPriv, wrapped, aad)
			if err != nil {
				t.Fatalf("Unwrap: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("Unwrap = %x, want %x", got, plaintext)
			}
		})
	}
}

// TestVectorGenkeyChain is the negative vector issue #20 calls out by name:
// GENKEY#<n> holds generation n (a symmetric AES-256 key) encrypted under
// generation n+1's key, per docs/DESIGN.md:1131. A holder of generation n+1
// decrypts backward to generation n; a holder of only generation n has no
// key material that decrypts anything encrypted under generation n+1.
func TestVectorGenkeyChain(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.GenkeyChain {
		t.Run(tc.Name, func(t *testing.T) {
			genN := mustHex(t, tc.GenNKeyHex)
			genNPlus1 := mustHex(t, tc.GenNPlus1KeyHex)
			aad := mustHex(t, tc.AADHex)
			nonce := mustHex(t, tc.LinkNonceHex)
			wantCiphertext := mustHex(t, tc.LinkCiphertext)

			gotCiphertext, err := EncryptWithNonce(genNPlus1, nonce, genN, aad)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotCiphertext, wantCiphertext) {
				t.Fatalf("link ciphertext = %x, want %x", gotCiphertext, wantCiphertext)
			}

			got, err := Decrypt(genNPlus1, nonce, wantCiphertext, aad)
			if err != nil {
				t.Fatalf("gen N+1 holder failed to decrypt the link: %v", err)
			}
			if !bytes.Equal(got, genN) {
				t.Fatalf("gen N+1 holder decrypted %x, want %x", got, genN)
			}

			if tc.ForwardMustFail {
				if _, err := Decrypt(genN, nonce, wantCiphertext, aad); err != ErrDecryptionFailed {
					t.Fatalf("gen N holder decrypted a link encrypted under gen N+1: got err %v, want ErrDecryptionFailed", err)
				}
			}
		})
	}
}

func TestVectorFingerprint(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.Fingerprint {
		t.Run(tc.Name, func(t *testing.T) {
			signingPub := ed25519.PublicKey(mustHex(t, tc.SigningPubHex))
			wrappingPub := mustHex(t, tc.WrappingPubHex)

			got, err := Fingerprint(signingPub, wrappingPub)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.Fingerprint {
				t.Fatalf("Fingerprint = %q, want %q", got, tc.Fingerprint)
			}
		})
	}
}
