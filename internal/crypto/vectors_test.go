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
	Version              int                          `json:"version"`
	KDF                  []kdfVector                  `json:"kdf"`
	AEAD                 []aeadVector                 `json:"aead"`
	AEADNegative         []aeadNegativeVector         `json:"aead_negative"`
	Signing              []signingVector              `json:"signing"`
	SignedPayload        []signedPayloadVector        `json:"signed_payload"`
	Wrapping             []wrapVector                 `json:"wrapping"`
	GenkeyChain          []genkeyChainVector          `json:"genkey_chain"`
	Fingerprint          []fingerprintVector          `json:"fingerprint"`
	CredentialWrap       []credentialWrapVector       `json:"credential_wrap"`
	KeyBundle            []keyBundleVector            `json:"key_bundle"`
	TrustAnchor          []trustAnchorVector          `json:"trust_anchor"`
	RoleGrant            []roleGrantVector            `json:"role_grant"`
	SuccessorDesignation []successorDesignationVector `json:"successor_designation"`
	SuccessorClaim       []successorClaimVector       `json:"successor_claim"`
	RotationStart        []rotationStartVector        `json:"rotation_start"`
	RotationRekey        []rotationRekeyVector        `json:"rotation_rekey"`
	WrapRecord           []wrapRecordVector           `json:"wrap_record"`
	Admission            []admissionVector            `json:"admission"`
	Pin                  []pinVector                  `json:"pin"`
	Verification         []verificationVector         `json:"verification"`
	KeyRotation          []keyRotationVector          `json:"key_rotation"`
	HandoffWrap          []handoffWrapVector          `json:"handoff_wrap_aad"`
	MemberWrap           []memberWrapVector           `json:"member_wrap_aad"`
	GroupName            []groupNameVector            `json:"group_name_aad"`
	PostAAD              []postAADVector              `json:"post_aad"`
	CommentAAD           []commentAADVector           `json:"comment_aad"`
	InviteCreation       []inviteCreationVector       `json:"invite_creation"`
	InviteAcceptance     []inviteAcceptanceVector     `json:"invite_acceptance"`
	InviteMAC            []inviteMACVector            `json:"invite_mac"`
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
	GroupID         string `json:"group_id"`
	Generation      uint64 `json:"generation"`
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

type keyBundleVector struct {
	Name               string `json:"name"`
	SigningSeedHex     string `json:"signing_seed_hex"`
	WrappingPrivKeyHex string `json:"wrapping_private_key_hex"`
	EncodedHex         string `json:"encoded_hex"`
}

type trustAnchorVector struct {
	Name         string `json:"name"`
	PrivateHex   string `json:"private_key_hex"`
	PublicHex    string `json:"public_key_hex"`
	CreatorUUID  string `json:"creator_uuid"`
	GroupID      string `json:"group_id"`
	PayloadHex   string `json:"payload_hex"`
	SignatureHex string `json:"signature_hex"`
}

type roleGrantVector struct {
	Name            string `json:"name"`
	PrivateHex      string `json:"private_key_hex"`
	PublicHex       string `json:"public_key_hex"`
	GroupID         string `json:"group_id"`
	SubjectUUID     string `json:"subject_uuid"`
	Role            string `json:"role"`
	GrantSortKey    string `json:"grant_sort_key"`
	GrantorGrantRef string `json:"grantor_grant_ref"`
	PayloadHex      string `json:"payload_hex"`
	SignatureHex    string `json:"signature_hex"`
}

type successorDesignationVector struct {
	Name               string `json:"name"`
	PrivateHex         string `json:"private_key_hex"`
	PublicHex          string `json:"public_key_hex"`
	GroupID            string `json:"group_id"`
	AdminUUID          string `json:"admin_uuid"`
	SuccessorUUID      string `json:"successor_uuid"`
	PeriodDays         int    `json:"period_days"`
	DesignationSortKey string `json:"designation_sort_key"`
	AdminGrantRef      string `json:"admin_grant_ref"`
	PayloadHex         string `json:"payload_hex"`
	SignatureHex       string `json:"signature_hex"`
}

type rotationStartVector struct {
	Name         string `json:"name"`
	PrivateHex   string `json:"private_key_hex"`
	PublicHex    string `json:"public_key_hex"`
	GroupID      string `json:"group_id"`
	RemoverUUID  string `json:"remover_uuid"`
	SubjectUUID  string `json:"subject_uuid"`
	Generation   int64  `json:"generation"`
	PayloadHex   string `json:"payload_hex"`
	SignatureHex string `json:"signature_hex"`
}

type rotationRekeyVector struct {
	Name         string `json:"name"`
	PrivateHex   string `json:"private_key_hex"`
	PublicHex    string `json:"public_key_hex"`
	GroupID      string `json:"group_id"`
	AdminUUID    string `json:"admin_uuid"`
	MemberUUID   string `json:"member_uuid"`
	Generation   int64  `json:"generation"`
	Reason       string `json:"reason"`
	PayloadHex   string `json:"payload_hex"`
	SignatureHex string `json:"signature_hex"`
}

type wrapRecordVector struct {
	Name         string `json:"name"`
	PrivateHex   string `json:"private_key_hex"`
	PublicHex    string `json:"public_key_hex"`
	GroupID      string `json:"group_id"`
	WrapperUUID  string `json:"wrapper_uuid"`
	MemberUUID   string `json:"member_uuid"`
	Generation   int64  `json:"generation"`
	KeyEpoch     uint64 `json:"key_epoch"`
	Reason       string `json:"reason"`
	Day          string `json:"day"`
	PayloadHex   string `json:"payload_hex"`
	SignatureHex string `json:"signature_hex"`
}

type admissionVector struct {
	Name            string `json:"name"`
	PrivateHex      string `json:"private_key_hex"`
	PublicHex       string `json:"public_key_hex"`
	GroupID         string `json:"group_id"`
	InviterUUID     string `json:"inviter_uuid"`
	InviteeUUID     string `json:"invitee_uuid"`
	InviteeEdHex    string `json:"invitee_ed25519_hex"`
	InviteeXHex     string `json:"invitee_x25519_hex"`
	InviteID        string `json:"invite_id"`
	InviterGrantRef string `json:"inviter_grant_ref"`
	Day             string `json:"day"`
	Generation      int64  `json:"generation"`
	PayloadHex      string `json:"payload_hex"`
	SignatureHex    string `json:"signature_hex"`
}

type successorClaimVector struct {
	Name               string `json:"name"`
	PrivateHex         string `json:"private_key_hex"`
	PublicHex          string `json:"public_key_hex"`
	GroupID            string `json:"group_id"`
	SuccessorUUID      string `json:"successor_uuid"`
	DesignationSortKey string `json:"designation_sort_key"`
	ClaimSortKey       string `json:"claim_sort_key"`
	PayloadHex         string `json:"payload_hex"`
	SignatureHex       string `json:"signature_hex"`
}

type pinVector struct {
	Name              string   `json:"name"`
	PrivateHex        string   `json:"private_key_hex"`
	PublicHex         string   `json:"public_key_hex"`
	PinnerUUID        string   `json:"pinner_uuid"`
	PinnedUUID        string   `json:"pinned_uuid"`
	WrappingPublicHex string   `json:"wrapping_public_key_hex"`
	SigningKeysHex    []string `json:"signing_keys_hex"`
	KeyEpoch          uint64   `json:"key_epoch"`
	SignedDay         string   `json:"signed_day"`
	PayloadHex        string   `json:"payload_hex"`
	SignatureHex      string   `json:"signature_hex"`
}

type verificationVector struct {
	Name            string `json:"name"`
	PrivateHex      string `json:"private_key_hex"`
	PublicHex       string `json:"public_key_hex"`
	VerifierUUID    string `json:"verifier_uuid"`
	VerifiedUUID    string `json:"verified_uuid"`
	VerifiedSignHex string `json:"verified_signing_public_key_hex"`
	VerifiedWrapHex string `json:"verified_wrapping_public_key_hex"`
	Fingerprint     string `json:"fingerprint"`
	SignedDay       string `json:"signed_day"`
	PayloadHex      string `json:"payload_hex"`
	SignatureHex    string `json:"signature_hex"`
}

type keyRotationVector struct {
	Name            string      `json:"name"`
	UserUUID        string      `json:"user_uuid"`
	OldPrivateHex   string      `json:"old_private_key_hex"`
	OldSigningHex   string      `json:"old_signing_public_key_hex"`
	OldWrappingHex  string      `json:"old_wrapping_public_key_hex"`
	NewPrivateHex   string      `json:"new_private_key_hex"`
	NewSigningHex   string      `json:"new_signing_public_key_hex"`
	NewWrappingHex  string      `json:"new_wrapping_public_key_hex"`
	UTCDay          string      `json:"utc_day"`
	KeyEpoch        uint64      `json:"key_epoch"`
	RosterRows      []rosterRow `json:"roster_rows"`
	RosterDigestHex string      `json:"roster_digest_hex"`
	PayloadHex      string      `json:"payload_hex"`
	OldSignatureHex string      `json:"old_signature_hex"`
	NewSignatureHex string      `json:"new_signature_hex"`
}

type rosterRow struct {
	SK           string `json:"sk"`
	SignatureHex string `json:"signature_hex"`
	EntryIDHex   string `json:"entry_id_hex"`
}

type handoffWrapVector struct {
	Name                 string `json:"name"`
	UserUUID             string `json:"user_uuid"`
	GroupID              string `json:"group_id"`
	Generation           uint64 `json:"generation"`
	NewWrappingPublicHex string `json:"new_wrapping_public_key_hex"`
	AADHex               string `json:"aad_hex"`
	KeyHex               string `json:"key_hex"`
	PlaintextHex         string `json:"plaintext_hex"`
	NonceHex             string `json:"nonce_hex"`
	CiphertextHex        string `json:"ciphertext_hex"`
}

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

type postAADVector struct {
	Name          string `json:"name"`
	GroupID       string `json:"group_id"`
	SortKey       string `json:"sort_key"`
	Generation    uint64 `json:"generation"`
	AADHex        string `json:"aad_hex"`
	KeyHex        string `json:"key_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	NonceHex      string `json:"nonce_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

type commentAADVector struct {
	Name          string `json:"name"`
	PostID        string `json:"post_id"`
	Path          string `json:"path"`
	Generation    uint64 `json:"generation"`
	AADHex        string `json:"aad_hex"`
	KeyHex        string `json:"key_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	NonceHex      string `json:"nonce_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

type inviteCreationVector struct {
	Name         string `json:"name"`
	PrivateHex   string `json:"private_key_hex"`
	PublicHex    string `json:"public_key_hex"`
	InviteID     string `json:"invite_id"`
	GroupID      string `json:"group_id"`
	ExpiresAt    string `json:"expires_at"`
	PayloadHex   string `json:"payload_hex"`
	SignatureHex string `json:"signature_hex"`
}

type inviteAcceptanceVector struct {
	Name                 string `json:"name"`
	PrivateHex           string `json:"private_key_hex"`
	PublicHex            string `json:"public_key_hex"`
	InviteID             string `json:"invite_id"`
	InvitedEd25519PubHex string `json:"invited_ed25519_pub_hex"`
	InvitedX25519PubHex  string `json:"invited_x25519_pub_hex"`
	PayloadHex           string `json:"payload_hex"`
	SignatureHex         string `json:"signature_hex"`
}

// inviteMACVector proves DeriveInviteMACKey/ComputeInviteMAC's exact
// encoding (PR #146 round-1 review's blocking finding #1) -- see
// crypto.DeriveInviteMACKey's own doc comment for the full reasoning.
type inviteMACVector struct {
	Name                 string `json:"name"`
	InviterSeedHex       string `json:"inviter_seed_hex"`
	InviteID             string `json:"invite_id"`
	InvitedEd25519PubHex string `json:"invited_ed25519_pub_hex"`
	InvitedX25519PubHex  string `json:"invited_x25519_pub_hex"`
	MACKeyHex            string `json:"mac_key_hex"`
	PayloadHex           string `json:"payload_hex"`
	MACHex               string `json:"mac_hex"`
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
			if got := GenKeyAAD(tc.GroupID, tc.Generation); !bytes.Equal(got, aad) {
				t.Fatalf("GenKeyAAD(%q, %d) = %q, want %q", tc.GroupID, tc.Generation, got, aad)
			}
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

// TestVectorCredentialWrap pins CredentialWrapAAD's exact encoding -- see
// that function's own doc comment for why this specific AAD, unlike every
// other one in this package, had no code fixing its byte format before #30
// needed one. Proves both the encoding itself and, by running the
// AES-256-GCM round trip through it, that a client unwrapping under the
// wrong copy's AAD (PROFILE's AAD against RECOVERY's ciphertext or vice
// versa) fails the way any other address-relocation attempt does.
func TestVectorCredentialWrap(t *testing.T) {
	v := loadVectors(t)
	if len(v.CredentialWrap) < 2 {
		t.Fatalf("expected at least 2 credential_wrap vectors (profile, recovery), got %d", len(v.CredentialWrap))
	}
	for _, tc := range v.CredentialWrap {
		t.Run(tc.Name, func(t *testing.T) {
			wantAAD := mustHex(t, tc.AADHex)
			gotAAD := CredentialWrapAAD(tc.UserID, CredentialCopy(tc.Copy))
			if !bytes.Equal(gotAAD, wantAAD) {
				t.Fatalf("CredentialWrapAAD(%q, %q) = %x, want %x", tc.UserID, tc.Copy, gotAAD, wantAAD)
			}

			key := mustHex(t, tc.KeyHex)
			nonce := mustHex(t, tc.NonceHex)
			plaintext := mustHex(t, tc.PlaintextHex)
			wantCiphertext := mustHex(t, tc.CiphertextHex)

			gotCiphertext, err := EncryptWithNonce(key, nonce, plaintext, gotAAD)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotCiphertext, wantCiphertext) {
				t.Fatalf("EncryptWithNonce = %x, want %x", gotCiphertext, wantCiphertext)
			}

			decrypted, err := Decrypt(key, nonce, wantCiphertext, gotAAD)
			if err != nil {
				t.Fatalf("Decrypt with matching copy's AAD: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("Decrypt = %x, want %x", decrypted, plaintext)
			}
		})
	}

	// Cross-copy negative case: PROFILE's ciphertext must not decrypt under
	// RECOVERY's AAD for the same user, and vice versa -- the exact
	// relocation this AAD exists to stop, per docs/DESIGN.md's AAD table.
	profile := v.CredentialWrap[0]
	recovery := v.CredentialWrap[1]
	if profile.Copy != string(CredentialCopyProfile) || recovery.Copy != string(CredentialCopyRecovery) {
		t.Fatalf("unexpected vector order: [0]=%q [1]=%q, want [PROFILE, RECOVERY]", profile.Copy, recovery.Copy)
	}
	key := mustHex(t, profile.KeyHex)
	nonce := mustHex(t, profile.NonceHex)
	profileCiphertext := mustHex(t, profile.CiphertextHex)
	recoveryAAD := mustHex(t, recovery.AADHex)
	if _, err := Decrypt(key, nonce, profileCiphertext, recoveryAAD); err != ErrDecryptionFailed {
		t.Fatalf("decrypting PROFILE's ciphertext under RECOVERY's AAD: got err %v, want ErrDecryptionFailed", err)
	}
}

// TestVectorKeyBundle pins EncodeKeyBundle's exact plaintext layout -- see
// keybundle.go's own doc comment for why this, like the credential-wrap AAD
// before it, needed a fixed cross-implementation vector rather than being
// left to whatever each side happened to guess.
func TestVectorKeyBundle(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.KeyBundle {
		t.Run(tc.Name, func(t *testing.T) {
			bundle := KeyBundle{
				SigningSeed:        mustHex(t, tc.SigningSeedHex),
				WrappingPrivateKey: mustHex(t, tc.WrappingPrivKeyHex),
			}
			want := mustHex(t, tc.EncodedHex)

			got, err := EncodeKeyBundle(bundle)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("EncodeKeyBundle = %x, want %x", got, want)
			}

			decoded, err := DecodeKeyBundle(want)
			if err != nil {
				t.Fatalf("DecodeKeyBundle: %v", err)
			}
			if !bytes.Equal(decoded.SigningSeed, bundle.SigningSeed) {
				t.Fatalf("decoded SigningSeed = %x, want %x", decoded.SigningSeed, bundle.SigningSeed)
			}
			if !bytes.Equal(decoded.WrappingPrivateKey, bundle.WrappingPrivateKey) {
				t.Fatalf("decoded WrappingPrivateKey = %x, want %x", decoded.WrappingPrivateKey, bundle.WrappingPrivateKey)
			}
		})
	}
}

// TestVectorTrustAnchor pins TrustAnchorPayload's exact encoding -- issue
// #34, the same reasoning TestVectorSignedPayload gives for posts and
// comments: a group's root of trust is verified by every future member's
// client, so this payload must produce byte-identical output in Go and
// TypeScript before any real group exists under it.
func TestVectorTrustAnchor(t *testing.T) {
	v := loadVectors(t)
	if len(v.TrustAnchor) == 0 {
		t.Fatal("expected at least 1 trust_anchor vector")
	}
	for _, tc := range v.TrustAnchor {
		t.Run(tc.Name, func(t *testing.T) {
			pub := mustHex(t, tc.PublicHex)
			priv := ed25519.PrivateKey(mustHex(t, tc.PrivateHex))
			wantPayload := mustHex(t, tc.PayloadHex)
			wantSig := mustHex(t, tc.SignatureHex)

			gotPayload := TrustAnchorPayload(tc.CreatorUUID, pub, tc.GroupID)
			if !bytes.Equal(gotPayload, wantPayload) {
				t.Fatalf("TrustAnchorPayload = %x, want %x", gotPayload, wantPayload)
			}

			gotSig, err := Sign(priv, ContextTrustAnchor, gotPayload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSig, wantSig) {
				t.Fatalf("Sign = %x, want %x", gotSig, wantSig)
			}
			if !Verify(pub, ContextTrustAnchor, wantPayload, wantSig) {
				t.Fatal("Verify rejected the vector's own signature over TrustAnchorPayload")
			}
		})
	}
}

// TestVectorRoleGrant pins RoleGrantPayload's exact encoding, for both the
// root-grant shape (empty grantorGrantRef) and a non-root grant referencing
// a real predecessor.
func TestVectorRoleGrant(t *testing.T) {
	v := loadVectors(t)
	if len(v.RoleGrant) < 2 {
		t.Fatalf("expected at least 2 role_grant vectors (root, non_root), got %d", len(v.RoleGrant))
	}
	for _, tc := range v.RoleGrant {
		t.Run(tc.Name, func(t *testing.T) {
			pub := mustHex(t, tc.PublicHex)
			priv := ed25519.PrivateKey(mustHex(t, tc.PrivateHex))
			wantPayload := mustHex(t, tc.PayloadHex)
			wantSig := mustHex(t, tc.SignatureHex)

			gotPayload := RoleGrantPayload(tc.GroupID, tc.SubjectUUID, tc.Role, tc.GrantSortKey, tc.GrantorGrantRef)
			if !bytes.Equal(gotPayload, wantPayload) {
				t.Fatalf("RoleGrantPayload = %x, want %x", gotPayload, wantPayload)
			}

			gotSig, err := Sign(priv, ContextRoleGrant, gotPayload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSig, wantSig) {
				t.Fatalf("Sign = %x, want %x", gotSig, wantSig)
			}
			if !Verify(pub, ContextRoleGrant, wantPayload, wantSig) {
				t.Fatal("Verify rejected the vector's own signature over RoleGrantPayload")
			}
		})
	}
}

// TestVectorSuccessorDesignation pins SuccessorDesignationPayload's exact
// encoding for a named successor and for the revocation form (empty successor).
func TestVectorSuccessorDesignation(t *testing.T) {
	v := loadVectors(t)
	if len(v.SuccessorDesignation) < 2 {
		t.Fatalf("expected at least 2 successor_designation vectors (named, revocation), got %d", len(v.SuccessorDesignation))
	}
	for _, tc := range v.SuccessorDesignation {
		t.Run(tc.Name, func(t *testing.T) {
			pub := mustHex(t, tc.PublicHex)
			priv := ed25519.PrivateKey(mustHex(t, tc.PrivateHex))
			wantPayload := mustHex(t, tc.PayloadHex)
			wantSig := mustHex(t, tc.SignatureHex)

			gotPayload := SuccessorDesignationPayload(tc.GroupID, tc.AdminUUID, tc.SuccessorUUID, tc.PeriodDays, tc.DesignationSortKey, tc.AdminGrantRef)
			if !bytes.Equal(gotPayload, wantPayload) {
				t.Fatalf("SuccessorDesignationPayload = %x, want %x", gotPayload, wantPayload)
			}
			gotSig, err := Sign(priv, ContextSuccessorDesignation, gotPayload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSig, wantSig) {
				t.Fatalf("Sign = %x, want %x", gotSig, wantSig)
			}
			if !Verify(pub, ContextSuccessorDesignation, wantPayload, wantSig) {
				t.Fatal("Verify rejected the vector's own signature")
			}
			// A designation must not verify as a claim or a role grant.
			if Verify(pub, ContextSuccessorClaim, wantPayload, wantSig) || Verify(pub, ContextRoleGrant, wantPayload, wantSig) {
				t.Fatal("designation signature verified under another context")
			}
		})
	}
}

// TestVectorSuccessorClaim pins SuccessorClaimPayload's exact encoding.
func TestVectorSuccessorClaim(t *testing.T) {
	v := loadVectors(t)
	if len(v.SuccessorClaim) < 1 {
		t.Fatal("expected at least 1 successor_claim vector")
	}
	for _, tc := range v.SuccessorClaim {
		t.Run(tc.Name, func(t *testing.T) {
			pub := mustHex(t, tc.PublicHex)
			priv := ed25519.PrivateKey(mustHex(t, tc.PrivateHex))
			wantPayload := mustHex(t, tc.PayloadHex)
			wantSig := mustHex(t, tc.SignatureHex)

			gotPayload := SuccessorClaimPayload(tc.GroupID, tc.SuccessorUUID, tc.DesignationSortKey, tc.ClaimSortKey)
			if !bytes.Equal(gotPayload, wantPayload) {
				t.Fatalf("SuccessorClaimPayload = %x, want %x", gotPayload, wantPayload)
			}
			gotSig, err := Sign(priv, ContextSuccessorClaim, gotPayload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSig, wantSig) {
				t.Fatalf("Sign = %x, want %x", gotSig, wantSig)
			}
			if !Verify(pub, ContextSuccessorClaim, wantPayload, wantSig) {
				t.Fatal("Verify rejected the vector's own signature")
			}
			if Verify(pub, ContextSuccessorDesignation, wantPayload, wantSig) || Verify(pub, ContextRoleGrant, wantPayload, wantSig) {
				t.Fatal("claim signature verified under another context")
			}
		})
	}
}

// TestVectorRotationStart pins RotationStartPayload's exact encoding (#178).
func TestVectorRotationStart(t *testing.T) {
	v := loadVectors(t)
	if len(v.RotationStart) < 1 {
		t.Fatal("expected at least 1 rotation_start vector")
	}
	for _, tc := range v.RotationStart {
		t.Run(tc.Name, func(t *testing.T) {
			pub := mustHex(t, tc.PublicHex)
			priv := ed25519.PrivateKey(mustHex(t, tc.PrivateHex))
			wantPayload := mustHex(t, tc.PayloadHex)
			wantSig := mustHex(t, tc.SignatureHex)

			gotPayload := RotationStartPayload(tc.GroupID, tc.RemoverUUID, tc.SubjectUUID, tc.Generation)
			if !bytes.Equal(gotPayload, wantPayload) {
				t.Fatalf("RotationStartPayload = %x, want %x", gotPayload, wantPayload)
			}
			gotSig, err := Sign(priv, ContextRotationStart, gotPayload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSig, wantSig) {
				t.Fatalf("Sign = %x, want %x", gotSig, wantSig)
			}
			if !Verify(pub, ContextRotationStart, wantPayload, wantSig) {
				t.Fatal("Verify rejected the vector's own signature")
			}
			if Verify(pub, ContextRoleGrant, wantPayload, wantSig) || Verify(pub, ContextSuccessorClaim, wantPayload, wantSig) {
				t.Fatal("rotation-start signature verified under another context")
			}
		})
	}
}

// TestVectorRotationRekey pins RotationRekeyPayload's exact encoding (#62).
func TestVectorRotationRekey(t *testing.T) {
	v := loadVectors(t)
	if len(v.RotationRekey) < 2 {
		t.Fatalf("expected at least 2 rotation_rekey vectors, got %d", len(v.RotationRekey))
	}
	seen := map[string]bool{}
	for _, tc := range v.RotationRekey {
		t.Run(tc.Name, func(t *testing.T) {
			pub := mustHex(t, tc.PublicHex)
			priv := ed25519.PrivateKey(mustHex(t, tc.PrivateHex))
			wantPayload := mustHex(t, tc.PayloadHex)
			wantSig := mustHex(t, tc.SignatureHex)

			gotPayload := RotationRekeyPayload(tc.GroupID, tc.AdminUUID, tc.MemberUUID, tc.Generation, tc.Reason)
			if !bytes.Equal(gotPayload, wantPayload) {
				t.Fatalf("RotationRekeyPayload = %x, want %x", gotPayload, wantPayload)
			}
			seen[tc.PayloadHex] = true
			gotSig, err := Sign(priv, ContextRotationRekey, gotPayload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSig, wantSig) {
				t.Fatalf("Sign = %x, want %x", gotSig, wantSig)
			}
			if !Verify(pub, ContextRotationRekey, wantPayload, wantSig) {
				t.Fatal("Verify rejected the vector's own signature")
			}
			if Verify(pub, ContextRotationStart, wantPayload, wantSig) || Verify(pub, ContextRoleGrant, wantPayload, wantSig) {
				t.Fatal("rotation-rekey signature verified under another context")
			}
		})
	}
	if len(seen) != len(v.RotationRekey) {
		t.Fatal("rekey vectors with different members or reasons must produce different payloads")
	}
}

// TestVectorAdmission pins AdmissionPayload's exact encoding (#178).
func TestVectorAdmission(t *testing.T) {
	v := loadVectors(t)
	if len(v.Admission) < 3 {
		t.Fatalf("expected at least 3 admission vectors, got %d", len(v.Admission))
	}
	seen := map[string]bool{}
	for _, tc := range v.Admission {
		t.Run(tc.Name, func(t *testing.T) {
			pub := mustHex(t, tc.PublicHex)
			priv := ed25519.PrivateKey(mustHex(t, tc.PrivateHex))
			wantPayload := mustHex(t, tc.PayloadHex)
			wantSig := mustHex(t, tc.SignatureHex)

			gotPayload := AdmissionPayload(tc.GroupID, tc.InviterUUID, tc.InviteeUUID,
				mustHex(t, tc.InviteeEdHex), mustHex(t, tc.InviteeXHex), tc.InviteID, tc.InviterGrantRef, tc.Day, tc.Generation)
			if !bytes.Equal(gotPayload, wantPayload) {
				t.Fatalf("AdmissionPayload = %x, want %x", gotPayload, wantPayload)
			}
			seen[tc.PayloadHex] = true
			gotSig, err := Sign(priv, ContextAdmission, gotPayload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSig, wantSig) {
				t.Fatalf("Sign = %x, want %x", gotSig, wantSig)
			}
			if !Verify(pub, ContextAdmission, wantPayload, wantSig) {
				t.Fatal("Verify rejected the vector's own signature")
			}
			if Verify(pub, ContextRoleGrant, wantPayload, wantSig) || Verify(pub, ContextRotationStart, wantPayload, wantSig) {
				t.Fatal("admission signature verified under another context")
			}
		})
	}
	if len(seen) != len(v.Admission) {
		t.Fatal("admission vectors with different grant refs or generations must produce different payloads")
	}
}

// TestVectorPin pins PinPayload's exact encoding, including that the signing
// key set is order-independent (two vectors list the same keys in different
// orders and must share a payload).
func TestVectorPin(t *testing.T) {
	v := loadVectors(t)
	if len(v.Pin) != 4 {
		t.Fatalf("expected 4 pin vectors, got %d", len(v.Pin))
	}
	for _, tc := range v.Pin {
		t.Run(tc.Name, func(t *testing.T) {
			pub := mustHex(t, tc.PublicHex)
			priv := ed25519.PrivateKey(mustHex(t, tc.PrivateHex))
			wantPayload := mustHex(t, tc.PayloadHex)
			wantSig := mustHex(t, tc.SignatureHex)
			var keys [][]byte
			for _, k := range tc.SigningKeysHex {
				keys = append(keys, mustHex(t, k))
			}

			gotPayload := PinPayload(tc.PinnerUUID, tc.PinnedUUID, pub, mustHex(t, tc.WrappingPublicHex), keys, tc.KeyEpoch, tc.SignedDay)
			if !bytes.Equal(gotPayload, wantPayload) {
				t.Fatalf("PinPayload = %x, want %x", gotPayload, wantPayload)
			}
			gotSig, err := Sign(priv, ContextPin, gotPayload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSig, wantSig) {
				t.Fatalf("Sign = %x, want %x", gotSig, wantSig)
			}
			if !Verify(pub, ContextPin, wantPayload, wantSig) {
				t.Fatal("Verify rejected the vector's own signature over PinPayload")
			}
			if Verify(pub, SigningContext("underground-bb:pin:v1"), wantPayload, wantSig) {
				t.Fatal("a v2 pin signature must not verify under the v1 context")
			}
		})
	}
	if v.Pin[0].PayloadHex != v.Pin[1].PayloadHex {
		t.Fatal("same key set in a different order must produce the same payload")
	}
	if v.Pin[0].PayloadHex == v.Pin[2].PayloadHex {
		t.Fatal("a different key set must produce a different payload")
	}
	if v.Pin[0].PayloadHex == v.Pin[3].PayloadHex {
		t.Fatal("a different pinned KeyEpoch must produce a different payload")
	}
}

// TestVectorVerification pins VerificationPayload's exact encoding (#65), and
// that the signed fingerprint is the one Fingerprint computes for the keys.
func TestVectorVerification(t *testing.T) {
	v := loadVectors(t)
	if len(v.Verification) != 2 {
		t.Fatalf("want 2 verification vectors, got %d", len(v.Verification))
	}
	for _, tc := range v.Verification {
		t.Run(tc.Name, func(t *testing.T) {
			pub := mustHex(t, tc.PublicHex)
			priv := ed25519.PrivateKey(mustHex(t, tc.PrivateHex))
			wantPayload := mustHex(t, tc.PayloadHex)
			wantSig := mustHex(t, tc.SignatureHex)

			fp, err := Fingerprint(mustHex(t, tc.VerifiedSignHex), mustHex(t, tc.VerifiedWrapHex))
			if err != nil {
				t.Fatal(err)
			}
			if fp != tc.Fingerprint {
				t.Fatalf("Fingerprint = %q, want %q", fp, tc.Fingerprint)
			}
			gotPayload := VerificationPayload(tc.VerifierUUID, tc.VerifiedUUID, pub, tc.Fingerprint, tc.SignedDay)
			if !bytes.Equal(gotPayload, wantPayload) {
				t.Fatalf("VerificationPayload = %x, want %x", gotPayload, wantPayload)
			}
			gotSig, err := Sign(priv, ContextVerification, gotPayload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSig, wantSig) {
				t.Fatalf("Sign = %x, want %x", gotSig, wantSig)
			}
			if !Verify(pub, ContextVerification, wantPayload, wantSig) {
				t.Fatal("Verify rejected the vector's own signature over VerificationPayload")
			}
			if Verify(pub, ContextPin, wantPayload, wantSig) {
				t.Fatal("a verification signature must not verify under the pin context")
			}
			if Verify(pub, SigningContext("underground-bb:verification:v1"), wantPayload, wantSig) {
				t.Fatal("a v2 verification signature must not verify under the v1 context")
			}
		})
	}
	if v.Verification[0].PayloadHex == v.Verification[1].PayloadHex {
		t.Fatal("different verified users must produce different payloads")
	}
}

// TestVectorMemberWrap pins MemberWrapAAD's exact encoding -- see
// TestVectorCredentialWrap for the identical reasoning applied to a
// different AAD.
func TestVectorMemberWrap(t *testing.T) {
	v := loadVectors(t)
	if len(v.MemberWrap) == 0 {
		t.Fatal("expected at least 1 member_wrap_aad vector")
	}
	for _, tc := range v.MemberWrap {
		t.Run(tc.Name, func(t *testing.T) {
			wantAAD := mustHex(t, tc.AADHex)
			gotAAD := MemberWrapAAD(tc.GroupID, tc.MemberUUID, tc.Generation)
			if !bytes.Equal(gotAAD, wantAAD) {
				t.Fatalf("MemberWrapAAD(%q, %q, %d) = %x, want %x", tc.GroupID, tc.MemberUUID, tc.Generation, gotAAD, wantAAD)
			}

			key := mustHex(t, tc.KeyHex)
			nonce := mustHex(t, tc.NonceHex)
			plaintext := mustHex(t, tc.PlaintextHex)
			wantCiphertext := mustHex(t, tc.CiphertextHex)

			gotCiphertext, err := EncryptWithNonce(key, nonce, plaintext, gotAAD)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotCiphertext, wantCiphertext) {
				t.Fatalf("EncryptWithNonce = %x, want %x", gotCiphertext, wantCiphertext)
			}

			decrypted, err := Decrypt(key, nonce, gotCiphertext, gotAAD)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("Decrypt = %x, want %x", decrypted, plaintext)
			}
		})
	}
}

// TestVectorPostAAD pins PostAAD's exact encoding (#42), and that a post
// ciphertext does not open under another generation's AAD.
func TestVectorPostAAD(t *testing.T) {
	v := loadVectors(t)
	if len(v.PostAAD) < 2 {
		t.Fatalf("expected at least 2 post_aad vectors, got %d", len(v.PostAAD))
	}
	for _, tc := range v.PostAAD {
		t.Run(tc.Name, func(t *testing.T) {
			wantAAD := mustHex(t, tc.AADHex)
			gotAAD := PostAAD(tc.GroupID, tc.SortKey, tc.Generation)
			if !bytes.Equal(gotAAD, wantAAD) {
				t.Fatalf("PostAAD = %x, want %x", gotAAD, wantAAD)
			}
			key, nonce := mustHex(t, tc.KeyHex), mustHex(t, tc.NonceHex)
			plaintext := mustHex(t, tc.PlaintextHex)
			got, err := EncryptWithNonce(key, nonce, plaintext, gotAAD)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, mustHex(t, tc.CiphertextHex)) {
				t.Fatalf("EncryptWithNonce = %x, want %s", got, tc.CiphertextHex)
			}
			if _, err := Decrypt(key, nonce, got, PostAAD(tc.GroupID, tc.SortKey, tc.Generation+1)); err == nil {
				t.Fatal("opened under another generation's AAD")
			}
			if _, err := Decrypt(key, nonce, got, PostAAD(tc.GroupID, "POST#2026-10-29#00112233445566ff", tc.Generation)); err == nil {
				t.Fatal("opened under another day's sort key")
			}
		})
	}
}

// TestVectorCommentAAD pins CommentAAD's exact encoding (#44), and that a
// comment ciphertext does not open when moved to another generation, another
// path or another post.
func TestVectorCommentAAD(t *testing.T) {
	v := loadVectors(t)
	if len(v.CommentAAD) < 2 {
		t.Fatalf("expected at least 2 comment_aad vectors, got %d", len(v.CommentAAD))
	}
	for _, tc := range v.CommentAAD {
		t.Run(tc.Name, func(t *testing.T) {
			wantAAD := mustHex(t, tc.AADHex)
			gotAAD := CommentAAD(tc.PostID, tc.Path, tc.Generation)
			if !bytes.Equal(gotAAD, wantAAD) {
				t.Fatalf("CommentAAD = %x, want %x", gotAAD, wantAAD)
			}
			key, nonce := mustHex(t, tc.KeyHex), mustHex(t, tc.NonceHex)
			plaintext := mustHex(t, tc.PlaintextHex)
			got, err := EncryptWithNonce(key, nonce, plaintext, gotAAD)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, mustHex(t, tc.CiphertextHex)) {
				t.Fatalf("EncryptWithNonce = %x, want %s", got, tc.CiphertextHex)
			}
			for name, other := range map[string][]byte{
				"another generation": CommentAAD(tc.PostID, tc.Path, tc.Generation+1),
				"another path":       CommentAAD(tc.PostID, "0009", tc.Generation),
				"another post":       CommentAAD("group-uuid-2#2026-10-29#00112233445566ff", tc.Path, tc.Generation),
				"as a post":          PostAAD("group-uuid-2", "POST#2026-10-28#00112233445566ff", tc.Generation),
			} {
				if _, err := Decrypt(key, nonce, got, other); err == nil {
					t.Fatalf("opened under %s", name)
				}
			}
		})
	}
}

// TestVectorGroupName pins GroupNameAAD's exact encoding, for both the name
// and description fields -- proving the two produce genuinely different
// AAD, the same shape TestVectorCredentialWrap proves for PROFILE vs.
// RECOVERY.
func TestVectorGroupName(t *testing.T) {
	v := loadVectors(t)
	if len(v.GroupName) < 2 {
		t.Fatalf("expected at least 2 group_name_aad vectors (name, description), got %d", len(v.GroupName))
	}
	for _, tc := range v.GroupName {
		t.Run(tc.Name, func(t *testing.T) {
			wantAAD := mustHex(t, tc.AADHex)
			gotAAD := GroupNameAAD(tc.GroupID, GroupTextField(tc.Field), tc.Generation)
			if !bytes.Equal(gotAAD, wantAAD) {
				t.Fatalf("GroupNameAAD(%q, %q, %d) = %x, want %x", tc.GroupID, tc.Field, tc.Generation, gotAAD, wantAAD)
			}

			key := mustHex(t, tc.KeyHex)
			nonce := mustHex(t, tc.NonceHex)
			plaintext := mustHex(t, tc.PlaintextHex)
			wantCiphertext := mustHex(t, tc.CiphertextHex)

			gotCiphertext, err := EncryptWithNonce(key, nonce, plaintext, gotAAD)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotCiphertext, wantCiphertext) {
				t.Fatalf("EncryptWithNonce = %x, want %x", gotCiphertext, wantCiphertext)
			}

			decrypted, err := Decrypt(key, nonce, gotCiphertext, gotAAD)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("Decrypt = %x, want %x", decrypted, plaintext)
			}
		})
	}

	t.Run("cross-field AAD must fail (name ciphertext under description AAD)", func(t *testing.T) {
		var nameVec, descVec *groupNameVector
		for i := range v.GroupName {
			switch v.GroupName[i].Field {
			case "NAME":
				nameVec = &v.GroupName[i]
			case "DESC":
				descVec = &v.GroupName[i]
			}
		}
		if nameVec == nil || descVec == nil {
			t.Fatal("expected both NAME and DESC vectors")
		}
		key := mustHex(t, nameVec.KeyHex)
		nonce := mustHex(t, nameVec.NonceHex)
		nameCiphertext := mustHex(t, nameVec.CiphertextHex)
		descAAD := mustHex(t, descVec.AADHex)

		if _, err := Decrypt(key, nonce, nameCiphertext, descAAD); err == nil {
			t.Fatal("Decrypt succeeded with the wrong field's AAD, want failure")
		}
	})
}

// TestVectorInviteCreation pins InviteCreationPayload's exact encoding --
// issue #38, the invite handshake's step-1 signed payload. Every future
// invitee's client verifies this signature before trusting the invite (or
// the inviter's identity it claims), so the encoding must be byte-identical
// in Go and TypeScript before any real invite exists under it. There is
// deliberately no ephemeral_pubkey field -- see docs/DESIGN.md's now-
// resolved open question.
func TestVectorInviteCreation(t *testing.T) {
	v := loadVectors(t)
	if len(v.InviteCreation) == 0 {
		t.Fatal("expected at least 1 invite_creation vector")
	}
	for _, tc := range v.InviteCreation {
		t.Run(tc.Name, func(t *testing.T) {
			pub := mustHex(t, tc.PublicHex)
			priv := ed25519.PrivateKey(mustHex(t, tc.PrivateHex))
			wantPayload := mustHex(t, tc.PayloadHex)
			wantSig := mustHex(t, tc.SignatureHex)

			gotPayload := InviteCreationPayload(tc.InviteID, tc.GroupID, pub, tc.ExpiresAt)
			if !bytes.Equal(gotPayload, wantPayload) {
				t.Fatalf("InviteCreationPayload = %x, want %x", gotPayload, wantPayload)
			}

			gotSig, err := Sign(priv, ContextInvite, gotPayload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSig, wantSig) {
				t.Fatalf("Sign = %x, want %x", gotSig, wantSig)
			}
			if !Verify(pub, ContextInvite, wantPayload, wantSig) {
				t.Fatal("Verify rejected the vector's own signature over InviteCreationPayload")
			}
		})
	}
}

// TestVectorInviteAcceptance pins InviteAcceptancePayload's exact encoding
// -- issue #39, the invite handshake's step-2 signed payload. Step 3 (the
// inviter's client) verifies this signature before ever wrapping the group
// key to the keys it names, so this encoding must also be byte-identical in
// Go and TypeScript before any real acceptance exists under it.
func TestVectorInviteAcceptance(t *testing.T) {
	v := loadVectors(t)
	if len(v.InviteAcceptance) == 0 {
		t.Fatal("expected at least 1 invite_acceptance vector")
	}
	for _, tc := range v.InviteAcceptance {
		t.Run(tc.Name, func(t *testing.T) {
			pub := mustHex(t, tc.PublicHex)
			priv := ed25519.PrivateKey(mustHex(t, tc.PrivateHex))
			invitedEd25519Pub := mustHex(t, tc.InvitedEd25519PubHex)
			invitedX25519Pub := mustHex(t, tc.InvitedX25519PubHex)
			wantPayload := mustHex(t, tc.PayloadHex)
			wantSig := mustHex(t, tc.SignatureHex)

			gotPayload := InviteAcceptancePayload(tc.InviteID, invitedEd25519Pub, invitedX25519Pub)
			if !bytes.Equal(gotPayload, wantPayload) {
				t.Fatalf("InviteAcceptancePayload = %x, want %x", gotPayload, wantPayload)
			}

			gotSig, err := Sign(priv, ContextInvite, gotPayload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSig, wantSig) {
				t.Fatalf("Sign = %x, want %x", gotSig, wantSig)
			}
			if !Verify(pub, ContextInvite, wantPayload, wantSig) {
				t.Fatal("Verify rejected the vector's own signature over InviteAcceptancePayload")
			}
		})
	}
}

// TestVectorInviteMAC pins DeriveInviteMACKey/ComputeInviteMAC's exact
// encoding -- PR #146 round-1 review's blocking finding #1, the per-invite
// MAC that closes the gap plain signature verification leaves open (a
// malicious server can mint its own keypair, self-sign, and pass that
// check with no real invitee involved). This must be byte-identical in Go
// and TypeScript before any real invite MAC exists under it, exactly like
// every other signed/derived payload in this file.
func TestVectorInviteMAC(t *testing.T) {
	v := loadVectors(t)
	if len(v.InviteMAC) == 0 {
		t.Fatal("expected at least 1 invite_mac vector")
	}
	for _, tc := range v.InviteMAC {
		t.Run(tc.Name, func(t *testing.T) {
			inviterSeed := mustHex(t, tc.InviterSeedHex)
			invitedEd25519Pub := mustHex(t, tc.InvitedEd25519PubHex)
			invitedX25519Pub := mustHex(t, tc.InvitedX25519PubHex)
			wantMACKey := mustHex(t, tc.MACKeyHex)
			wantPayload := mustHex(t, tc.PayloadHex)
			wantMAC := mustHex(t, tc.MACHex)

			gotMACKey, err := DeriveInviteMACKey(inviterSeed, tc.InviteID)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotMACKey, wantMACKey) {
				t.Fatalf("DeriveInviteMACKey = %x, want %x", gotMACKey, wantMACKey)
			}

			gotPayload := InviteAcceptancePayload(tc.InviteID, invitedEd25519Pub, invitedX25519Pub)
			if !bytes.Equal(gotPayload, wantPayload) {
				t.Fatalf("InviteAcceptancePayload = %x, want %x", gotPayload, wantPayload)
			}

			gotMAC := ComputeInviteMAC(gotMACKey, gotPayload)
			if !bytes.Equal(gotMAC, wantMAC) {
				t.Fatalf("ComputeInviteMAC = %x, want %x", gotMAC, wantMAC)
			}
			if !VerifyInviteMAC(gotMACKey, gotPayload, wantMAC) {
				t.Fatal("VerifyInviteMAC rejected the vector's own MAC")
			}

			// A MAC computed under a DIFFERENT invite id must not verify --
			// proves the MAC is actually bound to this invite via HKDF's
			// info parameter, not merely present.
			wrongIDKey, err := DeriveInviteMACKey(inviterSeed, "a-different-invite-id")
			if err != nil {
				t.Fatal(err)
			}
			if VerifyInviteMAC(wrongIDKey, gotPayload, wantMAC) {
				t.Fatal("VerifyInviteMAC accepted a MAC key derived under a different invite id")
			}
		})
	}
}

// TestVectorKeyRotation pins KeyRotationPayload's exact encoding (#62), the
// RosterEntryID/RosterDigest derivation behind its last field, and that the
// old-key and new-key signatures are two valid signatures over the same bytes
// -- each under its own key only.
func TestVectorKeyRotation(t *testing.T) {
	v := loadVectors(t)
	if len(v.KeyRotation) != 2 {
		t.Fatalf("want 2 key_rotation vectors, got %d", len(v.KeyRotation))
	}
	for _, tc := range v.KeyRotation {
		t.Run(tc.Name, func(t *testing.T) {
			oldPub, newPub := mustHex(t, tc.OldSigningHex), mustHex(t, tc.NewSigningHex)
			var entries [][]byte
			for _, r := range tc.RosterRows {
				id := RosterEntryID(r.SK, mustHex(t, r.SignatureHex))
				if !bytes.Equal(id, mustHex(t, r.EntryIDHex)) {
					t.Fatalf("RosterEntryID(%q) = %x, want %s", r.SK, id, r.EntryIDHex)
				}
				entries = append(entries, id)
			}
			digest := RosterDigest(entries)
			if !bytes.Equal(digest, mustHex(t, tc.RosterDigestHex)) {
				t.Fatalf("RosterDigest = %x, want %s", digest, tc.RosterDigestHex)
			}
			if len(entries) > 1 {
				reversed := [][]byte{entries[1], entries[0]}
				if !bytes.Equal(RosterDigest(reversed), digest) {
					t.Fatal("roster digest must not depend on entry order")
				}
			}
			payload := KeyRotationPayload(tc.UserUUID, oldPub, mustHex(t, tc.OldWrappingHex), newPub, mustHex(t, tc.NewWrappingHex), tc.UTCDay, tc.KeyEpoch, digest)
			if !bytes.Equal(payload, mustHex(t, tc.PayloadHex)) {
				t.Fatalf("KeyRotationPayload = %x, want %s", payload, tc.PayloadHex)
			}
			oldSig, newSig := mustHex(t, tc.OldSignatureHex), mustHex(t, tc.NewSignatureHex)
			gotOld, err := Sign(ed25519.PrivateKey(mustHex(t, tc.OldPrivateHex)), ContextKeyRotation, payload)
			if err != nil {
				t.Fatal(err)
			}
			gotNew, err := Sign(ed25519.PrivateKey(mustHex(t, tc.NewPrivateHex)), ContextKeyRotation, payload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotOld, oldSig) || !bytes.Equal(gotNew, newSig) {
				t.Fatal("Sign does not reproduce the vector's signatures")
			}
			if !Verify(oldPub, ContextKeyRotation, payload, oldSig) || !Verify(newPub, ContextKeyRotation, payload, newSig) {
				t.Fatal("Verify rejected a vector signature under its own key")
			}
			if Verify(oldPub, ContextKeyRotation, payload, newSig) || Verify(newPub, ContextKeyRotation, payload, oldSig) {
				t.Fatal("each rotation signature must verify only under its own key")
			}
			if Verify(oldPub, ContextPin, payload, oldSig) {
				t.Fatal("a rotation signature must not verify under another context")
			}
		})
	}
	if v.KeyRotation[0].PayloadHex == v.KeyRotation[1].PayloadHex {
		t.Fatal("different epoch and roster must produce different payloads")
	}
}

// TestVectorHandoffWrap pins HandoffWrapAAD's exact encoding (#62) and the
// ciphertext it produces, and that a row cannot open under another group's AAD.
func TestVectorHandoffWrap(t *testing.T) {
	v := loadVectors(t)
	if len(v.HandoffWrap) != 2 {
		t.Fatalf("want 2 handoff_wrap_aad vectors, got %d", len(v.HandoffWrap))
	}
	for _, tc := range v.HandoffWrap {
		t.Run(tc.Name, func(t *testing.T) {
			aad := HandoffWrapAAD(tc.UserUUID, tc.GroupID, tc.Generation, mustHex(t, tc.NewWrappingPublicHex))
			if !bytes.Equal(aad, mustHex(t, tc.AADHex)) {
				t.Fatalf("HandoffWrapAAD = %q, want %x", aad, mustHex(t, tc.AADHex))
			}
			key, nonce, plaintext := mustHex(t, tc.KeyHex), mustHex(t, tc.NonceHex), mustHex(t, tc.PlaintextHex)
			ct, err := EncryptWithNonce(key, nonce, plaintext, aad)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ct, mustHex(t, tc.CiphertextHex)) {
				t.Fatalf("ciphertext = %x, want %s", ct, tc.CiphertextHex)
			}
			other := HandoffWrapAAD(tc.UserUUID, "some-other-group", tc.Generation, mustHex(t, tc.NewWrappingPublicHex))
			if _, err := Decrypt(key, nonce, ct, other); err == nil {
				t.Fatal("a handoff row must not open under another group's AAD")
			}
		})
	}
	if v.HandoffWrap[0].AADHex == v.HandoffWrap[1].AADHex {
		t.Fatal("different groups must produce different AADs")
	}
}

// TestVectorWrapRecord pins WrapRecordPayload's exact encoding (#280).
func TestVectorWrapRecord(t *testing.T) {
	v := loadVectors(t)
	if len(v.WrapRecord) < 2 {
		t.Fatalf("expected at least 2 wrap_record vectors, got %d", len(v.WrapRecord))
	}
	seen := map[string]bool{}
	for _, tc := range v.WrapRecord {
		t.Run(tc.Name, func(t *testing.T) {
			pub := mustHex(t, tc.PublicHex)
			priv := ed25519.PrivateKey(mustHex(t, tc.PrivateHex))
			wantPayload := mustHex(t, tc.PayloadHex)
			wantSig := mustHex(t, tc.SignatureHex)

			gotPayload := WrapRecordPayload(tc.GroupID, tc.WrapperUUID, tc.MemberUUID, tc.Generation, tc.KeyEpoch, tc.Reason, tc.Day)
			if !bytes.Equal(gotPayload, wantPayload) {
				t.Fatalf("WrapRecordPayload = %x, want %x", gotPayload, wantPayload)
			}
			seen[tc.PayloadHex] = true
			gotSig, err := Sign(priv, ContextWrapRecord, gotPayload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSig, wantSig) {
				t.Fatalf("Sign = %x, want %x", gotSig, wantSig)
			}
			if !Verify(pub, ContextWrapRecord, wantPayload, wantSig) {
				t.Fatal("Verify rejected the vector's own signature")
			}
			if Verify(pub, ContextRotationRekey, wantPayload, wantSig) || Verify(pub, ContextAdmission, wantPayload, wantSig) || Verify(pub, ContextPin, wantPayload, wantSig) {
				t.Fatal("wrap-record signature verified under another context")
			}
		})
	}
	if len(seen) != len(v.WrapRecord) {
		t.Fatal("wrap-record vectors with different members, epochs or reasons must produce different payloads")
	}
}
