package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// usernamePattern bounds what this deployment accepts as a username. Neither
// docs/DESIGN.md nor THREAT_MODEL.md pins a character set or length --
// uniqueness is the only property the schema depends on -- so this is a
// server-side policy choice, not a protocol requirement: ASCII letters,
// digits, underscore and hyphen, 3-32 characters. Restricting to ASCII
// sidesteps Unicode normalization and homoglyph questions entirely rather
// than half-solving them; DESIGN.md already notes homoglyphs across scripts
// are "a harder version of this problem and are not solved here" even with
// this restriction, since fingerprint verification is the real defense.
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{3,32}$`)

// registerRequest is the wire shape of POST /api/auth/register. Every
// key-material field is client-generated and opaque to the server -- see
// docs/DESIGN.md, "The server never receives the password." Binary fields
// are base64-encoded (standard, padded) since this is a JSON API.
//
// The PROFILE and RECOVERY fields are two full, independent wrapped copies
// of the same private keys, matching the parallel structure in
// docs/DESIGN.md: RECOVERY "carries its own salt and its own parameters,
// since its derivation is independent of the password's."
type registerRequest struct {
	Username string `json:"username"`

	SigningPublicKey  string `json:"signingPublicKey"`
	WrappingPublicKey string `json:"wrappingPublicKey"`

	Salt               string       `json:"salt"`
	Argon2Params       argon2Params `json:"argon2Params"`
	WrappedPrivateKeys wrappedBlob  `json:"wrappedPrivateKeys"`

	RecoverySalt               string       `json:"recoverySalt"`
	RecoveryArgon2Params       argon2Params `json:"recoveryArgon2Params"`
	RecoveryWrappedPrivateKeys wrappedBlob  `json:"recoveryWrappedPrivateKeys"`
}

type argon2Params struct {
	MemoryKiB   int64 `json:"memoryKiB"`
	Iterations  int64 `json:"iterations"`
	Parallelism int64 `json:"parallelism"`
}

type wrappedBlob struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// registerResponse confirms the account was created. It deliberately echoes
// back nothing sensitive -- the client already holds everything it sent,
// and the server has nothing else to add until login.
type registerResponse struct {
	UserID string `json:"userId"`
}

// register implements POST /api/auth/register -- see docs/DESIGN.md,
// "signup writes three items across two partitions, so it is one
// TransactWriteItems" and issue #25. The server validates only structure
// (presence, encoding, an internally consistent Argon2id parameter set) --
// it has no way to validate the cryptographic content, since it never sees
// the password or the private keys.
func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	if h.cfg.RegistrationPolicy == config.RegistrationClosed {
		// See docs/DESIGN.md, "closed means the signup endpoint is
		// disabled." Not "409 username taken" or a silent no-op -- the
		// operator disabled signup, and a caller is entitled to know that
		// rather than debug a confusing per-attempt failure.
		WriteError(w, http.StatusForbidden, "registration is closed on this deployment")
		return
	}

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}

	if !usernamePattern.MatchString(req.Username) {
		WriteError(w, http.StatusBadRequest, "username must be 3-32 characters: letters, digits, underscore, hyphen")
		return
	}

	signingPub, err := decodeBase64Field(req.SigningPublicKey, ed25519.PublicKeySize)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "signingPublicKey: "+err.Error())
		return
	}
	wrappingPub, err := decodeBase64Field(req.WrappingPublicKey, x25519PublicKeySize)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "wrappingPublicKey: "+err.Error())
		return
	}

	salt, err := decodeBase64Field(req.Salt, 0)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "salt: "+err.Error())
		return
	}
	if err := validateArgon2Params(req.Argon2Params); err != nil {
		WriteError(w, http.StatusBadRequest, "argon2Params: "+err.Error())
		return
	}
	wrapped, err := decodeWrappedBlob(req.WrappedPrivateKeys)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "wrappedPrivateKeys: "+err.Error())
		return
	}

	recoverySalt, err := decodeBase64Field(req.RecoverySalt, 0)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "recoverySalt: "+err.Error())
		return
	}
	if err := validateArgon2Params(req.RecoveryArgon2Params); err != nil {
		WriteError(w, http.StatusBadRequest, "recoveryArgon2Params: "+err.Error())
		return
	}
	recoveryWrapped, err := decodeWrappedBlob(req.RecoveryWrappedPrivateKeys)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "recoveryWrappedPrivateKeys: "+err.Error())
		return
	}

	userID, err := idgen.UUID()
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not generate user id")
		return
	}

	err = h.db.Register(r.Context(), db.RegisterInput{
		UserID:            userID,
		Username:          req.Username,
		UsernameLower:     strings.ToLower(req.Username),
		SigningPublicKey:  signingPub,
		WrappingPublicKey: wrappingPub,

		Salt:               salt,
		Argon2Params:       toModelParams(req.Argon2Params),
		WrappedPrivateKeys: wrapped,

		RecoverySalt:               recoverySalt,
		RecoveryArgon2Params:       toModelParams(req.RecoveryArgon2Params),
		RecoveryWrappedPrivateKeys: recoveryWrapped,
	})
	if err != nil {
		if errors.Is(err, db.ErrUsernameTaken) {
			WriteError(w, http.StatusConflict, "username is taken")
			return
		}
		WriteError(w, http.StatusInternalServerError, "could not create account")
		return
	}

	WriteJSON(w, http.StatusCreated, registerResponse{UserID: userID})
}

// x25519PublicKeySize is X25519's fixed public key width. crypto/ecdh has no
// exported size constant the way crypto/ed25519 does, so this is named here
// rather than left as a bare 32.
const x25519PublicKeySize = 32

// decodeBase64Field decodes a standard-padded base64 field, rejecting an
// empty string and, when wantLen is nonzero, any decoded length other than
// wantLen. wantLen is 0 for fields with no fixed size (salts, ciphertext).
func decodeBase64Field(s string, wantLen int) ([]byte, error) {
	if s == "" {
		return nil, errEmptyField
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errNotBase64
	}
	if wantLen != 0 && len(b) != wantLen {
		return nil, errWrongLength
	}
	return b, nil
}

func decodeWrappedBlob(b wrappedBlob) (models.WrappedBlob, error) {
	nonce, err := decodeBase64Field(b.Nonce, crypto.NonceSize)
	if err != nil {
		return models.WrappedBlob{}, err
	}
	ciphertext, err := decodeBase64Field(b.Ciphertext, 0)
	if err != nil {
		return models.WrappedBlob{}, err
	}
	return models.WrappedBlob{Nonce: nonce, Ciphertext: ciphertext}, nil
}

// validateArgon2Params rejects a parameter set that could not have produced
// a real derivation. It does not, and cannot, verify the parameters are the
// ones actually used to wrap the accompanying blob -- that would require
// the password. It exists only to reject obviously-malformed input (a zero
// or negative field) before it is stored and later read back to drive a
// real client-side derivation on login.
func validateArgon2Params(p argon2Params) error {
	if p.MemoryKiB <= 0 || p.Iterations <= 0 || p.Parallelism <= 0 {
		return errInvalidArgon2Params
	}
	return nil
}

func toModelParams(p argon2Params) models.Argon2Params {
	return models.Argon2Params{
		MemoryKiB:   p.MemoryKiB,
		Iterations:  p.Iterations,
		Parallelism: p.Parallelism,
	}
}

var (
	errEmptyField          = fieldError("field is required")
	errNotBase64           = fieldError("must be valid base64")
	errWrongLength         = fieldError("wrong decoded length")
	errInvalidArgon2Params = fieldError("memoryKiB, iterations and parallelism must all be positive")
)

// fieldError is a plain string error -- these are user-facing validation
// messages, not conditions callers branch on, so there is nothing an error
// type would buy.
type fieldError string

func (e fieldError) Error() string { return string(e) }
