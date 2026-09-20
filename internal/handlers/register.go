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

// Field length bounds for the raw (non-base64) byte length of the
// unauthenticated fields in registerRequest. These are generous relative to
// the real payloads -- a salt is on the order of 16 bytes and a wrapped
// private-key blob on the order of 100 -- but they turn an oversized
// request into a 400 here instead of a DynamoDB 400 KB item-size error
// surfacing as an unactionable 500 after the transaction has already been
// attempted, and they bound how much an unauthenticated caller can make
// this endpoint write per call.
const (
	maxSaltLen       = 256
	maxCiphertextLen = 4096
	// maxVerifierLen bounds the recovery verifier -- an Argon2id output, on
	// the order of 32 bytes in practice, so this is as generous relative to
	// the real payload as maxSaltLen and maxCiphertextLen are to theirs.
	maxVerifierLen = 256
)

// maxRegisterBodyBytes bounds the request body itself, ahead of any
// per-field check -- nothing else in this handler limits how large a body
// net/http will read before decoding it.
const maxRegisterBodyBytes = 64 * 1024

// minArgon2MemoryKiB, minArgon2Iterations and minArgon2Parallelism are a
// floor below which a stored Argon2id parameter set cannot back the
// security claim docs/DESIGN.md makes: "Argon2id at m=8 MiB, t=1 is weaker
// against GPU cracking than a well-tuned bcrypt, and the entire
// offline-cracking argument in the threat model rests on the cost being
// high." The server cannot verify these are the parameters actually used to
// wrap the accompanying blob -- that would require the password -- but it
// can and does reject a set that is facially below the documented minimum,
// since POST /api/auth/challenge later hands these same stored parameters
// (and the wrapped keys) to any caller naming this username, and a future
// lazy re-wrap reads them as the baseline to raise from. The floor matches
// DESIGN.md's own chosen parameters (m=64 MiB, t=3, p=1) exactly, rather
// than a looser value, since this project has one canonical parameter set
// and no stated reason a client would legitimately register below it.
const (
	minArgon2MemoryKiB   = 64 * 1024
	minArgon2Iterations  = 3
	minArgon2Parallelism = 1
)

// registerRequest is the wire shape of POST /api/auth/register. Every
// key-material field is client-generated and opaque to the server -- see
// docs/DESIGN.md, "The server never receives the password." Binary fields
// are base64-encoded (standard, padded) since this is a JSON API.
//
// The PROFILE and RECOVERY fields are two full, independent wrapped copies
// of the same private keys, matching the parallel structure in
// docs/DESIGN.md: RECOVERY "carries its own salt and its own parameters,
// since its derivation is independent of the password's."
//
// RecoveryVerifierSalt/Params/Verifier are a third, independent Argon2id
// derivation of the same client-generated recovery code -- not of the
// wrapping key above -- so that holding the verifier never yields the
// wrapper. See docs/DESIGN.md, "derived separately from the wrapping key,"
// and models.Recovery's own doc comment. The server stores these opaquely,
// exactly like the wrap fields; it never computes a verifier itself, only
// checks one later (crypto.CheckRecoveryVerifier), at actual recovery time.
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

	RecoveryVerifierSalt   string       `json:"recoveryVerifierSalt"`
	RecoveryVerifierParams argon2Params `json:"recoveryVerifierParams"`
	RecoveryVerifier       string       `json:"recoveryVerifier"`
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
// TransactWriteItems" and issue #25. The server cannot validate
// cryptographic content, since it never sees the password or the private
// keys -- but it does validate structure (presence, encoding, length
// bounds) and, for the Argon2id parameters specifically, a floor below
// this deployment's documented minimum, since those parameters are stored
// as security-relevant policy, not opaque client state -- see
// minArgon2MemoryKiB.
func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	if h.cfg.RegistrationPolicy == config.RegistrationClosed {
		// See docs/DESIGN.md, "closed means the signup endpoint is
		// disabled." Not "409 username taken" or a silent no-op -- the
		// operator disabled signup, and a caller is entitled to know that
		// rather than debug a confusing per-attempt failure.
		WriteError(w, http.StatusForbidden, "registration is closed on this deployment")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRegisterBodyBytes)

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}

	if !usernamePattern.MatchString(req.Username) {
		WriteError(w, http.StatusBadRequest, "username must be 3-32 characters: letters, digits, underscore, hyphen")
		return
	}

	signingPub, err := decodeBase64Field(req.SigningPublicKey, ed25519.PublicKeySize, ed25519.PublicKeySize)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "signingPublicKey: "+err.Error())
		return
	}
	wrappingPub, err := decodeBase64Field(req.WrappingPublicKey, x25519PublicKeySize, x25519PublicKeySize)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "wrappingPublicKey: "+err.Error())
		return
	}

	salt, err := decodeBase64Field(req.Salt, 0, maxSaltLen)
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

	recoverySalt, err := decodeBase64Field(req.RecoverySalt, 0, maxSaltLen)
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

	// The verifier is a third, independent derivation of the same recovery
	// code (see registerRequest's doc comment) -- validated the same way as
	// the wrap fields above (a facially-too-weak Argon2id floor, a decoded
	// length bound), but under its own field names so a validation error
	// tells the client which of the three derivations is wrong.
	recoveryVerifierSalt, err := decodeBase64Field(req.RecoveryVerifierSalt, 0, maxSaltLen)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "recoveryVerifierSalt: "+err.Error())
		return
	}
	if err := validateArgon2Params(req.RecoveryVerifierParams); err != nil {
		WriteError(w, http.StatusBadRequest, "recoveryVerifierParams: "+err.Error())
		return
	}
	recoveryVerifier, err := decodeBase64Field(req.RecoveryVerifier, 0, maxVerifierLen)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "recoveryVerifier: "+err.Error())
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

		RecoveryVerifierSalt:   recoveryVerifierSalt,
		RecoveryVerifierParams: toModelParams(req.RecoveryVerifierParams),
		RecoveryVerifier:       recoveryVerifier,
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
// empty string, any decoded length over maxLen, and -- when wantLen is
// nonzero -- any decoded length other than wantLen. wantLen is 0 for fields
// with no fixed size (salts, ciphertext), which is what makes maxLen do the
// real bounding work for those: without it, a field with no fixed width had
// no upper bound at all on an unauthenticated endpoint.
func decodeBase64Field(s string, wantLen, maxLen int) ([]byte, error) {
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
	if len(b) > maxLen {
		return nil, errFieldTooLong
	}
	return b, nil
}

func decodeWrappedBlob(b wrappedBlob) (models.WrappedBlob, error) {
	nonce, err := decodeBase64Field(b.Nonce, crypto.NonceSize, crypto.NonceSize)
	if err != nil {
		return models.WrappedBlob{}, err
	}
	ciphertext, err := decodeBase64Field(b.Ciphertext, 0, maxCiphertextLen)
	if err != nil {
		return models.WrappedBlob{}, err
	}
	return models.WrappedBlob{Nonce: nonce, Ciphertext: ciphertext}, nil
}

// validateArgon2Params rejects a parameter set that could not have produced
// a real derivation, or that falls below this deployment's documented
// floor. It does not, and cannot, verify the parameters are the ones
// actually used to wrap the accompanying blob -- that would require the
// password -- but it does reject a set that is facially too weak, per
// minArgon2MemoryKiB's own doc comment.
func validateArgon2Params(p argon2Params) error {
	if p.MemoryKiB <= 0 || p.Iterations <= 0 || p.Parallelism <= 0 {
		return errInvalidArgon2Params
	}
	if p.MemoryKiB < minArgon2MemoryKiB || p.Iterations < minArgon2Iterations || p.Parallelism < minArgon2Parallelism {
		return errArgon2ParamsBelowFloor
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
	errEmptyField             = fieldError("field is required")
	errNotBase64              = fieldError("must be valid base64")
	errWrongLength            = fieldError("wrong decoded length")
	errFieldTooLong           = fieldError("field exceeds the maximum allowed length")
	errInvalidArgon2Params    = fieldError("memoryKiB, iterations and parallelism must all be positive")
	errArgon2ParamsBelowFloor = fieldError("memoryKiB, iterations and parallelism must each meet this deployment's minimum (see docs/DESIGN.md)")
)

// fieldError is a plain string error -- these are user-facing validation
// messages, not conditions callers branch on, so there is nothing an error
// type would buy.
type fieldError string

func (e fieldError) Error() string { return string(e) }
