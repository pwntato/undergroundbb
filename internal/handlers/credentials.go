package handlers

import (
	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/models"
)

// credentialRewrapFields is the wire shape shared by changePassword (#30)
// and recoveryCodeReset (#31) -- both submit a full re-wrap of PROFILE and
// RECOVERY plus a freshly issued recovery verifier, per docs/DESIGN.md,
// "Both copies are therefore rewritten together." Factored out so the two
// handlers validate identically rather than maintaining two copies of the
// same checks that could silently drift apart.
type credentialRewrapFields struct {
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

// decodedCredentialRewrap is credentialRewrapFields after validation and
// base64-decoding, in the model types db.RewrapCredentialsInput expects.
type decodedCredentialRewrap struct {
	Salt               []byte
	Argon2Params       models.Argon2Params
	WrappedPrivateKeys models.WrappedBlob

	RecoverySalt               []byte
	RecoveryArgon2Params       models.Argon2Params
	RecoveryWrappedPrivateKeys models.WrappedBlob

	RecoveryVerifierSalt   []byte
	RecoveryVerifierParams models.Argon2Params
	RecoveryVerifier       []byte
}

// decodeCredentialRewrapFields validates and decodes f, using exactly the
// same field-level checks register.go's handler applies to the identical
// fields at signup (decodeBase64Field, validateArgon2Params,
// decodeWrappedBlob, maxVerifierLen) -- a re-wrap has no looser
// requirements than the original wrap did.
func decodeCredentialRewrapFields(f credentialRewrapFields) (decodedCredentialRewrap, error) {
	salt, err := decodeBase64Field(f.Salt, 0, maxSaltLen)
	if err != nil {
		return decodedCredentialRewrap{}, fieldError("salt: " + err.Error())
	}
	if err := validateArgon2Params(f.Argon2Params); err != nil {
		return decodedCredentialRewrap{}, fieldError("argon2Params: " + err.Error())
	}
	wrapped, err := decodeWrappedBlob(f.WrappedPrivateKeys)
	if err != nil {
		return decodedCredentialRewrap{}, fieldError("wrappedPrivateKeys: " + err.Error())
	}

	recoverySalt, err := decodeBase64Field(f.RecoverySalt, 0, maxSaltLen)
	if err != nil {
		return decodedCredentialRewrap{}, fieldError("recoverySalt: " + err.Error())
	}
	if err := validateArgon2Params(f.RecoveryArgon2Params); err != nil {
		return decodedCredentialRewrap{}, fieldError("recoveryArgon2Params: " + err.Error())
	}
	recoveryWrapped, err := decodeWrappedBlob(f.RecoveryWrappedPrivateKeys)
	if err != nil {
		return decodedCredentialRewrap{}, fieldError("recoveryWrappedPrivateKeys: " + err.Error())
	}

	verifierSalt, err := decodeBase64Field(f.RecoveryVerifierSalt, 0, maxSaltLen)
	if err != nil {
		return decodedCredentialRewrap{}, fieldError("recoveryVerifierSalt: " + err.Error())
	}
	if err := validateArgon2Params(f.RecoveryVerifierParams); err != nil {
		return decodedCredentialRewrap{}, fieldError("recoveryVerifierParams: " + err.Error())
	}
	// wantLen is crypto.VerifierLen, not 0 -- see register.go's identical
	// check on this same field (PR #118 review): a re-wrap is the second
	// route to a wrong-length stored verifier, and unlike registration it
	// can lock out a legitimate user's own next recovery attempt rather than
	// just the registering caller's.
	verifier, err := decodeBase64Field(f.RecoveryVerifier, crypto.VerifierLen, maxVerifierLen)
	if err != nil {
		return decodedCredentialRewrap{}, fieldError("recoveryVerifier: " + err.Error())
	}

	return decodedCredentialRewrap{
		Salt:               salt,
		Argon2Params:       toModelParams(f.Argon2Params),
		WrappedPrivateKeys: wrapped,

		RecoverySalt:               recoverySalt,
		RecoveryArgon2Params:       toModelParams(f.RecoveryArgon2Params),
		RecoveryWrappedPrivateKeys: recoveryWrapped,

		RecoveryVerifierSalt:   verifierSalt,
		RecoveryVerifierParams: toModelParams(f.RecoveryVerifierParams),
		RecoveryVerifier:       verifier,
	}, nil
}
