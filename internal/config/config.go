// Package config holds runtime configuration for the server.
//
// UndergroundBB is open source and meant to be self-hosted under any name, so
// the site name and domain are configuration rather than constants. Values come
// from environment variables with defaults; the frontend reads the public
// subset from GET /api/config.
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

// Registration policy values. See Config.RegistrationPolicy.
const (
	RegistrationOpen   = "open"
	RegistrationClosed = "closed"
)

// Config is the server's runtime configuration.
type Config struct {
	// SiteName is the display name of this deployment.
	SiteName string
	// Domain is the public domain this deployment is served from.
	Domain string
	// Environment is the deployment environment ("dev" or "prod"), derived
	// from the Terraform workspace.
	Environment string
	// TableName is the DynamoDB table backing every record.
	TableName string
	// RegistrationPolicy is RegistrationOpen or RegistrationClosed. Open means
	// anyone may create an account, which is what THREAT_MODEL.md assumes
	// throughout (see docs/DESIGN.md, "Registration policy takes one of two
	// values"). Closed disables the signup endpoint; accounts are provisioned
	// out of band.
	RegistrationPolicy string
	// AllowGroupExpirationOff is whether a group in this deployment may set
	// "no expiration". Doing so switches off the only forward-secrecy
	// mechanism that works at any group size (see docs/DESIGN.md, "Message
	// expiration"), so a deployment may choose to forbid it entirely.
	AllowGroupExpirationOff bool
	// DefaultExpirationDays is the expiration policy assigned to a group that
	// does not choose one explicitly.
	DefaultExpirationDays int64
	// MaxRotatingGroupMembers is the most members a Rotating group may have
	// (#60). Open groups have no cap. docs/DESIGN.md sizes it against the write
	// burst of a rotation (one GENKEY link plus one wrap per member), so it is a
	// tuning knob: raise it only after checking that burst.
	MaxRotatingGroupMembers int
	// KeyRotationCooldown is the shortest time between two key rotations of one
	// account (#62). Each rotation obliges an admin in every group the user
	// belongs to to act, so an uncapped rotation is a way to keep those groups
	// busy; docs/DESIGN.md sets it at 24 hours.
	KeyRotationCooldown time.Duration

	// SessionSecret is the HMAC key session.Signer uses to issue and verify
	// login session cookies -- see internal/session. Treat it as a
	// credential: anyone holding it can mint a valid session for any user id.
	// Rotating it invalidates every outstanding session at once (the
	// intended blunt-force revocation mechanism, given docs/DESIGN.md's "a
	// stateless session cannot be revoked" -- this is the one lever an
	// operator has).
	SessionSecret []byte
	// SessionTTL is how long an issued session cookie remains valid.
	// docs/DESIGN.md says only "short-lived" and "keeping sessions short is
	// the only control" against a stolen-but-unrevoked cookie -- it does not
	// pin a duration, so this is a deployment policy choice with a
	// documented default rather than a value the design specifies.
	SessionTTL time.Duration
}

// Defaults applied when the corresponding environment variable is unset.
const (
	DefaultSiteName                = "UndergroundBB"
	DefaultDomain                  = "localhost:3000"
	DefaultEnvironment             = "dev"
	DefaultTableName               = "undergroundbb"
	DefaultRegistrationPolicy      = RegistrationOpen
	DefaultAllowGroupExpirationOff = true
	DefaultExpirationDays          = 30
	// DefaultKeyRotationCooldown is KeyRotationCooldown's default, and
	// MinKeyRotationCooldown and MaxKeyRotationCooldown bound the setting.
	DefaultKeyRotationCooldown = 24 * time.Hour
	MinKeyRotationCooldown     = time.Hour
	MaxKeyRotationCooldown     = 30 * 24 * time.Hour
	// DefaultMaxRotatingGroupMembers is MaxRotatingGroupMembers's default.
	DefaultMaxRotatingGroupMembers = 1000
	// MinRotatingGroupMembers and MaxRotatingGroupMembersCeiling bound the
	// setting. Below 2 a group could never hold an invitee; above the ceiling
	// the rotation burst outgrows what a browser can finish, so a larger value
	// is almost certainly a typo.
	MinRotatingGroupMembers        = 2
	MaxRotatingGroupMembersCeiling = 10000
)

// DefaultSessionTTL is SessionTTL's default: 24 hours. docs/DESIGN.md pins
// no duration, only "short-lived" and "keeping sessions short is the only
// control" against an unrevoked stolen cookie -- this is a starting policy
// choice, documented rather than left silent, not a value the design
// requires.
const DefaultSessionTTL = 24 * time.Hour

// MaxSessionTTL caps SESSION_TTL_HOURS at 7 days. The inactivity rule for a
// pre-signed successor (#161, docs/DESIGN.md, "Inactivity") measures an
// admin's activity by the day of their last LOGIN, and its shortest period is
// 30 days. A session as long as that period would let an admin who uses the
// board every day log in once a month and look inactive, so a successor could
// claim the group out from under them. A week leaves a wide margin below 30
// days while still being a "long session" for anyone who wants one.
const MaxSessionTTL = 7 * 24 * time.Hour

// FromEnv builds a Config from environment variables, falling back to
// defaults -- except SESSION_SECRET, which has no safe default and is
// required. A compiled-in or auto-generated fallback would either let
// anyone forge a session (a known, shared default) or make sessions behave
// inconsistently across every warm Lambda instance's own random key (a
// silently generated one) -- both worse than refusing to start. FromEnv
// calls log.Fatal itself, matching how every caller (cmd/lambda, cmd/local)
// already treats other unrecoverable startup failures (see db.New's own
// error handling at each call site), rather than changing FromEnv's
// signature to return an error only this one field can produce.
func FromEnv() Config {
	sessionSecretBytes, err := sessionSecretFromEnv("SESSION_SECRET")
	if err != nil {
		log.Fatal(err)
	}

	return Config{
		SiteName:                StringEnvOrDefault("SITE_NAME", DefaultSiteName),
		Domain:                  StringEnvOrDefault("DOMAIN", DefaultDomain),
		Environment:             StringEnvOrDefault("ENVIRONMENT", DefaultEnvironment),
		TableName:               StringEnvOrDefault("TABLE_NAME", DefaultTableName),
		RegistrationPolicy:      registrationPolicyEnvOrDefault("REGISTRATION_POLICY", DefaultRegistrationPolicy),
		AllowGroupExpirationOff: BoolEnvOrDefault("ALLOW_GROUP_EXPIRATION_OFF", DefaultAllowGroupExpirationOff),
		DefaultExpirationDays:   expirationDaysEnvOrDefault("DEFAULT_EXPIRATION_DAYS", DefaultExpirationDays),
		MaxRotatingGroupMembers: rotatingGroupMembersEnvOrDefault("MAX_ROTATING_GROUP_MEMBERS", DefaultMaxRotatingGroupMembers),
		KeyRotationCooldown:     keyRotationCooldownEnvOrDefault("KEY_ROTATION_COOLDOWN_HOURS", DefaultKeyRotationCooldown),
		SessionSecret:           sessionSecretBytes,
		SessionTTL:              sessionTTLEnvOrDefault("SESSION_TTL_HOURS", DefaultSessionTTL),
	}
}

// minSessionSecretBytes is the minimum decoded length FromEnv accepts for
// SESSION_SECRET. hex.DecodeString alone accepts any even-length hex string
// -- including a 1-byte value -- and HMAC-SHA256 technically accepts a key
// of any length without erroring, so nothing would fail loudly on a short
// secret; it would just silently become brute-forceable, which is exactly
// the "anyone holding it can mint a valid session for any user id" outcome
// Config.SessionSecret's own doc comment warns about. This matches what
// terraform/lambda.tf's random_id.session_secret generates (byte_length =
// 32) and what the error message below already recommends
// (`openssl rand -hex 32`) -- a self-hoster who follows that advice can't
// fail this check, and one who substitutes something shorter is told why,
// not left with a quietly weaker deployment.
const minSessionSecretBytes = 32

// errSessionSecretUnset, errSessionSecretNotHex, and errSessionSecretTooShort
// are sessionSecretFromEnv's failure modes, exported as sentinel values so a
// test can assert which one occurred with errors.Is rather than matching on
// message text.
var (
	errSessionSecretUnset    = errors.New("config: SESSION_SECRET is required and was not set -- generate one with e.g. `openssl rand -hex 32`; there is no safe default (a shared compiled-in secret would let anyone forge a session, and a silently auto-generated one would differ across Lambda instances and break sessions randomly)")
	errSessionSecretNotHex   = errors.New("config: SESSION_SECRET is not valid hex")
	errSessionSecretTooShort = fmt.Errorf("config: SESSION_SECRET must decode to at least %d bytes (generate one with `openssl rand -hex 32`)", minSessionSecretBytes)
)

// sessionSecretFromEnv reads and decodes key, factored out of FromEnv so the
// validation logic is directly unit-testable without exercising FromEnv's
// own log.Fatal call.
func sessionSecretFromEnv(key string) ([]byte, error) {
	v := os.Getenv(key)
	if v == "" {
		return nil, errSessionSecretUnset
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, errSessionSecretNotHex
	}
	if len(b) < minSessionSecretBytes {
		return nil, errSessionSecretTooShort
	}
	return b, nil
}

// durationEnvOrDefault reads key as a number of hours, falling back to def
// when unset, unparseable, or non-positive -- a non-positive TTL would issue
// an already-expired or immediately-expiring session, which is not a
// meaningful "short" session, it is a broken one.
func durationEnvOrDefault(key string, def time.Duration) time.Duration {
	hours := Int64EnvOrDefault(key, int64(def/time.Hour))
	if hours <= 0 {
		log.Printf("warning: %s=%d is not positive, using default %s", key, hours, def)
		return def
	}
	return time.Duration(hours) * time.Hour
}

// sessionTTLEnvOrDefault is durationEnvOrDefault with MaxSessionTTL applied. A
// value above the cap is clamped to it, not rejected: the operator asked for
// a longer session, the safe reading is the longest one allowed, and refusing
// to start would take the whole deployment down over a tuning knob.
func sessionTTLEnvOrDefault(key string, def time.Duration) time.Duration {
	ttl := durationEnvOrDefault(key, def)
	if ttl > MaxSessionTTL {
		log.Printf("warning: %s=%d exceeds the maximum of %d hours, using the maximum", key, int64(ttl/time.Hour), int64(MaxSessionTTL/time.Hour))
		return MaxSessionTTL
	}
	return ttl
}

// registrationPolicyEnvOrDefault reads REGISTRATION_POLICY. An unset variable
// falls back to def: the operator expressed no preference, so the deployment
// default applies. A value that is neither "open" nor "closed" instead fails
// closed to RegistrationClosed regardless of def, and logs a warning -- the
// operator tried to express a policy and failed, and silently falling open is
// the more dangerous failure mode for a security-relevant knob.
func registrationPolicyEnvOrDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if v != RegistrationOpen && v != RegistrationClosed {
		log.Printf("warning: %s=%q is not %q or %q, failing closed to %q", key, v, RegistrationOpen, RegistrationClosed, RegistrationClosed)
		return RegistrationClosed
	}
	return v
}

// keyRotationCooldownEnvOrDefault reads KEY_ROTATION_COOLDOWN_HOURS. Unset or
// unparseable falls back to def; a value outside [MinKeyRotationCooldown,
// MaxKeyRotationCooldown] is clamped with a warning, as the other tuning knobs
// are. The floor keeps the knob from being set to "no limit" by accident.
func keyRotationCooldownEnvOrDefault(key string, def time.Duration) time.Duration {
	hours := Int64EnvOrDefault(key, int64(def/time.Hour))
	d := time.Duration(hours) * time.Hour
	switch {
	case d < MinKeyRotationCooldown:
		log.Printf("warning: %s=%d is below the minimum of %s, using the minimum", key, hours, MinKeyRotationCooldown)
		return MinKeyRotationCooldown
	case d > MaxKeyRotationCooldown:
		log.Printf("warning: %s=%d exceeds the maximum of %s, using the maximum", key, hours, MaxKeyRotationCooldown)
		return MaxKeyRotationCooldown
	}
	return d
}

// rotatingGroupMembersEnvOrDefault reads MAX_ROTATING_GROUP_MEMBERS. Unset or
// unparseable falls back to def. A value outside [MinRotatingGroupMembers,
// MaxRotatingGroupMembersCeiling] is clamped to the nearest bound with a
// warning rather than rejected: refusing to start over a tuning knob would take
// the deployment down, and the nearest bound is the closest thing to what was
// asked for.
func rotatingGroupMembersEnvOrDefault(key string, def int) int {
	n := Int64EnvOrDefault(key, int64(def))
	switch {
	case n < MinRotatingGroupMembers:
		log.Printf("warning: %s=%d is below the minimum of %d, using the minimum", key, n, MinRotatingGroupMembers)
		return MinRotatingGroupMembers
	case n > MaxRotatingGroupMembersCeiling:
		log.Printf("warning: %s=%d exceeds the maximum of %d, using the maximum", key, n, MaxRotatingGroupMembersCeiling)
		return MaxRotatingGroupMembersCeiling
	}
	return int(n)
}

// expirationDaysEnvOrDefault reads DEFAULT_EXPIRATION_DAYS, falling back to
// def when unset, unparseable, or non-positive. Zero and negatives are
// rejected rather than passed through: the value becomes a DynamoDB TTL that
// comments and reactions copy from their parent (DESIGN.md, "Message
// expiration"), so a non-positive policy expires content on write. "No
// expiration" is a separate setting, not days <= 0.
func expirationDaysEnvOrDefault(key string, def int64) int64 {
	n := Int64EnvOrDefault(key, def)
	if n <= 0 {
		log.Printf("warning: %s=%d is not positive, using default %d", key, n, def)
		return def
	}
	return n
}

// StringEnvOrDefault reads an environment variable, returning def when unset.
func StringEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Int64EnvOrDefault reads an environment variable as int64. Returns def if the
// variable is unset or unparseable (logs a warning on parse failure).
func Int64EnvOrDefault(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		log.Printf("warning: %s=%q is not a valid int64, using default %d", key, v, def)
		return def
	}
	return n
}

// BoolEnvOrDefault reads an environment variable as a bool (accepting the
// same forms as strconv.ParseBool). Returns def if the variable is unset or
// unparseable (logs a warning on parse failure).
func BoolEnvOrDefault(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		log.Printf("warning: %s=%q is not a valid bool, using default %t", key, v, def)
		return def
	}
	return b
}
