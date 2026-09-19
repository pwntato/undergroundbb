package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// testSessionSecret is a fixed, validly-hex-encoded stand-in for
// SESSION_SECRET, used everywhere this file needs FromEnv to succeed
// without testing the secret itself -- that path has its own dedicated
// tests below.
const testSessionSecret = "14fb35fb361374c4ddf7aa98640ce2a75c0aa49cac4a7a93fe6d1ea90a6b2777"

func TestFromEnvDefaults(t *testing.T) {
	// FromEnv reads the real process environment, so the defaults can only be
	// asserted with the inputs pinned. ENVIRONMENT in particular is what the
	// Terraform Lambda config sets, and an unpinned test goes red for anyone
	// running the suite in a shell configured for dev or prod.
	// StringEnvOrDefault treats empty as unset, so this exercises the default
	// path exactly.
	t.Setenv("SITE_NAME", "")
	t.Setenv("DOMAIN", "")
	t.Setenv("ENVIRONMENT", "")
	t.Setenv("TABLE_NAME", "")
	t.Setenv("REGISTRATION_POLICY", "")
	t.Setenv("ALLOW_GROUP_EXPIRATION_OFF", "")
	t.Setenv("DEFAULT_EXPIRATION_DAYS", "")
	t.Setenv("SESSION_SECRET", testSessionSecret)
	t.Setenv("SESSION_TTL_HOURS", "")

	cfg := FromEnv()
	if cfg.SiteName != DefaultSiteName {
		t.Errorf("SiteName = %q, want %q", cfg.SiteName, DefaultSiteName)
	}
	if cfg.TableName != DefaultTableName {
		t.Errorf("TableName = %q, want %q", cfg.TableName, DefaultTableName)
	}
	if cfg.Environment != DefaultEnvironment {
		t.Errorf("Environment = %q, want %q", cfg.Environment, DefaultEnvironment)
	}
	if cfg.RegistrationPolicy != DefaultRegistrationPolicy {
		t.Errorf("RegistrationPolicy = %q, want %q", cfg.RegistrationPolicy, DefaultRegistrationPolicy)
	}
	if cfg.AllowGroupExpirationOff != DefaultAllowGroupExpirationOff {
		t.Errorf("AllowGroupExpirationOff = %t, want %t", cfg.AllowGroupExpirationOff, DefaultAllowGroupExpirationOff)
	}
	if cfg.DefaultExpirationDays != DefaultExpirationDays {
		t.Errorf("DefaultExpirationDays = %d, want %d", cfg.DefaultExpirationDays, DefaultExpirationDays)
	}
	if cfg.SessionTTL != DefaultSessionTTL {
		t.Errorf("SessionTTL = %s, want %s", cfg.SessionTTL, DefaultSessionTTL)
	}
}

// TestFromEnvOverrides covers the self-hosting requirement: a deployment must be
// able to run under its own name and domain without code changes.
func TestFromEnvOverrides(t *testing.T) {
	t.Setenv("SITE_NAME", "Somewhere Else")
	t.Setenv("DOMAIN", "example.test")
	t.Setenv("ENVIRONMENT", "prod")
	t.Setenv("TABLE_NAME", "ubb-prod")
	t.Setenv("REGISTRATION_POLICY", "closed")
	t.Setenv("ALLOW_GROUP_EXPIRATION_OFF", "false")
	t.Setenv("DEFAULT_EXPIRATION_DAYS", "14")
	t.Setenv("SESSION_SECRET", testSessionSecret)
	t.Setenv("SESSION_TTL_HOURS", "2")

	cfg := FromEnv()
	if cfg.SiteName != "Somewhere Else" {
		t.Errorf("SiteName = %q", cfg.SiteName)
	}
	if cfg.Domain != "example.test" {
		t.Errorf("Domain = %q", cfg.Domain)
	}
	if cfg.Environment != "prod" {
		t.Errorf("Environment = %q", cfg.Environment)
	}
	if cfg.TableName != "ubb-prod" {
		t.Errorf("TableName = %q", cfg.TableName)
	}
	if cfg.RegistrationPolicy != RegistrationClosed {
		t.Errorf("RegistrationPolicy = %q, want %q", cfg.RegistrationPolicy, RegistrationClosed)
	}
	if cfg.AllowGroupExpirationOff != false {
		t.Errorf("AllowGroupExpirationOff = %t, want false", cfg.AllowGroupExpirationOff)
	}
	if cfg.DefaultExpirationDays != 14 {
		t.Errorf("DefaultExpirationDays = %d, want 14", cfg.DefaultExpirationDays)
	}
	wantTTL := 2 * time.Hour
	if cfg.SessionTTL != wantTTL {
		t.Errorf("SessionTTL = %s, want %s", cfg.SessionTTL, wantTTL)
	}
	wantSecret, err := hex.DecodeString(testSessionSecret)
	if err != nil {
		t.Fatalf("test setup: %v", err)
	}
	if !bytes.Equal(cfg.SessionSecret, wantSecret) {
		t.Errorf("SessionSecret = %x, want %x", cfg.SessionSecret, wantSecret)
	}
}

// TestRegistrationPolicyEnvOrDefault covers the reject-and-warn path: an
// invalid value must fall back to RegistrationClosed rather than propagate or
// fall open, since RegistrationPolicy gates the signup endpoint and an
// unrecognized value taking effect -- or silently opening signup -- would
// both be security-relevant surprises.
func TestRegistrationPolicyEnvOrDefault(t *testing.T) {
	t.Setenv("UBB_TEST_UNSET_POLICY", "")
	if got := registrationPolicyEnvOrDefault("UBB_TEST_UNSET_POLICY", RegistrationOpen); got != RegistrationOpen {
		t.Errorf("unset = %q, want %q", got, RegistrationOpen)
	}

	t.Setenv("UBB_TEST_POLICY", RegistrationClosed)
	if got := registrationPolicyEnvOrDefault("UBB_TEST_POLICY", RegistrationOpen); got != RegistrationClosed {
		t.Errorf("set = %q, want %q", got, RegistrationClosed)
	}

	// The fallback is always RegistrationClosed here, not the def passed in
	// (RegistrationOpen), because an invalid value must fail closed.
	t.Setenv("UBB_TEST_BAD_POLICY", "invite-only")
	if got := registrationPolicyEnvOrDefault("UBB_TEST_BAD_POLICY", RegistrationOpen); got != RegistrationClosed {
		t.Errorf("invalid = %q, want fail-closed %q", got, RegistrationClosed)
	}
}

// TestExpirationDaysEnvOrDefault covers the reject-and-warn path for
// non-positive values: DESIGN.md's "Message expiration" has comments and
// reactions copy their parent post's TTL, so a non-positive policy would
// expire content on write rather than express "no expiration", which is a
// separate setting (AllowGroupExpirationOff).
func TestExpirationDaysEnvOrDefault(t *testing.T) {
	t.Setenv("UBB_TEST_DAYS_UNSET", "")
	if got := expirationDaysEnvOrDefault("UBB_TEST_DAYS_UNSET", 30); got != 30 {
		t.Errorf("unset = %d, want 30", got)
	}

	t.Setenv("UBB_TEST_DAYS_SET", "14")
	if got := expirationDaysEnvOrDefault("UBB_TEST_DAYS_SET", 30); got != 14 {
		t.Errorf("set = %d, want 14", got)
	}

	t.Setenv("UBB_TEST_DAYS_ZERO", "0")
	if got := expirationDaysEnvOrDefault("UBB_TEST_DAYS_ZERO", 30); got != 30 {
		t.Errorf("zero = %d, want fallback 30", got)
	}

	t.Setenv("UBB_TEST_DAYS_NEGATIVE", "-1")
	if got := expirationDaysEnvOrDefault("UBB_TEST_DAYS_NEGATIVE", 30); got != 30 {
		t.Errorf("negative = %d, want fallback 30", got)
	}
}

func TestSessionSecretFromEnv(t *testing.T) {
	t.Setenv("UBB_TEST_SECRET_UNSET", "")
	if _, err := sessionSecretFromEnv("UBB_TEST_SECRET_UNSET"); !errors.Is(err, errSessionSecretUnset) {
		t.Errorf("unset: err = %v, want errSessionSecretUnset", err)
	}

	t.Setenv("UBB_TEST_SECRET_BAD_HEX", "not-hex-zz")
	if _, err := sessionSecretFromEnv("UBB_TEST_SECRET_BAD_HEX"); !errors.Is(err, errSessionSecretNotHex) {
		t.Errorf("bad hex: err = %v, want errSessionSecretNotHex", err)
	}

	// Valid hex, but decodes to fewer than minSessionSecretBytes -- "ab" is
	// 1 byte, well under the floor. Review finding: this previously
	// succeeded silently.
	t.Setenv("UBB_TEST_SECRET_SHORT", "ab")
	if _, err := sessionSecretFromEnv("UBB_TEST_SECRET_SHORT"); !errors.Is(err, errSessionSecretTooShort) {
		t.Errorf("short secret: err = %v, want errSessionSecretTooShort", err)
	}

	t.Setenv("UBB_TEST_SECRET_OK", testSessionSecret)
	got, err := sessionSecretFromEnv("UBB_TEST_SECRET_OK")
	if err != nil {
		t.Fatalf("valid secret: unexpected error %v", err)
	}
	want, _ := hex.DecodeString(testSessionSecret)
	if !bytes.Equal(got, want) {
		t.Errorf("got = %x, want %x", got, want)
	}
}

func TestDurationEnvOrDefault(t *testing.T) {
	t.Setenv("UBB_TEST_TTL_UNSET", "")
	if got := durationEnvOrDefault("UBB_TEST_TTL_UNSET", 24*time.Hour); got != 24*time.Hour {
		t.Errorf("unset = %s, want 24h", got)
	}

	t.Setenv("UBB_TEST_TTL_SET", "6")
	if got := durationEnvOrDefault("UBB_TEST_TTL_SET", 24*time.Hour); got != 6*time.Hour {
		t.Errorf("set = %s, want 6h", got)
	}

	t.Setenv("UBB_TEST_TTL_ZERO", "0")
	if got := durationEnvOrDefault("UBB_TEST_TTL_ZERO", 24*time.Hour); got != 24*time.Hour {
		t.Errorf("zero = %s, want fallback 24h", got)
	}

	t.Setenv("UBB_TEST_TTL_NEGATIVE", "-1")
	if got := durationEnvOrDefault("UBB_TEST_TTL_NEGATIVE", 24*time.Hour); got != 24*time.Hour {
		t.Errorf("negative = %s, want fallback 24h", got)
	}
}

func TestBoolEnvOrDefault(t *testing.T) {
	t.Setenv("UBB_TEST_BOOL_UNSET", "")
	if got := BoolEnvOrDefault("UBB_TEST_BOOL_UNSET", true); got != true {
		t.Errorf("unset = %t, want true", got)
	}

	t.Setenv("UBB_TEST_BOOL_SET", "false")
	if got := BoolEnvOrDefault("UBB_TEST_BOOL_SET", true); got != false {
		t.Errorf("set = %t, want false", got)
	}

	t.Setenv("UBB_TEST_BOOL_BAD", "not-a-bool")
	if got := BoolEnvOrDefault("UBB_TEST_BOOL_BAD", true); got != true {
		t.Errorf("unparseable = %t, want fallback true", got)
	}
}

func TestInt64EnvOrDefault(t *testing.T) {
	t.Setenv("UBB_TEST_UNSET", "")
	if got := Int64EnvOrDefault("UBB_TEST_UNSET", 42); got != 42 {
		t.Errorf("unset = %d, want 42", got)
	}

	t.Setenv("UBB_TEST_SET", "1234")
	if got := Int64EnvOrDefault("UBB_TEST_SET", 42); got != 1234 {
		t.Errorf("set = %d, want 1234", got)
	}

	t.Setenv("UBB_TEST_BAD", "not-a-number")
	if got := Int64EnvOrDefault("UBB_TEST_BAD", 42); got != 42 {
		t.Errorf("unparseable = %d, want fallback 42", got)
	}
}
