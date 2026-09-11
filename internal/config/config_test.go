package config

import "testing"

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
}

// TestRegistrationPolicyEnvOrDefault covers the reject-and-warn path: an
// invalid value must fall back to the default rather than propagate, since
// RegistrationPolicy gates the signup endpoint and an unrecognized value
// silently taking effect would be a security-relevant surprise.
func TestRegistrationPolicyEnvOrDefault(t *testing.T) {
	if got := registrationPolicyEnvOrDefault("UBB_TEST_UNSET_POLICY", RegistrationOpen); got != RegistrationOpen {
		t.Errorf("unset = %q, want %q", got, RegistrationOpen)
	}

	t.Setenv("UBB_TEST_POLICY", RegistrationClosed)
	if got := registrationPolicyEnvOrDefault("UBB_TEST_POLICY", RegistrationOpen); got != RegistrationClosed {
		t.Errorf("set = %q, want %q", got, RegistrationClosed)
	}

	t.Setenv("UBB_TEST_BAD_POLICY", "invite-only")
	if got := registrationPolicyEnvOrDefault("UBB_TEST_BAD_POLICY", RegistrationOpen); got != RegistrationOpen {
		t.Errorf("invalid = %q, want fallback %q", got, RegistrationOpen)
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
