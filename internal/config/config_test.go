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
}

// TestFromEnvOverrides covers the self-hosting requirement: a deployment must be
// able to run under its own name and domain without code changes.
func TestFromEnvOverrides(t *testing.T) {
	t.Setenv("SITE_NAME", "Somewhere Else")
	t.Setenv("DOMAIN", "example.test")
	t.Setenv("ENVIRONMENT", "prod")
	t.Setenv("TABLE_NAME", "ubb-prod")

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
