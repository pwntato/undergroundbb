// Package config holds runtime configuration for the server.
//
// UndergroundBB is open source and meant to be self-hosted under any name, so
// the site name and domain are configuration rather than constants. Values come
// from environment variables with defaults; the frontend reads the public
// subset from GET /api/config.
package config

import (
	"log"
	"os"
	"strconv"
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
)

// FromEnv builds a Config from environment variables, falling back to defaults.
func FromEnv() Config {
	return Config{
		SiteName:                StringEnvOrDefault("SITE_NAME", DefaultSiteName),
		Domain:                  StringEnvOrDefault("DOMAIN", DefaultDomain),
		Environment:             StringEnvOrDefault("ENVIRONMENT", DefaultEnvironment),
		TableName:               StringEnvOrDefault("TABLE_NAME", DefaultTableName),
		RegistrationPolicy:      registrationPolicyEnvOrDefault("REGISTRATION_POLICY", DefaultRegistrationPolicy),
		AllowGroupExpirationOff: BoolEnvOrDefault("ALLOW_GROUP_EXPIRATION_OFF", DefaultAllowGroupExpirationOff),
		DefaultExpirationDays:   Int64EnvOrDefault("DEFAULT_EXPIRATION_DAYS", DefaultExpirationDays),
	}
}

// registrationPolicyEnvOrDefault reads REGISTRATION_POLICY, falling back to
// def when unset or when the value is neither "open" nor "closed" (logging a
// warning in the latter case so a typo fails loud rather than silently
// opening or closing signup).
func registrationPolicyEnvOrDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if v != RegistrationOpen && v != RegistrationClosed {
		log.Printf("warning: %s=%q is not %q or %q, using default %q", key, v, RegistrationOpen, RegistrationClosed, def)
		return def
	}
	return v
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
