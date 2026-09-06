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
}

// Defaults applied when the corresponding environment variable is unset.
const (
	DefaultSiteName    = "UndergroundBB"
	DefaultDomain      = "localhost:3000"
	DefaultEnvironment = "dev"
	DefaultTableName   = "undergroundbb"
)

// FromEnv builds a Config from environment variables, falling back to defaults.
func FromEnv() Config {
	return Config{
		SiteName:    StringEnvOrDefault("SITE_NAME", DefaultSiteName),
		Domain:      StringEnvOrDefault("DOMAIN", DefaultDomain),
		Environment: StringEnvOrDefault("ENVIRONMENT", DefaultEnvironment),
		TableName:   StringEnvOrDefault("TABLE_NAME", DefaultTableName),
	}
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
