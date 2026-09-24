// Package handlers implements the JSON HTTP API.
//
// Everything is served under /api. Handlers are plain net/http, so the same
// mux serves both the Lambda entrypoint (cmd/lambda) and the local development
// server (cmd/local) with no behavioural difference between them.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/session"
)

// Handler serves the API.
type Handler struct {
	cfg      config.Config
	db       *db.Client
	sessions *session.Signer
}

// New builds a Handler.
func New(cfg config.Config, dbClient *db.Client) *Handler {
	return &Handler{cfg: cfg, db: dbClient, sessions: session.NewSigner(cfg.SessionSecret)}
}

// RegisterRoutes attaches every API route to mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/health", h.health)
	mux.HandleFunc("GET /api/config", h.getConfig)
	mux.HandleFunc("POST /api/auth/register", h.register)
	mux.HandleFunc("GET /api/auth/username-available", h.usernameAvailable)
	mux.HandleFunc("POST /api/auth/challenge", h.challenge)
	mux.HandleFunc("POST /api/auth/verify", h.verify)
	mux.HandleFunc("GET /api/auth/session", h.getSession)
	mux.HandleFunc("GET /api/account/credentials", h.requireSession(h.getAccountCredentials))
	mux.HandleFunc("PUT /api/account/password", h.requireSession(h.changePassword))
	mux.HandleFunc("POST /api/account/recovery-code/release", h.recoveryCodeRelease)
	mux.HandleFunc("PUT /api/account/recovery-code", h.recoveryCodeReset)
}

// health reports that the process is up. It touches no dependencies, so it
// stays cheap enough to call from an uptime check.
func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// publicConfig is the subset of config.Config the SPA needs on boot. It is a
// deliberately separate type from config.Config rather than a marshalled
// subset of it, so adding a server-only field (a secret, an internal tuning
// knob) can never leak here by default -- it has to be added to this struct
// explicitly.
type publicConfig struct {
	SiteName                string `json:"siteName"`
	Domain                  string `json:"domain"`
	RegistrationPolicy      string `json:"registrationPolicy"`
	AllowGroupExpirationOff bool   `json:"allowGroupExpirationOff"`
	DefaultExpirationDays   int64  `json:"defaultExpirationDays"`
}

// getConfig serves the public, unauthenticated subset of the deployment's
// runtime configuration. The SPA fetches it on boot so branding and policy
// are never compiled into the bundle -- see docs/DESIGN.md, "Site name,
// domain, registration policy, and whether 'no expiration' is a permitted
// group setting are all runtime configuration".
func (h *Handler) getConfig(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, publicConfig{
		SiteName:                h.cfg.SiteName,
		Domain:                  h.cfg.Domain,
		RegistrationPolicy:      h.cfg.RegistrationPolicy,
		AllowGroupExpirationOff: h.cfg.AllowGroupExpirationOff,
		DefaultExpirationDays:   h.cfg.DefaultExpirationDays,
	})
}

// WriteJSON writes v as a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status line is already sent, so this can only be logged.
		log.Printf("write json response: %v", err)
	}
}

// WriteError writes a JSON error response.
func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"error": msg})
}

// WriteErrorWithCode writes a JSON error response carrying a stable,
// machine-readable code alongside the free-text message WriteError already
// sends. Most callers should still use WriteError -- this project has no
// general convention yet for when an error is worth a code. A userId
// conflict and a username conflict need genuinely different client recovery
// (the former means regenerating the id and re-wrapping both key copies;
// the latter just means resending under a new name), and only the former is
// exposed with a code today. Use this only where a caller genuinely needs to
// branch on the failure kind rather than just display msg, rather than
// adding a code to every error as a matter of course.
func WriteErrorWithCode(w http.ResponseWriter, status int, msg, code string) {
	WriteJSON(w, status, map[string]string{"error": msg, "code": code})
}
