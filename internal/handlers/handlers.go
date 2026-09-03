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
)

// Handler serves the API.
type Handler struct {
	cfg config.Config
	db  *db.Client
}

// New builds a Handler.
func New(cfg config.Config, dbClient *db.Client) *Handler {
	return &Handler{cfg: cfg, db: dbClient}
}

// RegisterRoutes attaches every API route to mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/health", h.health)
}

// health reports that the process is up. It touches no dependencies, so it
// stays cheap enough to call from an uptime check.
func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
