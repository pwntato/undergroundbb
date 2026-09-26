package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
)

// TestMain sets a fixed, valid SESSION_SECRET for every test in this
// package before any of them run. config.FromEnv now requires it (there is
// no safe default -- see its own doc comment), and almost none of this
// package's tests are about sessions, so setting it once here keeps that
// requirement from becoming per-test boilerplate. A test that specifically
// exercises a missing/invalid SESSION_SECRET overrides it with t.Setenv,
// same as any other env var this package's tests already override.
func TestMain(m *testing.M) {
	if err := os.Setenv("SESSION_SECRET", "14fb35fb361374c4ddf7aa98640ce2a75c0aa49cac4a7a93fe6d1ea90a6b2777"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func TestHealth(t *testing.T) {
	mux := http.NewServeMux()
	New(config.FromEnv(), testDB(t)).RegisterRoutes(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want %q", body["status"], "ok")
	}
}

func TestGetConfig(t *testing.T) {
	t.Setenv("SITE_NAME", "Test Site")
	t.Setenv("DOMAIN", "example.test")
	t.Setenv("REGISTRATION_POLICY", "closed")
	t.Setenv("ALLOW_GROUP_EXPIRATION_OFF", "false")
	t.Setenv("DEFAULT_EXPIRATION_DAYS", "14")

	mux := http.NewServeMux()
	New(config.FromEnv(), testDB(t)).RegisterRoutes(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/config", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body publicConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body.SiteName != "Test Site" {
		t.Errorf("SiteName = %q, want %q", body.SiteName, "Test Site")
	}
	if body.Domain != "example.test" {
		t.Errorf("Domain = %q, want %q", body.Domain, "example.test")
	}
	if body.RegistrationPolicy != "closed" {
		t.Errorf("RegistrationPolicy = %q, want %q", body.RegistrationPolicy, "closed")
	}
	if body.AllowGroupExpirationOff != false {
		t.Errorf("AllowGroupExpirationOff = %t, want false", body.AllowGroupExpirationOff)
	}
	if body.DefaultExpirationDays != 14 {
		t.Errorf("DefaultExpirationDays = %d, want 14", body.DefaultExpirationDays)
	}
}

// TestNewPanicsOnNilClient pins #87: a nil dbClient must fail at
// construction, not pass silently into a Handler and panic later at request
// time on whichever route first reads h.db.
func TestNewPanicsOnNilClient(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("New(cfg, nil) did not panic, want a panic")
		}
	}()
	New(config.FromEnv(), nil)
	t.Fatal("New(cfg, nil) returned, want it to panic before returning")
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusNotFound, "no such group")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["error"] != "no such group" {
		t.Errorf("error = %q", body["error"])
	}
}
