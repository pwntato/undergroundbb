package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pwntato/undergroundbb/internal/config"
)

func doUsernameAvailable(t *testing.T, h *Handler, u string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	target := "/api/auth/username-available?u=" + url.QueryEscape(u)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func decodeAvailable(t *testing.T, rec *httptest.ResponseRecorder) usernameAvailableResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body usernameAvailableResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	return body
}

func TestUsernameAvailableUnclaimed(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	body := decodeAvailable(t, doUsernameAvailable(t, h, randomUsername(t)))
	if !body.Available {
		t.Error("Available = false, want true for an unregistered name")
	}
}

func TestUsernameAvailableAfterRegistration(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	username := randomUsername(t)

	reg := doRegister(t, h, validRegisterRequest(username))
	if reg.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body: %s", reg.Code, http.StatusCreated, reg.Body.String())
	}

	body := decodeAvailable(t, doUsernameAvailable(t, h, username))
	if body.Available {
		t.Error("Available = true, want false right after registering this name")
	}

	// Case-insensitive: the claim folds case, so a differently-cased query
	// for the same name must also report unavailable.
	body = decodeAvailable(t, doUsernameAvailable(t, h, upperFirst(username)))
	if body.Available {
		t.Error("Available = true for a case-variant of a taken name, want false")
	}
}

func TestUsernameAvailableInvalidCandidates(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))

	cases := []string{
		"",                                  // empty
		"ab",                                // too short
		"has space",                         // disallowed character
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 33 chars, one over the 32 cap
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			body := decodeAvailable(t, doUsernameAvailable(t, h, u))
			if body.Available {
				t.Errorf("Available = true for invalid candidate %q, want false (not a 400)", u)
			}
		})
	}
}

func TestUsernameAvailableMissingParam(t *testing.T) {
	h := New(config.FromEnv(), testDB(t))
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/username-available", nil))

	body := decodeAvailable(t, rec)
	if body.Available {
		t.Error("Available = true with no u param at all, want false")
	}
}
