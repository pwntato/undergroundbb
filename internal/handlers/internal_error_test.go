package handlers

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteInternalErrorLogsCauseButNotToClient(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/groups", nil)
	WriteInternalError(w, r, errors.New("AccessDeniedException: ConditionCheckItem"), "could not create group")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "could not create group") {
		t.Errorf("body = %q, want the generic message", body)
	}
	if strings.Contains(body, "AccessDenied") {
		t.Errorf("body leaks the underlying error: %q", body)
	}
	logged := buf.String()
	for _, want := range []string{"POST", "/api/groups", "could not create group", "AccessDeniedException: ConditionCheckItem"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log %q is missing %q", logged, want)
		}
	}
}
