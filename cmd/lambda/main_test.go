package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

// TestCookieRoundTrip pins the one detail of the v2 payload format that is easy
// to get wrong and fails silently: request cookies arrive in a Cookies array
// rather than a Cookie header, and Set-Cookie must go back out in the response
// Cookies array rather than in Headers.
func TestCookieRoundTrip(t *testing.T) {
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session")
		if err != nil {
			t.Errorf("reading session cookie: %v", err)
		} else if c.Value != "abc123" {
			t.Errorf("session cookie = %q, want %q", c.Value, "abc123")
		}

		http.SetCookie(w, &http.Cookie{Name: "session", Value: "renewed", HttpOnly: true})
		http.SetCookie(w, &http.Cookie{Name: "csrf", Value: "token"})
		w.WriteHeader(http.StatusNoContent)
	})

	resp, err := lambdaHandler(context.Background(), events.APIGatewayV2HTTPRequest{
		RawPath: "/api/health",
		Cookies: []string{"session=abc123"},
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			DomainName: "example.invalid",
			HTTP:       events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: http.MethodGet},
		},
	})
	if err != nil {
		t.Fatalf("lambdaHandler: %v", err)
	}

	if len(resp.Cookies) != 2 {
		t.Fatalf("response Cookies = %v, want 2 entries", resp.Cookies)
	}
	for _, k := range []string{"Set-Cookie", "set-cookie"} {
		if v, ok := resp.Headers[k]; ok {
			t.Errorf("Headers[%q] = %q, want Set-Cookie absent from Headers", k, v)
		}
	}
}

// TestHealthThroughLambdaPayload exercises the full request and response
// translation against the real handler wiring.
func TestHealthThroughLambdaPayload(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
	handler = mux

	resp, err := lambdaHandler(context.Background(), events.APIGatewayV2HTTPRequest{
		RawPath: "/api/health",
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			DomainName: "example.invalid",
			HTTP:       events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: http.MethodGet},
		},
	})
	if err != nil {
		t.Fatalf("lambdaHandler: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if resp.IsBase64Encoded {
		t.Error("IsBase64Encoded = true, want false for a JSON response")
	}
	if resp.Body != `{"status":"ok"}` {
		t.Errorf("Body = %q", resp.Body)
	}
}

// TestQueryStringAndBodyDecoding covers base64 request bodies and query strings.
func TestQueryStringAndBodyDecoding(t *testing.T) {
	req := events.APIGatewayV2HTTPRequest{
		RawPath:         "/api/echo",
		RawQueryString:  "q=hello",
		Body:            "aGVsbG8=", // "hello"
		IsBase64Encoded: true,
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			DomainName: "example.invalid",
			HTTP:       events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: http.MethodPost},
		},
	}

	httpReq, err := toHTTPRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("toHTTPRequest: %v", err)
	}
	if got := httpReq.URL.Query().Get("q"); got != "hello" {
		t.Errorf("query q = %q, want %q", got, "hello")
	}
	buf := make([]byte, 5)
	if _, err := httpReq.Body.Read(buf); err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("body = %q, want %q", buf, "hello")
	}
}

// TestBinaryResponseIsBase64Encoded checks that non-text content is encoded.
func TestBinaryResponseIsBase64Encoded(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/octet-stream")
	rec.Write([]byte{0x00, 0x01, 0x02})

	resp := toLambdaResponse(rec)
	if !resp.IsBase64Encoded {
		t.Error("IsBase64Encoded = false, want true for binary content")
	}
	if resp.Body != "AAEC" {
		t.Errorf("Body = %q, want %q", resp.Body, "AAEC")
	}
}
