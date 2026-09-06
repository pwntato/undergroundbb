// Command lambda is the AWS Lambda entrypoint.
//
// A Lambda Function URL sits behind CloudFront and delivers requests in the
// API Gateway v2 payload format. This file translates that payload to and from
// net/http so internal/handlers stays a plain HTTP handler, identical to what
// cmd/local serves.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/pwntato/undergroundbb/internal/config"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/handlers"
)

// handler is built once at cold start and reused across invocations.
var handler http.Handler

// initHandler builds the global handler. It is separate from main so tests can
// install their own handler without triggering AWS configuration loading.
func initHandler(ctx context.Context) {
	cfg := config.FromEnv()

	dbClient, err := db.New(ctx, cfg.TableName, "")
	if err != nil {
		log.Fatalf("db: %v", err)
	}

	mux := http.NewServeMux()
	handlers.New(cfg, dbClient).RegisterRoutes(mux)
	handler = mux
}

func main() {
	initHandler(context.Background())
	lambda.Start(lambdaHandler)
}

// lambdaHandler recovers panics itself. net/http's Server does this per
// connection, so cmd/local is already covered by the stdlib and this path is
// not; without it a panicking handler fails the invocation, returns an opaque
// 502, and kills a container that was serving warm requests.
func lambdaHandler(ctx context.Context, req events.APIGatewayV2HTTPRequest) (resp events.APIGatewayV2HTTPResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic serving %s %s: %v\n%s",
				req.RequestContext.HTTP.Method, req.RawPath, r, debug.Stack())
			resp = events.APIGatewayV2HTTPResponse{
				StatusCode: http.StatusInternalServerError,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       `{"error":"internal error"}`,
			}
			err = nil
		}
	}()

	httpReq, err := toHTTPRequest(ctx, req)
	if err != nil {
		log.Printf("toHTTPRequest: %v", err)
		return events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusBadRequest,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `{"error":"bad request"}`,
		}, nil
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httpReq)

	return toLambdaResponse(rec), nil
}

// toHTTPRequest converts a Function URL request into an *http.Request.
func toHTTPRequest(ctx context.Context, req events.APIGatewayV2HTTPRequest) (*http.Request, error) {
	url := "https://" + req.RequestContext.DomainName + req.RawPath
	if req.RawQueryString != "" {
		url += "?" + req.RawQueryString
	}

	var body io.Reader
	if req.IsBase64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(req.Body)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(decoded)
	} else {
		body = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.RequestContext.HTTP.Method, url, body)
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		// Host is authoritative from RequestContext.DomainName, which is what
		// builds the URL above. Header.Set does not update Request.Host, so
		// copying a client-supplied host header leaves a spoofed value in the
		// map for any later code that reads it -- absolute URLs in invite and
		// password-reset links, and Origin/Referer checks.
		if http.CanonicalHeaderKey(k) == "Host" {
			continue
		}
		httpReq.Header.Set(k, v)
	}
	// The v2 payload delivers request cookies in a dedicated array rather than
	// in a Cookie header, so they must be reassembled here or every handler
	// reading r.Cookie sees nothing.
	if len(req.Cookies) > 0 {
		httpReq.Header.Set("Cookie", strings.Join(req.Cookies, "; "))
	}
	// net/http's Server populates RemoteAddr from the TCP connection; nothing
	// does that for cmd/lambda, so handlers get an empty client address unless
	// it is copied here. SourceIP (not the spoofable client-supplied
	// X-Forwarded-For) is what CloudFront/API Gateway itself observed.
	if ip := req.RequestContext.HTTP.SourceIP; ip != "" {
		httpReq.RemoteAddr = ip
	}
	return httpReq, nil
}

// toLambdaResponse converts a recorded HTTP response into the v2 payload.
func toLambdaResponse(rec *httptest.ResponseRecorder) events.APIGatewayV2HTTPResponse {
	resp := rec.Result()

	// Set-Cookie must travel in the response's Cookies array. Collapsing
	// multiple Set-Cookie values into a comma-joined Headers entry yields one
	// malformed cookie and silently breaks the session.
	//
	// Collect and filter in the same loop, keyed by the same canonicalization,
	// so the two decisions cannot disagree. A prior two-step version filtered
	// resp.Header (keyed by http.CanonicalHeaderKey) with resp.Header.Values
	// (which canonicalizes its argument but not the map keys it looks up) --
	// a Set-Cookie value stored under a non-canonical map key matched the
	// filter's skip but was invisible to the collector, and was dropped
	// silently from both the Cookies array and Headers.
	var setCookies []string
	headers := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		if http.CanonicalHeaderKey(k) == "Set-Cookie" {
			setCookies = append(setCookies, vs...)
			continue
		}
		headers[k] = strings.Join(vs, ", ")
	}

	body := rec.Body.String()
	isBase64 := false
	if ct := resp.Header.Get("Content-Type"); ct != "" &&
		!strings.HasPrefix(ct, "text/") &&
		!strings.HasPrefix(ct, "application/json") {
		body = base64.StdEncoding.EncodeToString(rec.Body.Bytes())
		isBase64 = true
	}

	return events.APIGatewayV2HTTPResponse{
		StatusCode:      resp.StatusCode,
		Headers:         headers,
		Cookies:         setCookies,
		Body:            body,
		IsBase64Encoded: isBase64,
	}
}
