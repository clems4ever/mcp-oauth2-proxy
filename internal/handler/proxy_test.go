package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/token"
)

const proxyJWTSecret = "proxy-test-secret"

// proxyConfig returns a configuration for proxy tests with the given upstream URL.
//
// @arg upstream The upstream URL to forward authenticated requests to; may be empty.
// @return *config.Config A configuration wired with the test issuer, JWT secret and upstream.
func proxyConfig(upstream string) *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Issuer:      testIssuer,
			JWTSecret:   proxyJWTSecret,
			TokenTTL:    3600,
			UpstreamURL: upstream,
		},
	}
}

// TestProxy_NoToken_Returns401 verifies a missing token yields 401 with resource metadata.
//
// @arg t The testing context provided by the Go test runner.
func TestProxy_NoToken_Returns401(t *testing.T) {
	h := Proxy(proxyConfig(""), "")
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	wa := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(wa, "resource_metadata=") {
		t.Errorf("expected resource_metadata in WWW-Authenticate, got %q", wa)
	}
}

// TestProxy_InvalidToken_Returns401 verifies an invalid token yields 401 with an invalid_token error.
//
// @arg t The testing context provided by the Go test runner.
func TestProxy_InvalidToken_Returns401(t *testing.T) {
	h := Proxy(proxyConfig(""), "")
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("expected invalid_token error, got %q", rr.Header().Get("WWW-Authenticate"))
	}
}

// TestProxy_ValidToken_ForwardsToUpstream verifies a valid token is proxied to the upstream.
//
// @arg t The testing context provided by the Go test runner.
func TestProxy_ValidToken_ForwardsToUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from upstream"))
	}))
	defer upstream.Close()

	cfg := proxyConfig(upstream.URL)
	h := Proxy(cfg, upstream.URL)

	tok, err := token.Generate(proxyJWTSecret, testIssuer, "sub", []string{"read"}, 3600)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if rr.Body.String() != "hello from upstream" {
		t.Errorf("unexpected upstream body: %q", rr.Body.String())
	}
}

// TestProxy_ValidToken_NoUpstream_Returns502 verifies a valid token with no upstream configured yields 502.
//
// @arg t The testing context provided by the Go test runner.
func TestProxy_ValidToken_NoUpstream_Returns502(t *testing.T) {
	h := Proxy(proxyConfig(""), "")

	tok, err := token.Generate(proxyJWTSecret, testIssuer, "sub", nil, 3600)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rr.Code)
	}
}

// TestBearerToken verifies extraction for Bearer, non-Bearer and missing Authorization headers.
//
// @arg t The testing context provided by the Go test runner.
func TestBearerToken(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"Bearer abc", "abc"},
		{"bearer abc", ""}, // case-sensitive per RFC 6750 scheme matching here
		{"Basic abc", ""},
		{"", ""},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.header != "" {
			req.Header.Set("Authorization", c.header)
		}
		if got := bearerToken(req); got != c.want {
			t.Errorf("bearerToken(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}

// TestFormatRequest_RedactsSensitiveHeaders verifies credentials are redacted while ordinary headers and the body remain.
//
// @arg t The testing context provided by the Go test runner.
func TestFormatRequest_RedactsSensitiveHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("body-data"))
	req.Header.Set("Authorization", "Basic c2VjcmV0")
	req.Header.Set("Cookie", "session=supersecret")
	req.Header.Set("Proxy-Authorization", "Bearer leak")
	req.Header.Set("X-Custom", "visible")

	body, _ := io.ReadAll(req.Body)
	out := formatRequest(req, time.Unix(0, 0).UTC(), body)

	for _, secret := range []string{"c2VjcmV0", "supersecret", "leak"} {
		if strings.Contains(out, secret) {
			t.Errorf("dump leaked sensitive value %q:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected redaction marker, got:\n%s", out)
	}
	if !strings.Contains(out, "X-Custom: visible") {
		t.Errorf("non-sensitive header should be visible, got:\n%s", out)
	}
	if !strings.Contains(out, "body-data") {
		t.Errorf("expected body in dump, got:\n%s", out)
	}
}
