package handler

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/token"
)

// Proxy returns an http.Handler that enforces Bearer token authentication,
// logs unauthenticated requests, and forwards authenticated ones to the upstream.
//
// @arg cfg The server configuration providing the JWT secret, issuer and base URL.
// @arg upstreamURL The upstream MCP server URL to forward authenticated requests to; empty disables proxying.
// @return http.Handler A handler that returns 401 for missing/invalid tokens and otherwise proxies to the upstream.
//
// @testcase TestProxy_NoToken_Returns401 verifies a missing token yields 401 with resource metadata.
// @testcase TestProxy_InvalidToken_Returns401 verifies an invalid token yields 401 with an invalid_token error.
// @testcase TestProxy_ValidToken_ForwardsToUpstream verifies a valid token is proxied to the upstream.
// @testcase TestProxy_ValidToken_NoUpstream_Returns502 verifies a valid token with no upstream configured yields 502.
func Proxy(cfg *config.Config, upstreamURL string) http.Handler {
	var rp *httputil.ReverseProxy
	if upstreamURL != "" {
		target, err := url.Parse(upstreamURL)
		if err != nil {
			panic(fmt.Sprintf("invalid upstream_url %q: %v", upstreamURL, err))
		}
		rp = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.Host = target.Host
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				log.Printf("[PROXY] upstream error: %v", err)
				http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
			},
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resourceMetadata := baseURL(cfg) + "/.well-known/oauth-protected-resource"

		raw := bearerToken(r)
		if raw == "" {
			logRequest(r)
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer resource_metadata=%q`, resourceMetadata))
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if _, err := token.Verify(cfg.Server.JWTSecret, cfg.Server.Issuer, raw); err != nil {
			log.Printf("[AUTH] invalid token: %v", err)
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer error="invalid_token" resource_metadata=%q`, resourceMetadata))
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		if rp != nil {
			rp.ServeHTTP(w, r)
			return
		}
		http.Error(w, "no upstream configured", http.StatusBadGateway)
	})
}

// bearerToken extracts the raw token from an "Authorization: Bearer <token>"
// header, returning an empty string when no such header is present.
//
// @arg r Incoming HTTP request whose Authorization header is inspected.
// @return string The token following the "Bearer " prefix, or "" if absent.
//
// @testcase TestBearerToken verifies extraction for Bearer, non-Bearer and missing headers.
func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// sensitiveHeaders are redacted from request dumps to avoid writing
// credentials (bearer/basic tokens, cookies) to the logs.
var sensitiveHeaders = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
}

// logRequest dumps the request to stderr with sensitive headers redacted.
// It consumes and restores r.Body so the request remains usable afterwards.
//
// @arg r Incoming HTTP request to log; its body is read (bounded) and restored.
//
// @testcase TestFormatRequest_RedactsSensitiveHeaders verifies the rendered dump omits credentials.
func logRequest(r *http.Request) {
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		b, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err == nil {
			body = b
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
	}
	log.Print(formatRequest(r, time.Now(), body))
}

// formatRequest renders a request dump with sensitive headers redacted.
//
// @arg r Incoming HTTP request to render (method, target, host and headers).
// @arg now Timestamp used in the dump header, injected for deterministic tests.
// @arg body The already-read request body to append, or nil/empty for none.
// @return string A human-readable request dump with sensitive headers replaced by [REDACTED].
//
// @testcase TestFormatRequest_RedactsSensitiveHeaders verifies credentials are redacted while ordinary headers and the body remain.
func formatRequest(r *http.Request, now time.Time, body []byte) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "\n────────────────────────────────────────\n")
	fmt.Fprintf(&buf, "[%s] UNAUTHENTICATED %s %s\n", now.Format(time.RFC3339), r.Method, r.RequestURI)
	fmt.Fprintf(&buf, "Host: %s\n", r.Host)
	for name, vals := range r.Header {
		if _, ok := sensitiveHeaders[strings.ToLower(name)]; ok {
			fmt.Fprintf(&buf, "%s: [REDACTED]\n", name)
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&buf, "%s: %s\n", name, v)
		}
	}
	if len(body) > 0 {
		fmt.Fprintf(&buf, "\n%s\n", body)
	}
	fmt.Fprintf(&buf, "────────────────────────────────────────\n")
	return buf.String()
}
