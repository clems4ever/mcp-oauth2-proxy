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
func Proxy(cfg *config.Config, upstreamURL string) http.Handler {
	var rp *httputil.ReverseProxy
	if upstreamURL != "" {
		target, err := url.Parse(upstreamURL)
		if err != nil {
			panic(fmt.Sprintf("invalid upstream_url %q: %v", upstreamURL, err))
		}
		rp = httputil.NewSingleHostReverseProxy(target)
		originalDirector := rp.Director
		rp.Director = func(req *http.Request) {
			originalDirector(req)
			req.Host = target.Host
		}
		rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[PROXY] upstream error: %v", err)
			http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resourceMetadata := baseURL(cfg, r) + "/.well-known/oauth-protected-resource"

		raw := bearerToken(r)
		if raw == "" {
			logRequest(r)
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer resource_metadata=%q`, resourceMetadata))
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if _, err := token.Verify(cfg.Server.JWTSecret, raw); err != nil {
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

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// logRequest dumps the full request to stderr.
func logRequest(r *http.Request) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "\n────────────────────────────────────────\n")
	fmt.Fprintf(&buf, "[%s] UNAUTHENTICATED %s %s\n", time.Now().Format(time.RFC3339), r.Method, r.RequestURI)
	fmt.Fprintf(&buf, "Host: %s\n", r.Host)
	for name, vals := range r.Header {
		for _, v := range vals {
			fmt.Fprintf(&buf, "%s: %s\n", name, v)
		}
	}
	if r.Body != nil && r.Body != http.NoBody {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err == nil && len(body) > 0 {
			r.Body = io.NopCloser(bytes.NewReader(body))
			fmt.Fprintf(&buf, "\n%s\n", body)
		}
	}
	fmt.Fprintf(&buf, "────────────────────────────────────────\n")
	log.Print(buf.String())
}
