package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
)

// baseURL returns the public base URL for the current request.
// It respects X-Forwarded-Proto and X-Forwarded-Host (set by ngrok, etc.).
// The configured issuer is used as a fallback.
func baseURL(cfg *config.Config, r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}

	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	} else {
		// X-Forwarded-Proto may be a comma-separated list; take the first.
		proto = strings.TrimSpace(strings.SplitN(proto, ",", 2)[0])
	}

	if host != "" {
		return fmt.Sprintf("%s://%s", proto, host)
	}
	return cfg.Server.Issuer
}
