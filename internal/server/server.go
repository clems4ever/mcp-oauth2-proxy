package server

import (
	"fmt"
	"net/http"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/handler"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/oidc"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/store"
)

// New builds and returns a configured HTTP server.
//
// It panics if jwt_secret is not configured: signing and verifying tokens with
// an empty HMAC key would let anyone forge valid access tokens.
//
// @arg cfg The loaded server configuration; its jwt_secret, issuer, port and upstream settings wire the handlers.
// @arg st The authorization-server state store (in-memory or persistent).
// @arg oidcClient The configured OIDC relying party, or nil to disable OIDC login routes.
// @return *http.Server An HTTP server with the OAuth2 routes and authenticating reverse proxy mounted.
//
// @testcase TestNew_PanicsOnEmptyJWTSecret verifies that New panics when jwt_secret is empty.
// @testcase TestNew_SucceedsWithJWTSecret verifies that New returns a server bound to the configured port with a handler set.
func New(cfg *config.Config, st *store.Store, oidcClient *oidc.Client) *http.Server {
	if cfg.Server.JWTSecret == "" {
		panic("jwt_secret must be set: refusing to sign tokens with an empty key")
	}

	// Seed the statically-configured application so it is available to the
	// authorization code flow (authorize endpoint checks the store).
	st.PutClient(&store.Client{
		ClientID:     cfg.Application.ClientID,
		ClientSecret: cfg.Application.ClientSecret,
		RedirectURIs: cfg.Application.RedirectURIs,
		ClientName:   "configured application",
		IsPublic:     cfg.Application.ClientSecret == "",
	})

	h := handler.New(cfg, st, oidcClient)

	mux := http.NewServeMux()
	// RFC 9728 – protected resource metadata (tells the client which AS to use)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", h.ProtectedResource)
	// RFC 8414 – authorization server metadata discovery
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.Metadata)
	// RFC 6749 / 9700 – authorization endpoint (GET = show login, POST = submit)
	mux.HandleFunc("/oauth2/authorize", h.Authorize)
	// RFC 6749 / 9700 – token endpoint
	mux.HandleFunc("POST /oauth2/token", h.Token)
	// OIDC browser login (only when an OIDC provider is configured).
	if oidcClient != nil {
		mux.HandleFunc("POST /oauth2/oidc/login", h.OIDCLogin)
		mux.HandleFunc("GET /oauth2/oidc/callback", h.OIDCCallback)
	}
	// Browsers auto-request /favicon.ico while on the login page; answer it
	// quietly so it does not hit the authenticated proxy (401 + request dump).
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	// Catch-all: enforce Bearer auth, then proxy to the upstream MCP server.
	mux.Handle("/", handler.Proxy(cfg, cfg.Server.UpstreamURL))

	return &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: mux,
	}
}
