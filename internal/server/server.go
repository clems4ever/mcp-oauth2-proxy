package server

import (
	"fmt"
	"net/http"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/handler"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/store"
)

// New builds and returns a configured HTTP server.
func New(cfg *config.Config) *http.Server {
	st := store.New()

	// Seed the statically-configured application so it is available to the
	// authorization code flow (authorize endpoint checks the store).
	st.PutClient(&store.Client{
		ClientID:     cfg.Application.ClientID,
		ClientSecret: cfg.Application.ClientSecret,
		RedirectURIs: cfg.Application.RedirectURIs,
		ClientName:   "configured application",
		IsPublic:     cfg.Application.ClientSecret == "",
	})

	h := handler.New(cfg, st)

	mux := http.NewServeMux()
	// RFC 9728 – protected resource metadata (tells the client which AS to use)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", h.ProtectedResource)
	// RFC 8414 – authorization server metadata discovery
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.Metadata)
	// RFC 7591 – dynamic client registration
	// RFC 6749 / 9700 – authorization endpoint (GET = show login, POST = submit)
	mux.HandleFunc("/oauth2/authorize", h.Authorize)
	// RFC 6749 / 9700 – token endpoint
	mux.HandleFunc("POST /oauth2/token", h.Token)
	// Catch-all: enforce Bearer auth, then proxy to the upstream MCP server.
	mux.Handle("/", handler.Proxy(cfg, cfg.Server.UpstreamURL))

	return &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: mux,
	}
}
