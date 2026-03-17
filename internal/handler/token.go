package handler

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/store"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/token"
)

// Handler handles all OAuth2 HTTP requests.
type Handler struct {
	cfg   *config.Config
	store *store.Store
}

// New creates a Handler.
func New(cfg *config.Config, st *store.Store) *Handler {
	return &Handler{cfg: cfg, store: st}
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Token handles POST /oauth2/token.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Printf("[TOKEN] failed to parse form: %v", err)
		writeError(w, "invalid_request", "failed to parse request body", http.StatusBadRequest)
		return
	}

	grant := r.FormValue("grant_type")
	log.Printf("[TOKEN] grant_type=%q", grant)
	switch grant {
	case "client_credentials":
		h.handleClientCredentials(w, r)
	case "authorization_code":
		h.handleAuthorizationCode(w, r)
	default:
		log.Printf("[TOKEN] unsupported grant_type=%q", grant)
		writeError(w, "unsupported_grant_type", "supported grants: client_credentials, authorization_code", http.StatusBadRequest)
	}
}

func (h *Handler) handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
		log.Printf("[TOKEN/cc] credentials from form: client_id=%q", clientID)
	} else {
		log.Printf("[TOKEN/cc] credentials from Basic auth: client_id=%q", clientID)
	}
	if clientID == "" {
		log.Printf("[TOKEN/cc] missing client_id")
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth2"`)
		writeError(w, "invalid_client", "client authentication required", http.StatusUnauthorized)
		return
	}

	app := &h.cfg.Application
	if !secureCompare(app.ClientID, clientID) || !secureCompare(app.ClientSecret, clientSecret) {
		log.Printf("[TOKEN/cc] credential mismatch: got client_id=%q (want %q)", clientID, app.ClientID)
		writeError(w, "invalid_client", "invalid client credentials", http.StatusUnauthorized)
		return
	}

	granted := filterScopes(app.AllowedScopes, strings.Fields(r.FormValue("scope")))
	log.Printf("[TOKEN/cc] issuing token for client_id=%q scopes=%v", clientID, granted)
	tok, err := token.Generate(h.cfg.Server.JWTSecret, clientID, granted, h.cfg.Server.TokenTTL)
	if err != nil {
		log.Printf("[TOKEN/cc] generate error: %v", err)
		writeError(w, "server_error", "failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: tok,
		TokenType:   "Bearer",
		ExpiresIn:   h.cfg.Server.TokenTTL,
		Scope:       strings.Join(granted, " "),
	})
}

func (h *Handler) handleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
		log.Printf("[TOKEN/ac] credentials from form: client_id=%q", clientID)
	} else {
		log.Printf("[TOKEN/ac] credentials from Basic auth: client_id=%q", clientID)
	}
	if clientID == "" {
		log.Printf("[TOKEN/ac] missing client_id")
		writeError(w, "invalid_client", "client_id is required", http.StatusUnauthorized)
		return
	}

	client := h.store.FindClient(clientID)
	if client == nil {
		log.Printf("[TOKEN/ac] unknown client_id=%q", clientID)
		writeError(w, "invalid_client", "unknown client", http.StatusUnauthorized)
		return
	}
	// Confidential clients must authenticate with their secret.
	if !client.IsPublic && !secureCompare(client.ClientSecret, clientSecret) {
		log.Printf("[TOKEN/ac] secret mismatch for client_id=%q (IsPublic=%v)", clientID, client.IsPublic)
		writeError(w, "invalid_client", "invalid client credentials", http.StatusUnauthorized)
		return
	}

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")
	log.Printf("[TOKEN/ac] code=%q redirect_uri=%q code_verifier_len=%d", code, redirectURI, len(codeVerifier))
	if code == "" || codeVerifier == "" {
		log.Printf("[TOKEN/ac] missing code or code_verifier")
		writeError(w, "invalid_request", "code and code_verifier are required", http.StatusBadRequest)
		return
	}

	ac := h.store.ConsumeAuthCode(code)
	if ac == nil {
		log.Printf("[TOKEN/ac] code not found or expired: %q", code)
		writeError(w, "invalid_grant", "invalid or expired authorization code", http.StatusBadRequest)
		return
	}
	if ac.ClientID != clientID {
		log.Printf("[TOKEN/ac] client_id mismatch: code belongs to %q, got %q", ac.ClientID, clientID)
		writeError(w, "invalid_grant", "client_id mismatch", http.StatusBadRequest)
		return
	}
	if redirectURI != "" && ac.RedirectURI != redirectURI {
		log.Printf("[TOKEN/ac] redirect_uri mismatch: code has %q, got %q", ac.RedirectURI, redirectURI)
		writeError(w, "invalid_grant", "redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	if !verifyPKCE(ac.CodeChallenge, codeVerifier) {
		log.Printf("[TOKEN/ac] PKCE failed: challenge=%q verifier=%q", ac.CodeChallenge, codeVerifier)
		writeError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
		return
	}

	log.Printf("[TOKEN/ac] issuing token for subject=%q client_id=%q scopes=%v", ac.Subject, clientID, ac.Scopes)
	tok, err := token.Generate(h.cfg.Server.JWTSecret, ac.Subject, ac.Scopes, h.cfg.Server.TokenTTL)
	if err != nil {
		log.Printf("[TOKEN/ac] generate error: %v", err)
		writeError(w, "server_error", "failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: tok,
		TokenType:   "Bearer",
		ExpiresIn:   h.cfg.Server.TokenTTL,
		Scope:       strings.Join(ac.Scopes, " "),
	})
}

// secureCompare prevents timing-based secret leakage.
func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// filterScopes returns the intersection of allowed and requested scopes.
// If no scopes are requested, all allowed scopes are granted.
func filterScopes(allowed, requested []string) []string {
	if len(requested) == 0 {
		return allowed
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = struct{}{}
	}
	var granted []string
	for _, s := range requested {
		if _, ok := allowedSet[s]; ok {
			granted = append(granted, s)
		}
	}
	return granted
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, errCode, desc string, status int) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, errorResponse{Error: errCode, ErrorDescription: desc})
}
