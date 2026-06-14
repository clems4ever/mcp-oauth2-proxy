package handler

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/oidc"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/store"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/token"
)

// Handler handles all OAuth2 HTTP requests.
type Handler struct {
	cfg   *config.Config
	store *store.Store
	oidc  *oidc.Client // nil when OIDC login is not configured
}

// New creates a Handler.
//
// @arg cfg The loaded server configuration backing token issuance and validation.
// @arg st The authorization-server state store holding clients and authorization codes.
// @arg oidcClient The configured OIDC relying party, or nil when OIDC login is disabled.
// @return *Handler A handler wired to the given configuration, store and OIDC client.
//
// @testcase TestMetadata_StatusOK constructs a handler via New to serve metadata.
// @testcase TestClientCredentials_BasicAuth_Success constructs a handler via New to issue tokens.
func New(cfg *config.Config, st *store.Store, oidcClient *oidc.Client) *Handler {
	return &Handler{cfg: cfg, store: st, oidc: oidcClient}
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Token handles POST /oauth2/token, dispatching to the client_credentials,
// authorization_code or refresh_token grant handler based on the grant_type
// form value.
//
// @arg w HTTP response writer the token or error JSON is written to.
// @arg r Incoming token request carrying the grant_type and grant parameters.
//
// @testcase TestToken_UnsupportedGrant verifies an unknown grant_type is rejected with 400.
// @testcase TestClientCredentials_BasicAuth_Success verifies the client_credentials grant is routed and issues a token.
// @testcase TestAuthorizationCode_PublicClient_Success verifies the authorization_code grant is routed and issues a token.
// @testcase TestRefreshToken_Success verifies the refresh_token grant is routed and issues a new token.
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
	case "refresh_token":
		h.handleRefreshToken(w, r)
	default:
		log.Printf("[TOKEN] unsupported grant_type=%q", grant)
		writeError(w, "unsupported_grant_type", "supported grants: client_credentials, authorization_code, refresh_token", http.StatusBadRequest)
	}
}

// handleClientCredentials processes the OAuth 2.0 client_credentials grant:
// it authenticates the configured application (via Basic auth or form fields)
// and issues an access token for the granted, allowed scopes.
//
// @arg w HTTP response writer the token or error JSON is written to.
// @arg r Token request carrying client credentials and the optional requested scope.
//
// @testcase TestClientCredentials_BasicAuth_Success verifies a token is issued for valid Basic-auth credentials.
// @testcase TestClientCredentials_FormCredentials_Success verifies credentials may be supplied as form fields.
// @testcase TestClientCredentials_MissingClientID verifies a missing client_id yields 401.
// @testcase TestClientCredentials_WrongSecret verifies an invalid secret yields 401.
// @testcase TestClientCredentials_ScopeEscalationFiltered verifies scopes outside allowed_scopes are filtered out.
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
	idOK := secureCompare(app.ClientID, clientID)
	secretOK := secureCompare(app.ClientSecret, clientSecret)
	if !idOK || !secretOK {
		log.Printf("[TOKEN/cc] credential mismatch: got client_id=%q (want %q)", clientID, app.ClientID)
		writeError(w, "invalid_client", "invalid client credentials", http.StatusUnauthorized)
		return
	}

	granted := filterScopes(app.AllowedScopes, strings.Fields(r.FormValue("scope")))
	log.Printf("[TOKEN/cc] issuing token for client_id=%q scopes=%v", clientID, granted)
	tok, err := token.Generate(h.cfg.Server.JWTSecret, h.cfg.Server.Issuer, clientID, granted, h.cfg.Server.TokenTTL)
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

// handleAuthorizationCode processes the OAuth 2.1 authorization_code grant:
// it authenticates the client, consumes the single-use authorization code,
// verifies the client binding, redirect_uri and PKCE challenge, then issues
// an access token for the code's subject and scopes.
//
// @arg w HTTP response writer the token or error JSON is written to.
// @arg r Token request carrying the code, redirect_uri, code_verifier and client credentials.
//
// @testcase TestAuthorizationCode_PublicClient_Success verifies a public client (PKCE only) can exchange a code.
// @testcase TestAuthorizationCode_ConfidentialClient_Success verifies a confidential client with the correct secret can exchange a code.
// @testcase TestAuthorizationCode_ConfidentialClient_WrongSecret verifies a wrong client secret yields 401.
// @testcase TestAuthorizationCode_UnknownClient verifies an unknown client yields 401.
// @testcase TestAuthorizationCode_MissingCode verifies a missing code or verifier yields 400.
// @testcase TestAuthorizationCode_UnknownCode verifies an unknown code yields 400.
// @testcase TestAuthorizationCode_ClientIDMismatch verifies a code bound to another client is rejected.
// @testcase TestAuthorizationCode_RedirectURIMismatch verifies a mismatched redirect_uri is rejected.
// @testcase TestAuthorizationCode_BadPKCE verifies a wrong code_verifier fails PKCE.
// @testcase TestAuthorizationCode_CodeIsSingleUse verifies a code cannot be replayed.
// @testcase TestAuthorizationCode_ExpiredCode verifies an expired code is rejected.
// @testcase TestAuthorizationCode_IssuesRefreshToken verifies a refresh_token is returned.
func (h *Handler) handleAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	client, ok := h.authenticateClient(w, r)
	if !ok {
		return
	}
	clientID := client.ClientID

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")
	// Never log the authorization code or PKCE verifier — they are short-lived
	// credentials that could be replayed if logs leak.
	log.Printf("[TOKEN/ac] redirect_uri=%q code_len=%d code_verifier_len=%d", redirectURI, len(code), len(codeVerifier))
	if code == "" || codeVerifier == "" {
		log.Printf("[TOKEN/ac] missing code or code_verifier")
		writeError(w, "invalid_request", "code and code_verifier are required", http.StatusBadRequest)
		return
	}

	ac := h.store.ConsumeAuthCode(code)
	if ac == nil {
		log.Printf("[TOKEN/ac] authorization code not found or expired")
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
		log.Printf("[TOKEN/ac] PKCE verification failed for client_id=%q", clientID)
		writeError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
		return
	}

	log.Printf("[TOKEN/ac] issuing token for subject=%q client_id=%q scopes=%v", ac.Subject, clientID, ac.Scopes)
	h.issueAccessAndRefresh(w, ac.Subject, clientID, ac.Scopes)
}

// handleRefreshToken processes the OAuth 2.0 refresh_token grant: it
// authenticates the client, consumes the (single-use, rotated) refresh token,
// verifies it belongs to the client, optionally narrows scopes, and issues a
// fresh access token plus a new refresh token.
//
// @arg w HTTP response writer the token or error JSON is written to.
// @arg r Token request carrying the refresh_token, client credentials and optional scope.
//
// @testcase TestRefreshToken_Success verifies a valid refresh token yields a new access and refresh token.
// @testcase TestRefreshToken_Rotation verifies the old refresh token is invalidated after use.
// @testcase TestRefreshToken_Unknown verifies an unknown refresh token yields invalid_grant.
// @testcase TestRefreshToken_Missing verifies a missing refresh_token yields invalid_request.
// @testcase TestRefreshToken_ClientMismatch verifies a token bound to another client is rejected.
// @testcase TestRefreshToken_WrongSecret verifies a confidential client with a wrong secret yields 401.
// @testcase TestRefreshToken_ScopeNarrowing verifies requested scopes are restricted to the original set.
func (h *Handler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	client, ok := h.authenticateClient(w, r)
	if !ok {
		return
	}

	refreshTok := r.FormValue("refresh_token")
	if refreshTok == "" {
		log.Printf("[TOKEN/rt] missing refresh_token")
		writeError(w, "invalid_request", "refresh_token is required", http.StatusBadRequest)
		return
	}

	rt := h.store.ConsumeRefreshToken(refreshTok)
	if rt == nil {
		log.Printf("[TOKEN/rt] refresh token not found or expired")
		writeError(w, "invalid_grant", "invalid or expired refresh token", http.StatusBadRequest)
		return
	}
	if rt.ClientID != client.ClientID {
		log.Printf("[TOKEN/rt] client_id mismatch: token belongs to %q, got %q", rt.ClientID, client.ClientID)
		writeError(w, "invalid_grant", "client_id mismatch", http.StatusBadRequest)
		return
	}

	// Optional scope narrowing: requested scopes must be a subset of the original.
	scopes := rt.Scopes
	if requested := strings.Fields(r.FormValue("scope")); len(requested) > 0 {
		scopes = filterScopes(rt.Scopes, requested)
	}

	log.Printf("[TOKEN/rt] refreshing token for subject=%q client_id=%q scopes=%v", rt.Subject, client.ClientID, scopes)
	h.issueAccessAndRefresh(w, rt.Subject, client.ClientID, scopes)
}

// authenticateClient resolves and authenticates the requesting client from
// Basic auth or form fields. Confidential clients must present their secret;
// public clients (PKCE) need none. On failure it writes a 401 and returns false.
//
// @arg w HTTP response writer a 401 error is written to on failure.
// @arg r Token request carrying client credentials (Basic auth or form fields).
// @return *store.Client The authenticated client.
// @return bool True if authentication succeeded; false (with a 401 written) otherwise.
//
// @testcase TestAuthorizationCode_UnknownClient verifies an unknown client yields 401.
// @testcase TestAuthorizationCode_ConfidentialClient_WrongSecret verifies a wrong secret yields 401.
// @testcase TestRefreshToken_WrongSecret verifies a wrong secret on refresh yields 401.
func (h *Handler) authenticateClient(w http.ResponseWriter, r *http.Request) (*store.Client, bool) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	if clientID == "" {
		log.Printf("[TOKEN] missing client_id")
		writeError(w, "invalid_client", "client authentication required", http.StatusUnauthorized)
		return nil, false
	}
	client := h.store.FindClient(clientID)
	if client == nil {
		log.Printf("[TOKEN] unknown client_id=%q", clientID)
		writeError(w, "invalid_client", "unknown client", http.StatusUnauthorized)
		return nil, false
	}
	if !client.IsPublic && !secureCompare(client.ClientSecret, clientSecret) {
		log.Printf("[TOKEN] secret mismatch for client_id=%q (IsPublic=%v)", clientID, client.IsPublic)
		writeError(w, "invalid_client", "invalid client credentials", http.StatusUnauthorized)
		return nil, false
	}
	return client, true
}

// issueAccessAndRefresh mints an access token and a rotating refresh token for
// the subject, persists the refresh token, and writes the token response.
//
// @arg w HTTP response writer the token JSON or error is written to.
// @arg subject The token subject (the "sub" claim).
// @arg clientID The client the issued tokens are bound to.
// @arg scopes The scopes to grant.
//
// @testcase TestAuthorizationCode_IssuesRefreshToken verifies the response includes a refresh token.
// @testcase TestRefreshToken_Success verifies a refreshed response includes new access and refresh tokens.
func (h *Handler) issueAccessAndRefresh(w http.ResponseWriter, subject, clientID string, scopes []string) {
	access, err := token.Generate(h.cfg.Server.JWTSecret, h.cfg.Server.Issuer, subject, scopes, h.cfg.Server.TokenTTL)
	if err != nil {
		log.Printf("[TOKEN] generate error: %v", err)
		writeError(w, "server_error", "failed to generate token", http.StatusInternalServerError)
		return
	}
	refresh, err := randomToken()
	if err != nil {
		log.Printf("[TOKEN] refresh token generation error: %v", err)
		writeError(w, "server_error", "failed to generate refresh token", http.StatusInternalServerError)
		return
	}
	h.store.SaveRefreshToken(&store.RefreshToken{
		Token:     refresh,
		ClientID:  clientID,
		Subject:   subject,
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(time.Duration(h.cfg.Server.RefreshTokenTTL) * time.Second),
	})

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    h.cfg.Server.TokenTTL,
		RefreshToken: refresh,
		Scope:        strings.Join(scopes, " "),
	})
}

// secureCompare reports whether a and b are equal using a constant-time
// comparison, preventing timing-based secret leakage.
//
// @arg a First string to compare (e.g. an expected secret).
// @arg b Second string to compare (e.g. a presented secret).
// @return bool True if the two strings are byte-for-byte equal.
//
// @testcase TestClientCredentials_WrongSecret verifies a mismatching secret is rejected.
// @testcase TestAuthorizationCode_ConfidentialClient_WrongSecret verifies a mismatching client secret is rejected.
func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// filterScopes returns the intersection of allowed and requested scopes.
// If no scopes are requested, all allowed scopes are granted.
//
// @arg allowed The scopes the application is permitted to receive.
// @arg requested The scopes asked for in the request; empty means "all allowed".
// @return []string The granted scopes: the requested scopes restricted to the allowed set.
//
// @testcase TestClientCredentials_ScopeEscalationFiltered verifies disallowed scopes are dropped.
// @testcase TestAuthorizePOST_ScopeEscalation_Filtered verifies disallowed scopes are dropped during the auth code flow.
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

// writeJSON serialises v as JSON to w with the given HTTP status code and an
// application/json content type.
//
// @arg w HTTP response writer to write the JSON body to.
// @arg status HTTP status code to set on the response.
// @arg v Value to serialise as the JSON response body.
//
// @testcase TestClientCredentials_BasicAuth_Success verifies a JSON token body is written on success.
// @testcase TestMetadata_ContentType verifies the application/json content type is set.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes an OAuth 2.0 error response as JSON with a no-store cache
// directive and the given HTTP status code.
//
// @arg w HTTP response writer to write the error body to.
// @arg errCode OAuth 2.0 error code (e.g. invalid_client, invalid_grant).
// @arg desc Human-readable error description; omitted from the body when empty.
// @arg status HTTP status code to set on the response.
//
// @testcase TestToken_UnsupportedGrant verifies an error body is written for an unsupported grant.
// @testcase TestClientCredentials_MissingClientID verifies an error body is written when authentication is missing.
func writeError(w http.ResponseWriter, errCode, desc string, status int) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, errorResponse{Error: errCode, ErrorDescription: desc})
}
