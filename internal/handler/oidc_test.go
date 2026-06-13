package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/oidc"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/store"
)

// newDiscoveryServer starts a minimal OIDC discovery endpoint sufficient to
// build an oidc.Client (enough for AuthCodeURL; token exchange is covered in the
// oidc package tests).
// newDiscoveryServer starts a minimal OIDC discovery endpoint.
//
// @arg t The testing context provided by the Go test runner.
// @return *httptest.Server The running discovery server; closed at test cleanup.
func newDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/auth",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newOIDCHandler builds a handler with OIDC enabled, a public client registered,
// and returns the handler plus the registered client ID.
// newOIDCHandler builds a handler with OIDC enabled and a public client registered.
//
// @arg t The testing context provided by the Go test runner.
// @return *Handler The handler under test, with OIDC configured.
// @return string The registered public client ID.
func newOIDCHandler(t *testing.T) (*Handler, string) {
	t.Helper()
	srv := newDiscoveryServer(t)

	st := store.New()
	client, err := st.RegisterClient([]string{testRedirectURI}, testClientName, true)
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	oidcCfg := &config.OIDCConfig{
		Issuer:        srv.URL,
		ClientID:      "oidc-client",
		ClientSecret:  "oidc-secret",
		RedirectURL:   testIssuer + "/oauth2/oidc/callback",
		Scopes:        []string{"openid", "email"},
		AllowedEmails: []string{"alice@example.com"},
	}
	oidcClient, err := oidc.New(context.Background(), oidcCfg)
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			Issuer:      testIssuer,
			AuthCodeTTL: 300,
		},
		Application: config.Application{AllowedScopes: []string{"read", "write"}},
		OIDC:        oidcCfg,
	}
	return New(cfg, st, oidcClient), client.ClientID
}

// postOIDCLogin builds a POST /oauth2/oidc/login form request.
//
// @arg clientID The client_id to submit.
// @arg challenge The PKCE code challenge to submit.
// @return *http.Request The form-encoded login request.
func postOIDCLogin(clientID, challenge string) *http.Request {
	form := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {testRedirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"read"},
		"state":                 {"client-state"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/oidc/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// TestOIDCLogin_RedirectsToProvider verifies a valid request 302s to the provider authorize URL.
//
// @arg t The testing context provided by the Go test runner.
func TestOIDCLogin_RedirectsToProvider(t *testing.T) {
	h, clientID := newOIDCHandler(t)
	rr := httptest.NewRecorder()
	h.OIDCLogin(rr, postOIDCLogin(clientID, testCodeChallenge()))

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/auth?") {
		t.Errorf("expected redirect to provider /auth, got %q", loc)
	}
	u, _ := url.Parse(loc)
	if u.Query().Get("state") == "" || u.Query().Get("nonce") == "" {
		t.Errorf("expected state and nonce in provider URL, got %q", loc)
	}
}

// TestOIDCLogin_UnknownClient verifies an unknown client_id is rejected with 400.
//
// @arg t The testing context provided by the Go test runner.
func TestOIDCLogin_UnknownClient(t *testing.T) {
	h, _ := newOIDCHandler(t)
	rr := httptest.NewRecorder()
	h.OIDCLogin(rr, postOIDCLogin("nope", testCodeChallenge()))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestOIDCLogin_MissingPKCE verifies a missing PKCE challenge is rejected with 400.
//
// @arg t The testing context provided by the Go test runner.
func TestOIDCLogin_MissingPKCE(t *testing.T) {
	h, clientID := newOIDCHandler(t)
	rr := httptest.NewRecorder()
	h.OIDCLogin(rr, postOIDCLogin(clientID, ""))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestOIDCLogin_Disabled verifies the endpoint returns 404 when OIDC is not configured.
//
// @arg t The testing context provided by the Go test runner.
func TestOIDCLogin_Disabled(t *testing.T) {
	h, clientID := newAuthorizeHandler(t) // no OIDC configured
	rr := httptest.NewRecorder()
	h.OIDCLogin(rr, postOIDCLogin(clientID, testCodeChallenge()))
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 when OIDC disabled, got %d", rr.Code)
	}
}

// TestOIDCCallback_UnknownState verifies an unknown/expired state yields 400.
//
// @arg t The testing context provided by the Go test runner.
func TestOIDCCallback_UnknownState(t *testing.T) {
	h, _ := newOIDCHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/oidc/callback?state=bogus&code=x", nil)
	rr := httptest.NewRecorder()
	h.OIDCCallback(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown state, got %d", rr.Code)
	}
}

// TestOIDCCallback_Disabled verifies the endpoint returns 404 when OIDC is not configured.
//
// @arg t The testing context provided by the Go test runner.
func TestOIDCCallback_Disabled(t *testing.T) {
	h, _ := newAuthorizeHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/oidc/callback?state=x", nil)
	rr := httptest.NewRecorder()
	h.OIDCCallback(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 when OIDC disabled, got %d", rr.Code)
	}
}

// TestOIDCCallback_ProviderError verifies a provider error redirects to the client with access_denied.
//
// @arg t The testing context provided by the Go test runner.
func TestOIDCCallback_ProviderError(t *testing.T) {
	h, clientID := newOIDCHandler(t)
	// Seed a pending state so the callback can correlate the error to a client.
	h.store.SaveOIDCState(&store.OIDCState{
		State:       "s1",
		ClientID:    clientID,
		RedirectURI: testRedirectURI,
		ClientState: "client-state",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	})
	req := httptest.NewRequest(http.MethodGet, "/oauth2/oidc/callback?state=s1&error=access_denied", nil)
	rr := httptest.NewRecorder()
	h.OIDCCallback(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect to client, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "error=access_denied") {
		t.Errorf("expected access_denied in redirect, got %q", rr.Header().Get("Location"))
	}
}

// TestLoginForm_ShowsGoogleButtonWhenEnabled verifies the Google button appears when OIDC is enabled.
//
// @arg t The testing context provided by the Go test runner.
func TestLoginForm_ShowsGoogleButtonWhenEnabled(t *testing.T) {
	h, clientID := newOIDCHandler(t)
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"code_challenge":        {testCodeChallenge()},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "/oauth2/oidc/login") || !strings.Contains(body, "Sign in with Google") {
		t.Errorf("expected Google login button in form")
	}
}

// TestLoginForm_NoGoogleButtonWhenDisabled verifies the Google button is absent when OIDC is disabled.
//
// @arg t The testing context provided by the Go test runner.
func TestLoginForm_NoGoogleButtonWhenDisabled(t *testing.T) {
	h, clientID := newAuthorizeHandler(t)
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"code_challenge":        {testCodeChallenge()},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)

	if strings.Contains(rr.Body.String(), "Sign in with Google") {
		t.Error("Google button must not appear when OIDC is disabled")
	}
}
