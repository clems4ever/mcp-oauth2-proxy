package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
	josev4 "github.com/go-jose/go-jose/v4"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

const testKID = "test-key"

// mockIDP is a minimal OIDC provider for tests: it serves a discovery document,
// a JWKS, and a token endpoint that returns a signed ID token built from the
// fields below.
type mockIDP struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	clientID string

	// ID-token claims returned by the token endpoint (set per test).
	email         string
	emailVerified bool
	nonce         string
}

// newMockIDP starts a mock OIDC provider (discovery, JWKS, token endpoint).
//
// @arg t The testing context provided by the Go test runner.
// @arg clientID The client ID the provider issues ID tokens for.
// @return *mockIDP The running mock provider; its HTTP server is closed at test cleanup.
func newMockIDP(t *testing.T, clientID string) *mockIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	m := &mockIDP{key: key, clientID: clientID, emailVerified: true}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                m.server.URL,
			"authorization_endpoint":                m.server.URL + "/auth",
			"token_endpoint":                        m.server.URL + "/token",
			"jwks_uri":                              m.server.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		set := josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
			Key:       &m.key.PublicKey,
			KeyID:     testKID,
			Algorithm: "RS256",
			Use:       "sig",
		}}}
		writeJSON(w, set)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"access_token": "access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     m.signIDToken(t),
		})
	})

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

// signIDToken returns an RS256-signed ID token built from the provider's
// current claim fields.
//
// @arg t The testing context provided by the Go test runner.
// @return string The compact signed ID token.
func (m *mockIDP) signIDToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{
		"iss":            m.server.URL,
		"aud":            m.clientID,
		"sub":            "subject-123",
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
		"email":          m.email,
		"email_verified": m.emailVerified,
		"nonce":          m.nonce,
	})
	tok.Header["kid"] = testKID
	signed, err := tok.SignedString(m.key)
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	return signed
}

// writeJSON encodes v as a JSON response body.
//
// @arg w HTTP response writer to write to.
// @arg v Value to encode as JSON.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// newClient builds an oidc.Client pointed at the mock provider.
//
// @arg t The testing context provided by the Go test runner.
// @arg allowed The email addresses to allow.
// @return *Client A client wired to the mock provider.
func (m *mockIDP) newClient(t *testing.T, allowed ...string) *Client {
	t.Helper()
	c, err := New(context.Background(), &config.OIDCConfig{
		Issuer:        m.server.URL,
		ClientID:      m.clientID,
		ClientSecret:  "secret",
		RedirectURL:   "https://proxy.example.com/oauth2/oidc/callback",
		Scopes:        []string{"openid", "email"},
		AllowedEmails: allowed,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// TestNew_DiscoveryError verifies New fails when the issuer is unreachable.
//
// @arg t The testing context provided by the Go test runner.
func TestNew_DiscoveryError(t *testing.T) {
	_, err := New(context.Background(), &config.OIDCConfig{Issuer: "http://127.0.0.1:1/nope"})
	if err == nil {
		t.Error("expected discovery error for unreachable issuer")
	}
}

// TestAuthCodeURL verifies the provider URL carries client_id, state, nonce and redirect_uri.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthCodeURL(t *testing.T) {
	idp := newMockIDP(t, "client-1")
	c := idp.newClient(t, "a@example.com")

	raw := c.AuthCodeURL("state-xyz", "nonce-abc")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	q := u.Query()
	if q.Get("client_id") != "client-1" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("state") != "state-xyz" {
		t.Errorf("state = %q", q.Get("state"))
	}
	if q.Get("nonce") != "nonce-abc" {
		t.Errorf("nonce = %q", q.Get("nonce"))
	}
	if q.Get("redirect_uri") != "https://proxy.example.com/oauth2/oidc/callback" {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
}

// TestExchange_Success verifies a valid code yields the verified email.
//
// @arg t The testing context provided by the Go test runner.
func TestExchange_Success(t *testing.T) {
	idp := newMockIDP(t, "client-1")
	idp.email = "alice@example.com"
	idp.nonce = "the-nonce"
	c := idp.newClient(t, "alice@example.com")

	email, err := c.Exchange(context.Background(), "any-code", "the-nonce")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if email != "alice@example.com" {
		t.Errorf("expected alice@example.com, got %q", email)
	}
}

// TestExchange_NonceMismatch verifies a mismatched nonce is rejected.
//
// @arg t The testing context provided by the Go test runner.
func TestExchange_NonceMismatch(t *testing.T) {
	idp := newMockIDP(t, "client-1")
	idp.email = "alice@example.com"
	idp.nonce = "server-nonce"
	c := idp.newClient(t, "alice@example.com")

	if _, err := c.Exchange(context.Background(), "code", "different-nonce"); err == nil {
		t.Error("expected nonce mismatch error")
	}
}

// TestExchange_UnverifiedEmail verifies an unverified email is rejected.
//
// @arg t The testing context provided by the Go test runner.
func TestExchange_UnverifiedEmail(t *testing.T) {
	idp := newMockIDP(t, "client-1")
	idp.email = "alice@example.com"
	idp.emailVerified = false
	idp.nonce = "n"
	c := idp.newClient(t, "alice@example.com")

	if _, err := c.Exchange(context.Background(), "code", "n"); err == nil {
		t.Error("expected error for unverified email")
	}
}

// TestEmailAllowed verifies case-insensitive allowlist matching.
//
// @arg t The testing context provided by the Go test runner.
func TestEmailAllowed(t *testing.T) {
	idp := newMockIDP(t, "client-1")
	c := idp.newClient(t, "Alice@Example.com", "bob@example.com")

	if !c.EmailAllowed("alice@example.com") {
		t.Error("expected case-insensitive match for alice")
	}
	if !c.EmailAllowed("BOB@EXAMPLE.COM") {
		t.Error("expected case-insensitive match for bob")
	}
	if c.EmailAllowed("eve@example.com") {
		t.Error("eve must not be allowed")
	}
}
