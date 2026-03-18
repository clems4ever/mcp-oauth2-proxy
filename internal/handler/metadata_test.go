package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/store"
)

const testIssuer = "https://auth.example.com"

func newTestHandler() *Handler {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Issuer: testIssuer,
		},
	}
	return New(cfg, store.New())
}

func TestMetadata_StatusOK(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()

	h.Metadata(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestMetadata_ContentType(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()

	h.Metadata(rr, req)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestMetadata_Body(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()

	h.Metadata(rr, req)

	var resp metadataResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Issuer != testIssuer {
		t.Errorf("expected Issuer %q, got %q", testIssuer, resp.Issuer)
	}
	if resp.AuthorizationEndpoint != testIssuer+"/oauth2/authorize" {
		t.Errorf("unexpected AuthorizationEndpoint: %q", resp.AuthorizationEndpoint)
	}
	if resp.TokenEndpoint != testIssuer+"/oauth2/token" {
		t.Errorf("unexpected TokenEndpoint: %q", resp.TokenEndpoint)
	}
	if resp.RegistrationEndpoint != testIssuer+"/oauth2/register" {
		t.Errorf("unexpected RegistrationEndpoint: %q", resp.RegistrationEndpoint)
	}

	if len(resp.ResponseTypesSupported) != 1 || resp.ResponseTypesSupported[0] != "code" {
		t.Errorf("unexpected ResponseTypesSupported: %v", resp.ResponseTypesSupported)
	}
	if len(resp.CodeChallengeMethodsSupported) != 1 || resp.CodeChallengeMethodsSupported[0] != "S256" {
		t.Errorf("unexpected CodeChallengeMethodsSupported: %v", resp.CodeChallengeMethodsSupported)
	}

	expectedGrantTypes := map[string]bool{"authorization_code": true, "client_credentials": true}
	for _, gt := range resp.GrantTypesSupported {
		delete(expectedGrantTypes, gt)
	}
	if len(expectedGrantTypes) != 0 {
		t.Errorf("missing grant types: %v", expectedGrantTypes)
	}

	expectedAuthMethods := map[string]bool{
		"client_secret_basic": true,
		"client_secret_post":  true,
		"none":                true,
	}
	for _, m := range resp.TokenEndpointAuthMethodsSupported {
		delete(expectedAuthMethods, m)
	}
	if len(expectedAuthMethods) != 0 {
		t.Errorf("missing token endpoint auth methods: %v", expectedAuthMethods)
	}
}

func TestProtectedResource_StatusOK(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()

	h.ProtectedResource(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestProtectedResource_ContentType(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()

	h.ProtectedResource(rr, req)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestProtectedResource_Body(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()

	h.ProtectedResource(rr, req)

	var resp protectedResourceResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Resource != testIssuer {
		t.Errorf("expected Resource %q, got %q", testIssuer, resp.Resource)
	}
	if len(resp.AuthorizationServers) != 1 || resp.AuthorizationServers[0] != testIssuer {
		t.Errorf("unexpected AuthorizationServers: %v", resp.AuthorizationServers)
	}
	if len(resp.BearerMethodsSupported) != 1 || resp.BearerMethodsSupported[0] != "header" {
		t.Errorf("unexpected BearerMethodsSupported: %v", resp.BearerMethodsSupported)
	}
}
