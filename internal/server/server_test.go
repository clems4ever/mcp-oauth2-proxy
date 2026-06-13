package server

import (
	"testing"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
)

// baseConfig returns a minimal valid configuration (with a JWT secret and
// application credentials) for exercising server.New.
//
// @return *config.Config A configuration that allows New to build a server without panicking.
func baseConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Port:      8080,
			Issuer:    "https://auth.example.com",
			JWTSecret: "a-strong-secret",
		},
		Application: config.Application{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		},
	}
}

// TestNew_PanicsOnEmptyJWTSecret verifies that New panics when jwt_secret is empty.
//
// @arg t The testing context provided by the Go test runner.
func TestNew_PanicsOnEmptyJWTSecret(t *testing.T) {
	cfg := baseConfig()
	cfg.Server.JWTSecret = ""

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected New to panic when jwt_secret is empty")
		}
	}()

	New(cfg)
}

// TestNew_SucceedsWithJWTSecret verifies that New returns a server bound to the configured port with a handler set.
//
// @arg t The testing context provided by the Go test runner.
func TestNew_SucceedsWithJWTSecret(t *testing.T) {
	srv := New(baseConfig())
	if srv == nil {
		t.Fatal("expected a non-nil server")
	}
	if srv.Addr != ":8080" {
		t.Errorf("expected addr :8080, got %q", srv.Addr)
	}
	if srv.Handler == nil {
		t.Error("expected a non-nil handler")
	}
}
