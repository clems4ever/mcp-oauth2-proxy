package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig writes body to a temporary YAML file and returns its path.
//
// @arg t The testing context, used for temp-dir creation and fatal errors.
// @arg body The YAML document to write to the temporary config file.
// @return string The path to the written temporary config file.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestLoad_AppliesDefaults verifies Load fills in default port, TTLs and issuer when unset.
//
// @arg t The testing context provided by the Go test runner.
func TestLoad_AppliesDefaults(t *testing.T) {
	path := writeConfig(t, `
server:
  jwt_secret: secret
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Server.Port)
	}
	if cfg.Server.TokenTTL != 3600 {
		t.Errorf("expected default token_ttl 3600, got %d", cfg.Server.TokenTTL)
	}
	if cfg.Server.AuthCodeTTL != 300 {
		t.Errorf("expected default auth_code_ttl 300, got %d", cfg.Server.AuthCodeTTL)
	}
	if cfg.Server.Issuer != "http://localhost:8080" {
		t.Errorf("expected default issuer, got %q", cfg.Server.Issuer)
	}
}

// TestLoad_KeepsExplicitValues verifies Load preserves explicitly configured values instead of defaulting them.
//
// @arg t The testing context provided by the Go test runner.
func TestLoad_KeepsExplicitValues(t *testing.T) {
	path := writeConfig(t, `
server:
  port: 9000
  issuer: https://auth.example.com
  jwt_secret: secret
  token_ttl: 60
  auth_code_ttl: 120
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 9000 || cfg.Server.Issuer != "https://auth.example.com" ||
		cfg.Server.TokenTTL != 60 || cfg.Server.AuthCodeTTL != 120 {
		t.Errorf("explicit values overwritten: %+v", cfg.Server)
	}
}

// TestLoad_MissingFile verifies Load returns an error when the config file does not exist.
//
// @arg t The testing context provided by the Go test runner.
func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
}

// TestLoad_InvalidYAML verifies Load returns an error when the config file is not valid YAML.
//
// @arg t The testing context provided by the Go test runner.
func TestLoad_InvalidYAML(t *testing.T) {
	path := writeConfig(t, "server: : :\n  bad")
	if _, err := Load(path); err == nil {
		t.Error("expected error for invalid YAML")
	}
}

// TestFindUser verifies FindUser returns a matching user and nil for an unknown username.
//
// @arg t The testing context provided by the Go test runner.
func TestFindUser(t *testing.T) {
	cfg := &Config{Users: []User{{Username: "alice", Password: "h"}}}
	if u := cfg.FindUser("alice"); u == nil || u.Username != "alice" {
		t.Errorf("expected to find alice, got %+v", u)
	}
	if u := cfg.FindUser("bob"); u != nil {
		t.Errorf("expected nil for unknown user, got %+v", u)
	}
}
