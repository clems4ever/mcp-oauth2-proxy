package token

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "super-secret-key-for-tests"
const testIssuer = "https://auth.example.com"

// TestGenerate_ReturnsToken verifies that Generate returns a non-empty three-part JWT for valid inputs.
//
// @arg t The testing context provided by the Go test runner.
func TestGenerate_ReturnsToken(t *testing.T) {
	tok, err := Generate(testSecret, testIssuer, "client1", []string{"read", "write"}, 3600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok == "" {
		t.Error("expected non-empty token")
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3-part JWT, got %d parts", len(parts))
	}
}

// TestGenerate_Claims verifies that the subject and scope claims are correctly embedded in the generated token.
//
// @arg t The testing context provided by the Go test runner.
func TestGenerate_Claims(t *testing.T) {
	scopes := []string{"read", "write"}
	tok, err := Generate(testSecret, testIssuer, "client42", scopes, 3600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := Verify(testSecret, testIssuer, tok)
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}
	if claims.Subject != "client42" {
		t.Errorf("expected Subject %q, got %q", "client42", claims.Subject)
	}
	if claims.Scope != "read write" {
		t.Errorf("expected Scope %q, got %q", "read write", claims.Scope)
	}
}

// TestGenerate_EmptyScopes verifies that an empty scope list results in an empty scope claim.
//
// @arg t The testing context provided by the Go test runner.
func TestGenerate_EmptyScopes(t *testing.T) {
	tok, err := Generate(testSecret, testIssuer, "client1", []string{}, 60)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	claims, err := Verify(testSecret, testIssuer, tok)
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}
	if claims.Scope != "" {
		t.Errorf("expected empty scope, got %q", claims.Scope)
	}
}

// TestGenerate_Expiry verifies that the expiry claim is set to approximately now plus ttlSeconds.
//
// @arg t The testing context provided by the Go test runner.
func TestGenerate_Expiry(t *testing.T) {
	tok, err := Generate(testSecret, testIssuer, "client1", nil, 60)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	claims, err := Verify(testSecret, testIssuer, tok)
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}
	expectedExp := time.Now().Add(60 * time.Second)
	diff := claims.ExpiresAt.Time.Sub(expectedExp)
	if diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("expiry %v differs too much from expected %v", claims.ExpiresAt.Time, expectedExp)
	}
}

// TestVerify_ValidToken verifies that a freshly generated token is accepted and claims are returned.
//
// @arg t The testing context provided by the Go test runner.
func TestVerify_ValidToken(t *testing.T) {
	tok, err := Generate(testSecret, testIssuer, "userX", []string{"admin"}, 3600)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}
	claims, err := Verify(testSecret, testIssuer, tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims == nil {
		t.Fatal("expected non-nil claims")
	}
	if claims.Subject != "userX" {
		t.Errorf("expected Subject %q, got %q", "userX", claims.Subject)
	}
}

// TestVerify_WrongSecret verifies that a token signed with a different secret is rejected.
//
// @arg t The testing context provided by the Go test runner.
func TestVerify_WrongSecret(t *testing.T) {
	tok, err := Generate(testSecret, testIssuer, "client1", nil, 3600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = Verify("wrong-secret", testIssuer, tok)
	if err == nil {
		t.Error("expected error when verifying with wrong secret")
	}
}

// TestVerify_ExpiredToken verifies that an expired token is rejected.
//
// @arg t The testing context provided by the Go test runner.
func TestVerify_ExpiredToken(t *testing.T) {
	tok, err := Generate(testSecret, testIssuer, "client1", nil, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = Verify(testSecret, testIssuer, tok)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

// TestVerify_MalformedToken verifies that a malformed token string is rejected.
//
// @arg t The testing context provided by the Go test runner.
func TestVerify_MalformedToken(t *testing.T) {
	_, err := Verify(testSecret, testIssuer, "not.a.valid.jwt.token")
	if err == nil {
		t.Error("expected error for malformed token")
	}
}

// TestVerify_WrongAlgorithm verifies that a token using an unexpected signing algorithm is rejected.
//
// @arg t The testing context provided by the Go test runner.
func TestVerify_WrongAlgorithm(t *testing.T) {
	// Craft a token signed with RS256 (asymmetric) — should be rejected.
	claims := &Claims{
		Scope: "read",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "client1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	// Use None algorithm to trigger the unexpected signing method check.
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to craft token: %v", err)
	}
	_, err = Verify(testSecret, testIssuer, signed)
	if err == nil {
		t.Error("expected error for token with unexpected signing algorithm")
	}
}
