package store

import (
	"testing"
	"time"
)

// TestNew verifies all internal maps are initialized.
//
// @arg t The testing context provided by the Go test runner.
func TestNew(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("expected non-nil store")
	}
	if s.clients == nil {
		t.Error("expected clients map to be initialized")
	}
	if s.codes == nil {
		t.Error("expected codes map to be initialized")
	}
	if s.oidcStates == nil {
		t.Error("expected oidcStates map to be initialized")
	}
}

// TestConsumeOIDCState_Valid verifies a saved state can be retrieved.
//
// @arg t The testing context provided by the Go test runner.
func TestConsumeOIDCState_Valid(t *testing.T) {
	s := New()
	s.SaveOIDCState(&OIDCState{State: "abc", Nonce: "n", ExpiresAt: time.Now().Add(time.Minute)})

	got := s.ConsumeOIDCState("abc")
	if got == nil {
		t.Fatal("expected to retrieve saved state")
	}
	if got.Nonce != "n" {
		t.Errorf("expected nonce n, got %q", got.Nonce)
	}
}

// TestConsumeOIDCState_SingleUse verifies a state cannot be consumed twice.
//
// @arg t The testing context provided by the Go test runner.
func TestConsumeOIDCState_SingleUse(t *testing.T) {
	s := New()
	s.SaveOIDCState(&OIDCState{State: "abc", ExpiresAt: time.Now().Add(time.Minute)})

	if s.ConsumeOIDCState("abc") == nil {
		t.Fatal("first consume should succeed")
	}
	if s.ConsumeOIDCState("abc") != nil {
		t.Error("second consume must return nil (single use)")
	}
}

// TestConsumeOIDCState_Expired verifies an expired state is rejected.
//
// @arg t The testing context provided by the Go test runner.
func TestConsumeOIDCState_Expired(t *testing.T) {
	s := New()
	s.SaveOIDCState(&OIDCState{State: "abc", ExpiresAt: time.Now().Add(-time.Minute)})

	if s.ConsumeOIDCState("abc") != nil {
		t.Error("expired state must return nil")
	}
}

// TestConsumeOIDCState_Unknown verifies an unknown state returns nil.
//
// @arg t The testing context provided by the Go test runner.
func TestConsumeOIDCState_Unknown(t *testing.T) {
	s := New()
	if s.ConsumeOIDCState("missing") != nil {
		t.Error("unknown state must return nil")
	}
}

// TestConsumeRefreshToken_Valid verifies a saved refresh token can be retrieved.
//
// @arg t The testing context provided by the Go test runner.
func TestConsumeRefreshToken_Valid(t *testing.T) {
	s := New()
	s.SaveRefreshToken(&RefreshToken{
		Token:     "rt1",
		ClientID:  "client1",
		Subject:   "alice",
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(time.Hour),
	})

	got := s.ConsumeRefreshToken("rt1")
	if got == nil {
		t.Fatal("expected to retrieve saved refresh token")
	}
	if got.Subject != "alice" || got.ClientID != "client1" {
		t.Errorf("unexpected refresh token: %+v", got)
	}
}

// TestConsumeRefreshToken_SingleUse verifies a refresh token cannot be consumed twice.
//
// @arg t The testing context provided by the Go test runner.
func TestConsumeRefreshToken_SingleUse(t *testing.T) {
	s := New()
	s.SaveRefreshToken(&RefreshToken{Token: "rt1", ExpiresAt: time.Now().Add(time.Hour)})

	if s.ConsumeRefreshToken("rt1") == nil {
		t.Fatal("first consume should succeed")
	}
	if s.ConsumeRefreshToken("rt1") != nil {
		t.Error("second consume must return nil (single use)")
	}
}

// TestConsumeRefreshToken_Expired verifies an expired refresh token is rejected.
//
// @arg t The testing context provided by the Go test runner.
func TestConsumeRefreshToken_Expired(t *testing.T) {
	s := New()
	s.SaveRefreshToken(&RefreshToken{Token: "rt1", ExpiresAt: time.Now().Add(-time.Minute)})

	if s.ConsumeRefreshToken("rt1") != nil {
		t.Error("expired refresh token must return nil")
	}
}

// TestConsumeRefreshToken_Unknown verifies an unknown refresh token returns nil.
//
// @arg t The testing context provided by the Go test runner.
func TestConsumeRefreshToken_Unknown(t *testing.T) {
	s := New()
	if s.ConsumeRefreshToken("missing") != nil {
		t.Error("unknown refresh token must return nil")
	}
}

// TestRegisterClient_Confidential verifies a confidential client gets a secret and is stored.
//
// @arg t The testing context provided by the Go test runner.
func TestRegisterClient_Confidential(t *testing.T) {
	s := New()
	redirectURIs := []string{"https://example.com/callback"}
	c, err := s.RegisterClient(redirectURIs, "test-app", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ClientID == "" {
		t.Error("expected non-empty ClientID")
	}
	if c.ClientSecret == "" {
		t.Error("expected non-empty ClientSecret for confidential client")
	}
	if c.IsPublic {
		t.Error("expected IsPublic to be false")
	}
	if c.ClientName != "test-app" {
		t.Errorf("expected ClientName %q, got %q", "test-app", c.ClientName)
	}
	if len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != redirectURIs[0] {
		t.Errorf("unexpected RedirectURIs: %v", c.RedirectURIs)
	}
	if c.RegisteredAt.IsZero() {
		t.Error("expected non-zero RegisteredAt")
	}
}

// TestRegisterClient_Public verifies a public client has no secret.
//
// @arg t The testing context provided by the Go test runner.
func TestRegisterClient_Public(t *testing.T) {
	s := New()
	c, err := s.RegisterClient([]string{"https://example.com/callback"}, "public-app", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ClientSecret != "" {
		t.Error("expected empty ClientSecret for public client")
	}
	if !c.IsPublic {
		t.Error("expected IsPublic to be true")
	}
}

// TestRegisterClient_UniqueIDs verifies distinct clients get distinct IDs and secrets.
//
// @arg t The testing context provided by the Go test runner.
func TestRegisterClient_UniqueIDs(t *testing.T) {
	s := New()
	a, err := s.RegisterClient(nil, "a", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b, err := s.RegisterClient(nil, "b", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.ClientID == b.ClientID {
		t.Error("expected unique ClientIDs")
	}
	if a.ClientSecret == b.ClientSecret {
		t.Error("expected unique ClientSecrets")
	}
}

// TestRegisterClient_StoredAndRetrievable verifies a registered client is retrievable via FindClient.
//
// @arg t The testing context provided by the Go test runner.
func TestRegisterClient_StoredAndRetrievable(t *testing.T) {
	s := New()
	c, err := s.RegisterClient([]string{"https://example.com/cb"}, "app", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := s.FindClient(c.ClientID)
	if found == nil {
		t.Fatal("expected client to be stored")
	}
	if found.ClientID != c.ClientID {
		t.Errorf("expected %q, got %q", c.ClientID, found.ClientID)
	}
}

// TestPutClient verifies a pre-assigned client is stored and retrievable.
//
// @arg t The testing context provided by the Go test runner.
func TestPutClient(t *testing.T) {
	s := New()
	c := &Client{
		ClientID:     "fixed-id",
		ClientSecret: "fixed-secret",
		RedirectURIs: []string{"https://example.com/cb"},
		ClientName:   "fixed-app",
		IsPublic:     false,
		RegisteredAt: time.Now(),
	}
	s.PutClient(c)

	found := s.FindClient("fixed-id")
	if found == nil {
		t.Fatal("expected client to be stored")
	}
	if found.ClientSecret != "fixed-secret" {
		t.Errorf("expected ClientSecret %q, got %q", "fixed-secret", found.ClientSecret)
	}
}

// TestPutClient_Replace verifies PutClient replaces an existing client with the same ID.
//
// @arg t The testing context provided by the Go test runner.
func TestPutClient_Replace(t *testing.T) {
	s := New()
	original := &Client{ClientID: "id1", ClientName: "original"}
	s.PutClient(original)

	updated := &Client{ClientID: "id1", ClientName: "updated"}
	s.PutClient(updated)

	found := s.FindClient("id1")
	if found.ClientName != "updated" {
		t.Errorf("expected %q, got %q", "updated", found.ClientName)
	}
}

// TestFindClient_NotFound verifies FindClient returns nil for an unknown client.
//
// @arg t The testing context provided by the Go test runner.
func TestFindClient_NotFound(t *testing.T) {
	s := New()
	found := s.FindClient("nonexistent")
	if found != nil {
		t.Error("expected nil for unknown client")
	}
}

// TestSaveAndConsumeAuthCode verifies a saved authorization code can be consumed.
//
// @arg t The testing context provided by the Go test runner.
func TestSaveAndConsumeAuthCode(t *testing.T) {
	s := New()
	ac := &AuthCode{
		Code:      "authcode123",
		ClientID:  "client1",
		Subject:   "user1",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	s.SaveAuthCode(ac)

	got := s.ConsumeAuthCode("authcode123")
	if got == nil {
		t.Fatal("expected to retrieve auth code")
	}
	if got.Code != "authcode123" {
		t.Errorf("expected code %q, got %q", "authcode123", got.Code)
	}
}

// TestConsumeAuthCode_DeletesOnConsume verifies an authorization code is single-use.
//
// @arg t The testing context provided by the Go test runner.
func TestConsumeAuthCode_DeletesOnConsume(t *testing.T) {
	s := New()
	ac := &AuthCode{
		Code:      "code-once",
		ClientID:  "client1",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	s.SaveAuthCode(ac)

	first := s.ConsumeAuthCode("code-once")
	if first == nil {
		t.Fatal("expected first consume to succeed")
	}
	second := s.ConsumeAuthCode("code-once")
	if second != nil {
		t.Error("expected second consume to return nil (code already used)")
	}
}

// TestConsumeAuthCode_Expired verifies an expired authorization code is rejected.
//
// @arg t The testing context provided by the Go test runner.
func TestConsumeAuthCode_Expired(t *testing.T) {
	s := New()
	ac := &AuthCode{
		Code:      "expired-code",
		ClientID:  "client1",
		ExpiresAt: time.Now().Add(-1 * time.Second),
	}
	s.SaveAuthCode(ac)

	got := s.ConsumeAuthCode("expired-code")
	if got != nil {
		t.Error("expected nil for expired auth code")
	}
}

// TestConsumeAuthCode_NotFound verifies ConsumeAuthCode returns nil for an unknown code.
//
// @arg t The testing context provided by the Go test runner.
func TestConsumeAuthCode_NotFound(t *testing.T) {
	s := New()
	got := s.ConsumeAuthCode("nonexistent")
	if got != nil {
		t.Error("expected nil for unknown code")
	}
}
