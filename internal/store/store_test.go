package store

import (
	"testing"
	"time"
)

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
}

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

func TestFindClient_NotFound(t *testing.T) {
	s := New()
	found := s.FindClient("nonexistent")
	if found != nil {
		t.Error("expected nil for unknown client")
	}
}

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

func TestConsumeAuthCode_NotFound(t *testing.T) {
	s := New()
	got := s.ConsumeAuthCode("nonexistent")
	if got != nil {
		t.Error("expected nil for unknown code")
	}
}
