package store

import (
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// TestStore_PersistsRefreshAcrossReopen verifies refresh tokens survive closing
// and reopening the on-disk store.
//
// @arg t The testing context provided by the Go test runner.
func TestStore_PersistsRefreshAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")

	s1, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s1.SaveRefreshToken(&RefreshToken{
		Token:     "rt",
		ClientID:  "client1",
		Subject:   "alice",
		Scopes:    []string{"read"},
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	got := s2.ConsumeRefreshToken("rt")
	if got == nil {
		t.Fatal("refresh token did not survive reopen")
	}
	if got.Subject != "alice" || got.ClientID != "client1" {
		t.Errorf("unexpected token after reopen: %+v", got)
	}
}

// TestStore_BoltConsumeSingleUse verifies the bolt backend enforces single-use consumption.
//
// @arg t The testing context provided by the Go test runner.
func TestStore_BoltConsumeSingleUse(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.SaveRefreshToken(&RefreshToken{Token: "rt", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}
	if s.ConsumeRefreshToken("rt") == nil {
		t.Fatal("first consume should succeed")
	}
	if s.ConsumeRefreshToken("rt") != nil {
		t.Error("second consume must return nil (single use)")
	}
}

// TestStore_BoltExpiredRejected verifies the bolt backend rejects an expired token on consume.
//
// @arg t The testing context provided by the Go test runner.
func TestStore_BoltExpiredRejected(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.SaveRefreshToken(&RefreshToken{Token: "rt", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}
	if s.ConsumeRefreshToken("rt") != nil {
		t.Error("expired token must return nil")
	}
}

// TestStore_InMemoryClose verifies closing an in-memory store is a no-op that returns no error.
//
// @arg t The testing context provided by the Go test runner.
func TestStore_InMemoryClose(t *testing.T) {
	if err := New().Close(); err != nil {
		t.Errorf("closing an in-memory store should not error, got %v", err)
	}
}

// TestBoltRefresh_SweepsExpired verifies the sweeper purges expired tokens while keeping valid ones.
//
// @arg t The testing context provided by the Go test runner.
func TestBoltRefresh_SweepsExpired(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.SaveRefreshToken(&RefreshToken{Token: "old", ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}
	if err := s.SaveRefreshToken(&RefreshToken{Token: "new", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	b := s.refresh.(*boltRefresh)
	b.sweepExpired()

	remaining := 0
	_ = b.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(refreshBucket).ForEach(func(k, v []byte) error {
			remaining++
			return nil
		})
	})
	if remaining != 1 {
		t.Errorf("expected 1 token after sweep, got %d", remaining)
	}
	if s.ConsumeRefreshToken("new") == nil {
		t.Error("valid token should remain after sweep")
	}
}
