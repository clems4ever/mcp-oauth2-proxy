package store

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// refreshBackend abstracts refresh-token persistence so the store can run fully
// in-memory or back refresh tokens with an on-disk bbolt database.
type refreshBackend interface {
	save(rt *RefreshToken) error
	consume(token string) (*RefreshToken, error)
	close() error
}

// --- in-memory backend ---

// memRefresh is a process-local, non-persistent refresh-token backend.
type memRefresh struct {
	mu sync.Mutex
	m  map[string]*RefreshToken
}

// newMemRefresh creates an empty in-memory refresh-token backend.
//
// @return *memRefresh An empty in-memory backend.
//
// @testcase TestConsumeRefreshToken_Valid verifies the in-memory backend stores and returns tokens.
func newMemRefresh() *memRefresh {
	return &memRefresh{m: make(map[string]*RefreshToken)}
}

// save stores rt keyed by its token value.
//
// @arg rt The refresh token to store.
// @error Always nil for the in-memory backend.
//
// @testcase TestConsumeRefreshToken_Valid verifies a saved token can be retrieved.
func (m *memRefresh) save(rt *RefreshToken) error {
	m.mu.Lock()
	m.m[rt.Token] = rt
	m.mu.Unlock()
	return nil
}

// consume atomically removes and returns the token, or nil if absent/expired.
//
// @arg token The refresh token value to consume.
// @return *RefreshToken The stored token, or nil if not found or expired.
// @error Always nil for the in-memory backend.
//
// @testcase TestConsumeRefreshToken_SingleUse verifies single-use consumption.
// @testcase TestConsumeRefreshToken_Expired verifies expired tokens are rejected.
// @testcase TestConsumeRefreshToken_Unknown verifies unknown tokens return nil.
func (m *memRefresh) consume(token string) (*RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rt, ok := m.m[token]
	if !ok {
		return nil, nil
	}
	delete(m.m, token)
	if time.Now().After(rt.ExpiresAt) {
		return nil, nil
	}
	return rt, nil
}

// close is a no-op for the in-memory backend.
//
// @error Always nil.
//
// @testcase TestStore_InMemoryClose verifies closing an in-memory store is a no-op.
func (m *memRefresh) close() error { return nil }

// --- bbolt backend ---

var refreshBucket = []byte("refresh_tokens")

// sweepInterval is how often the bolt backend purges expired refresh tokens.
const sweepInterval = time.Hour

// boltRefresh is a durable refresh-token backend backed by a bbolt database.
type boltRefresh struct {
	db   *bolt.DB
	stop chan struct{}
}

// newBoltRefresh opens (or creates) the bbolt database at path, purges any
// already-expired tokens, and starts a background expiry sweeper.
//
// @arg path Filesystem path to the bbolt database file.
// @return *boltRefresh A ready bolt-backed refresh store.
// @error Returns an error if the database cannot be opened or initialised.
//
// @testcase TestStore_PersistsRefreshAcrossReopen verifies the database opens and persists tokens.
func newBoltRefresh(path string) (*boltRefresh, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("opening bolt db %q: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(refreshBucket)
		return e
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("creating bucket: %w", err)
	}
	b := &boltRefresh{db: db, stop: make(chan struct{})}
	b.sweepExpired()
	go b.sweepLoop()
	return b, nil
}

// save persists rt as JSON keyed by its token value.
//
// @arg rt The refresh token to persist.
// @error Returns an error if encoding or the write transaction fails.
//
// @testcase TestStore_PersistsRefreshAcrossReopen verifies a saved token is persisted.
func (b *boltRefresh) save(rt *RefreshToken) error {
	data, err := json.Marshal(rt)
	if err != nil {
		return err
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(refreshBucket).Put([]byte(rt.Token), data)
	})
}

// consume atomically deletes and returns the token, or nil if absent/expired.
//
// @arg token The refresh token value to consume.
// @return *RefreshToken The stored token, or nil if not found or expired.
// @error Returns an error if the transaction or decoding fails.
//
// @testcase TestStore_BoltConsumeSingleUse verifies single-use consumption.
// @testcase TestStore_BoltExpiredRejected verifies expired tokens are rejected.
func (b *boltRefresh) consume(token string) (*RefreshToken, error) {
	var rt *RefreshToken
	err := b.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(refreshBucket)
		data := bk.Get([]byte(token))
		if data == nil {
			return nil
		}
		if err := bk.Delete([]byte(token)); err != nil {
			return err
		}
		var r RefreshToken
		if err := json.Unmarshal(data, &r); err != nil {
			return err
		}
		rt = &r
		return nil
	})
	if err != nil {
		return nil, err
	}
	if rt == nil || time.Now().After(rt.ExpiresAt) {
		return nil, nil
	}
	return rt, nil
}

// sweepExpired removes all expired (or unparseable) refresh tokens.
//
// @testcase TestBoltRefresh_SweepsExpired verifies expired tokens are purged.
func (b *boltRefresh) sweepExpired() {
	now := time.Now()
	_ = b.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(refreshBucket)
		var stale [][]byte
		_ = bk.ForEach(func(k, v []byte) error {
			var r RefreshToken
			if json.Unmarshal(v, &r) != nil || now.After(r.ExpiresAt) {
				stale = append(stale, append([]byte(nil), k...))
			}
			return nil
		})
		for _, k := range stale {
			_ = bk.Delete(k)
		}
		return nil
	})
}

// sweepLoop periodically sweeps expired tokens until close is called.
//
// @testcase TestBoltRefresh_SweepsExpired verifies the periodic sweep removes expired tokens.
func (b *boltRefresh) sweepLoop() {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-t.C:
			b.sweepExpired()
		}
	}
}

// close stops the sweeper and closes the database.
//
// @error Returns an error if closing the database fails.
//
// @testcase TestStore_PersistsRefreshAcrossReopen verifies the store closes and reopens cleanly.
func (b *boltRefresh) close() error {
	close(b.stop)
	return b.db.Close()
}
