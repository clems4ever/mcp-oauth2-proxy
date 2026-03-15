package store

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// DynamicClient is a client registered via dynamic client registration (RFC 7591).
type DynamicClient struct {
	ClientID     string
	ClientSecret string // empty for public clients
	RedirectURIs []string
	ClientName   string
	IsPublic     bool
	RegisteredAt time.Time
}

// AuthCode is a pending authorization code awaiting exchange.
type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	Subject             string
	ExpiresAt           time.Time
}

// Store is the in-memory authorization server state.
type Store struct {
	mu      sync.RWMutex
	clients map[string]*DynamicClient
	codes   map[string]*AuthCode
}

// New creates a new Store.
func New() *Store {
	return &Store{
		clients: make(map[string]*DynamicClient),
		codes:   make(map[string]*AuthCode),
	}
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RegisterClient creates and persists a new dynamic client.
func (s *Store) RegisterClient(redirectURIs []string, name string, isPublic bool) (*DynamicClient, error) {
	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}

	var secret string
	if !isPublic {
		secret, err = randomHex(32)
		if err != nil {
			return nil, err
		}
	}

	c := &DynamicClient{
		ClientID:     id,
		ClientSecret: secret,
		RedirectURIs: redirectURIs,
		ClientName:   name,
		IsPublic:     isPublic,
		RegisteredAt: time.Now(),
	}
	s.mu.Lock()
	s.clients[id] = c
	s.mu.Unlock()
	return c, nil
}

// PutClient inserts (or replaces) a client with a pre-assigned ID.
func (s *Store) PutClient(c *DynamicClient) {
	s.mu.Lock()
	s.clients[c.ClientID] = c
	s.mu.Unlock()
}

// FindClient returns the dynamic client with the given ID, or nil.
func (s *Store) FindClient(clientID string) *DynamicClient {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clients[clientID]
}

// SaveAuthCode stores an authorization code.
func (s *Store) SaveAuthCode(ac *AuthCode) {
	s.mu.Lock()
	s.codes[ac.Code] = ac
	s.mu.Unlock()
}

// ConsumeAuthCode atomically retrieves and deletes an authorization code.
// Returns nil if not found or expired.
func (s *Store) ConsumeAuthCode(code string) *AuthCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[code]
	if !ok {
		return nil
	}
	delete(s.codes, code)
	if time.Now().After(ac.ExpiresAt) {
		return nil
	}
	return ac
}
