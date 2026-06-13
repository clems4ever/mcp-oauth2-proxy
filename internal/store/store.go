package store

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Client is a client registered via dynamic client registration (RFC 7591).
type Client struct {
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

// OIDCState is a pending browser login awaiting return from the upstream OIDC
// provider. It carries the original MCP authorization request across the
// redirect to the provider and back.
type OIDCState struct {
	State               string // CSRF state, also the map key
	Nonce               string // OIDC nonce, echoed in the ID token
	ClientID            string
	RedirectURI         string
	Scope               string
	ClientState         string // original "state" supplied by the MCP client
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// Store is the in-memory authorization server state.
type Store struct {
	mu         sync.RWMutex
	clients    map[string]*Client
	codes      map[string]*AuthCode
	oidcStates map[string]*OIDCState
}

// New creates a new Store.
//
// @return *Store An empty store with its client, code and OIDC-state maps initialized.
//
// @testcase TestNew verifies all internal maps are initialized.
func New() *Store {
	return &Store{
		clients:    make(map[string]*Client),
		codes:      make(map[string]*AuthCode),
		oidcStates: make(map[string]*OIDCState),
	}
}

// randomHex returns a hex-encoded string of n random bytes.
//
// @arg n Number of random bytes to generate.
// @return string The hex encoding of the random bytes.
// @error Returns an error if the system random source fails.
//
// @testcase TestRegisterClient_UniqueIDs verifies randomHex produces distinct client IDs.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RegisterClient creates and persists a new dynamic client.
//
// @arg redirectURIs The client's registered redirect URIs.
// @arg name A human-readable client name.
// @arg isPublic Whether the client is public (no secret) or confidential.
// @return *Client The newly created and stored client.
// @error Returns an error if generating the client ID or secret fails.
//
// @testcase TestRegisterClient_Confidential verifies a confidential client gets a secret.
// @testcase TestRegisterClient_Public verifies a public client has no secret.
// @testcase TestRegisterClient_StoredAndRetrievable verifies the client can be looked up afterwards.
func (s *Store) RegisterClient(redirectURIs []string, name string, isPublic bool) (*Client, error) {
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

	c := &Client{
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
//
// @arg c The client to insert or replace, keyed by its ClientID.
//
// @testcase TestPutClient verifies a pre-assigned client is stored.
// @testcase TestPutClient_Replace verifies an existing client is replaced.
func (s *Store) PutClient(c *Client) {
	s.mu.Lock()
	s.clients[c.ClientID] = c
	s.mu.Unlock()
}

// FindClient returns the dynamic client with the given ID, or nil.
//
// @arg clientID The client ID to look up.
// @return *Client The matching client, or nil if not found.
//
// @testcase TestRegisterClient_StoredAndRetrievable verifies a registered client is retrievable.
func (s *Store) FindClient(clientID string) *Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clients[clientID]
}

// SaveAuthCode stores an authorization code.
//
// @arg ac The authorization code record to store, keyed by its Code.
//
// @testcase TestSaveAndConsumeAuthCode verifies a saved code can be consumed.
func (s *Store) SaveAuthCode(ac *AuthCode) {
	s.mu.Lock()
	s.codes[ac.Code] = ac
	s.mu.Unlock()
}

// ConsumeAuthCode atomically retrieves and deletes an authorization code.
// Returns nil if not found or expired.
//
// @arg code The authorization code to consume.
// @return *AuthCode The stored record, or nil if not found or expired.
//
// @testcase TestConsumeAuthCode_DeletesOnConsume verifies a code cannot be consumed twice.
// @testcase TestConsumeAuthCode_Expired verifies an expired code is rejected.
// @testcase TestConsumeAuthCode_NotFound verifies an unknown code returns nil.
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

// SaveOIDCState stores a pending OIDC login keyed by its CSRF state.
//
// @arg st The pending OIDC login to store, keyed by its State.
//
// @testcase TestConsumeOIDCState_Valid verifies a saved state can be retrieved.
func (s *Store) SaveOIDCState(st *OIDCState) {
	s.mu.Lock()
	s.oidcStates[st.State] = st
	s.mu.Unlock()
}

// ConsumeOIDCState atomically retrieves and deletes a pending OIDC login.
// Returns nil if not found or expired.
//
// @arg state The CSRF state value identifying the pending login.
// @return *OIDCState The stored pending login, or nil if not found or expired.
//
// @testcase TestConsumeOIDCState_SingleUse verifies a state cannot be consumed twice.
// @testcase TestConsumeOIDCState_Expired verifies an expired state is rejected.
// @testcase TestConsumeOIDCState_Unknown verifies an unknown state returns nil.
func (s *Store) ConsumeOIDCState(state string) *OIDCState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.oidcStates[state]
	if !ok {
		return nil
	}
	delete(s.oidcStates, state)
	if time.Now().After(st.ExpiresAt) {
		return nil
	}
	return st
}
