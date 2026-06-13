package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/store"
)

const (
	testRedirectURI = "https://client.example.com/callback"
	testClientName  = "test-client"
	testUsername    = "alice"
	testPassword    = "testpassword"
	// bcrypt hash of "testpassword" at MinCost
	testPasswordHash = "$2a$04$bngpHuW0yJwtMbVRimixtO0tJWwh3TsZuEIQBusCl.y9YxpFwMnWa"
	testCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

// testCodeChallenge returns the S256 challenge for testCodeVerifier.
//
// @return string The base64url-encoded SHA-256 challenge for testCodeVerifier.
func testCodeChallenge() string {
	sum := sha256.Sum256([]byte(testCodeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newAuthorizeHandler registers a public client and a user, then returns
// the handler and the registered client ID.
//
// @arg t The testing context provided by the Go test runner.
// @return *Handler The handler under test (OIDC disabled).
// @return string The registered public client ID.
func newAuthorizeHandler(t *testing.T) (*Handler, string) {
	t.Helper()
	st := store.New()
	client, err := st.RegisterClient([]string{testRedirectURI}, testClientName, true)
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	cfg := &config.Config{
		Server: config.ServerConfig{
			Issuer:      testIssuer,
			AuthCodeTTL: 300,
		},
		Users: []config.User{
			{Username: testUsername, Password: testPasswordHash},
		},
		Application: config.Application{
			AllowedScopes: []string{"read", "write"},
		},
	}
	return New(cfg, st, nil), client.ClientID
}

// --- GET tests ---

// TestAuthorizeGET_UnknownClient verifies an unknown client_id yields 400.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizeGET_UnknownClient(t *testing.T) {
	h, _ := newAuthorizeHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?client_id=unknown&redirect_uri="+testRedirectURI+"&response_type=code", nil)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestAuthorizeGET_UnregisteredRedirectURI verifies an unregistered redirect_uri yields 400.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizeGET_UnregisteredRedirectURI(t *testing.T) {
	h, clientID := newAuthorizeHandler(t)
	q := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {"https://evil.example.com/callback"},
		"response_type": {"code"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestAuthorizeGET_WrongResponseType verifies a non-code response_type redirects with an error.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizeGET_WrongResponseType(t *testing.T) {
	h, clientID := newAuthorizeHandler(t)
	q := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {testRedirectURI},
		"response_type": {"token"},
		"state":         {"xyz"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "error=unsupported_response_type") {
		t.Errorf("expected unsupported_response_type in redirect, got %q", loc)
	}
	if !strings.Contains(loc, "state=xyz") {
		t.Errorf("expected state preserved in redirect, got %q", loc)
	}
}

// TestAuthorizeGET_MissingPKCE verifies a missing PKCE challenge redirects with an error.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizeGET_MissingPKCE(t *testing.T) {
	h, clientID := newAuthorizeHandler(t)
	q := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {testRedirectURI},
		"response_type": {"code"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("expected invalid_request in redirect, got %q", loc)
	}
}

// TestAuthorizeGET_WrongChallengeMethod verifies a non-S256 challenge method redirects with an error.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizeGET_WrongChallengeMethod(t *testing.T) {
	h, clientID := newAuthorizeHandler(t)
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"code_challenge":        {"abc"},
		"code_challenge_method": {"plain"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("expected invalid_request in redirect, got %q", loc)
	}
}

// TestAuthorizeGET_Valid verifies a valid request renders the login form.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizeGET_Valid(t *testing.T) {
	h, clientID := newAuthorizeHandler(t)
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"code_challenge":        {testCodeChallenge()},
		"code_challenge_method": {"S256"},
		"scope":                 {"read"},
		"state":                 {"stateXYZ"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Errorf("expected HTML response")
	}
}

// --- POST tests ---

// postAuthorizeRequest builds a POST /oauth2/authorize form request.
//
// @arg clientID The client_id to submit.
// @arg challenge The PKCE code challenge to submit.
// @arg scope The requested scope.
// @arg username The submitted username.
// @arg password The submitted password.
// @return *http.Request The form-encoded authorize request.
func postAuthorizeRequest(clientID, challenge, scope, username, password string) *http.Request {
	form := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {testRedirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {scope},
		"state":                 {"abc"},
		"username":              {username},
		"password":              {password},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// TestAuthorizePOST_UnknownClient verifies an unknown client_id yields 400.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizePOST_UnknownClient(t *testing.T) {
	h, _ := newAuthorizeHandler(t)
	req := postAuthorizeRequest("unknown", testCodeChallenge(), "read", testUsername, testPassword)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestAuthorizePOST_MissingPKCE verifies a missing PKCE challenge yields 400.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizePOST_MissingPKCE(t *testing.T) {
	h, clientID := newAuthorizeHandler(t)
	form := url.Values{
		"client_id":    {clientID},
		"redirect_uri": {testRedirectURI},
		"username":     {testUsername},
		"password":     {testPassword},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestAuthorizePOST_WrongPassword verifies a bad password re-renders the login form with an error.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizePOST_WrongPassword(t *testing.T) {
	h, clientID := newAuthorizeHandler(t)
	req := postAuthorizeRequest(clientID, testCodeChallenge(), "read", testUsername, "wrongpassword")
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (re-show login), got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Invalid username or password") {
		t.Error("expected error message in login form")
	}
}

// TestAuthorizePOST_ValidCredentials_Redirects verifies valid credentials issue a code and redirect.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizePOST_ValidCredentials_Redirects(t *testing.T) {
	h, clientID := newAuthorizeHandler(t)
	req := postAuthorizeRequest(clientID, testCodeChallenge(), "read", testUsername, testPassword)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid redirect location %q: %v", loc, err)
	}
	if u.Query().Get("code") == "" {
		t.Errorf("expected code in redirect, got %q", loc)
	}
	if u.Query().Get("state") != "abc" {
		t.Errorf("expected state preserved in redirect, got %q", loc)
	}
}

// TestAuthorizePOST_ScopeEscalation_Filtered verifies disallowed scopes are filtered from the issued code.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizePOST_ScopeEscalation_Filtered(t *testing.T) {
	h, clientID := newAuthorizeHandler(t)
	// Attempt to request an admin scope not in AllowedScopes.
	req := postAuthorizeRequest(clientID, testCodeChallenge(), "read admin", testUsername, testPassword)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	u, _ := url.Parse(loc)
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("expected code in redirect, got %q", loc)
	}
	// Consume the stored auth code and verify scopes were filtered.
	ac := h.store.ConsumeAuthCode(code)
	if ac == nil {
		t.Fatal("auth code not found in store")
	}
	for _, s := range ac.Scopes {
		if s == "admin" {
			t.Error("admin scope must not be granted: scope escalation not prevented")
		}
	}
	if len(ac.Scopes) != 1 || ac.Scopes[0] != "read" {
		t.Errorf("expected scopes [read], got %v", ac.Scopes)
	}
}

// TestAuthorize_MethodNotAllowed verifies an unsupported HTTP method yields 405.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorize_MethodNotAllowed(t *testing.T) {
	h, _ := newAuthorizeHandler(t)
	req := httptest.NewRequest(http.MethodPut, "/oauth2/authorize", nil)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}
