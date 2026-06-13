package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/store"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/token"
)

const (
	tokenJWTSecret = "token-test-secret"
	ccClientID     = "cc-client"
	ccClientSecret = "cc-secret"
	confClientID   = "conf-client"
	confSecret     = "conf-secret"
	pubClientID    = "pub-client"
	tokenRedirect  = "https://client.example.com/cb"
	tokenSubject   = "alice"
	tokenVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

// newTokenHandler builds a Handler with a confidential and a public client
// seeded in the store and a configured client_credentials application.
//
// @arg t The testing context provided by the Go test runner.
// @return *Handler The handler under test.
// @return *store.Store The backing store, for seeding authorization codes.
func newTokenHandler(t *testing.T) (*Handler, *store.Store) {
	t.Helper()
	st := store.New()
	st.PutClient(&store.Client{
		ClientID:     confClientID,
		ClientSecret: confSecret,
		RedirectURIs: []string{tokenRedirect},
	})
	st.PutClient(&store.Client{
		ClientID:     pubClientID,
		RedirectURIs: []string{tokenRedirect},
		IsPublic:     true,
	})
	cfg := &config.Config{
		Server: config.ServerConfig{
			Issuer:    testIssuer,
			JWTSecret: tokenJWTSecret,
			TokenTTL:  3600,
		},
		Application: config.Application{
			ClientID:      ccClientID,
			ClientSecret:  ccClientSecret,
			AllowedScopes: []string{"read", "write"},
		},
	}
	return New(cfg, st), st
}

// postToken builds a POST /oauth2/token request with a form-encoded body.
//
// @arg form The form values to encode as the request body.
// @return *http.Request A token request with the urlencoded content type set.
func postToken(form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// decodeToken decodes a recorded response body into a tokenResponse.
//
// @arg t The testing context, used for fatal decode errors.
// @arg rr The recorded HTTP response to decode.
// @return tokenResponse The decoded token response.
func decodeToken(t *testing.T, rr *httptest.ResponseRecorder) tokenResponse {
	t.Helper()
	var resp tokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return resp
}

// --- grant routing ---

// TestToken_UnsupportedGrant verifies an unknown grant_type is rejected with 400.
//
// @arg t The testing context provided by the Go test runner.
func TestToken_UnsupportedGrant(t *testing.T) {
	h, _ := newTokenHandler(t)
	rr := httptest.NewRecorder()
	h.Token(rr, postToken(url.Values{"grant_type": {"password"}}))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- client credentials ---

// TestClientCredentials_BasicAuth_Success verifies a token is issued for valid Basic-auth credentials.
//
// @arg t The testing context provided by the Go test runner.
func TestClientCredentials_BasicAuth_Success(t *testing.T) {
	h, _ := newTokenHandler(t)
	req := postToken(url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}})
	req.SetBasicAuth(ccClientID, ccClientSecret)
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := decodeToken(t, rr)
	if resp.AccessToken == "" || resp.TokenType != "Bearer" {
		t.Errorf("unexpected token response: %+v", resp)
	}
	if resp.Scope != "read" {
		t.Errorf("expected scope read, got %q", resp.Scope)
	}
	if _, err := token.Verify(tokenJWTSecret, testIssuer, resp.AccessToken); err != nil {
		t.Errorf("issued token failed verification: %v", err)
	}
}

// TestClientCredentials_FormCredentials_Success verifies credentials may be supplied as form fields.
//
// @arg t The testing context provided by the Go test runner.
func TestClientCredentials_FormCredentials_Success(t *testing.T) {
	h, _ := newTokenHandler(t)
	req := postToken(url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {ccClientID},
		"client_secret": {ccClientSecret},
	})
	rr := httptest.NewRecorder()
	h.Token(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// TestClientCredentials_MissingClientID verifies a missing client_id yields 401.
//
// @arg t The testing context provided by the Go test runner.
func TestClientCredentials_MissingClientID(t *testing.T) {
	h, _ := newTokenHandler(t)
	rr := httptest.NewRecorder()
	h.Token(rr, postToken(url.Values{"grant_type": {"client_credentials"}}))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestClientCredentials_WrongSecret verifies an invalid secret yields 401.
//
// @arg t The testing context provided by the Go test runner.
func TestClientCredentials_WrongSecret(t *testing.T) {
	h, _ := newTokenHandler(t)
	req := postToken(url.Values{"grant_type": {"client_credentials"}})
	req.SetBasicAuth(ccClientID, "wrong")
	rr := httptest.NewRecorder()
	h.Token(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestClientCredentials_ScopeEscalationFiltered verifies scopes outside allowed_scopes are filtered out.
//
// @arg t The testing context provided by the Go test runner.
func TestClientCredentials_ScopeEscalationFiltered(t *testing.T) {
	h, _ := newTokenHandler(t)
	req := postToken(url.Values{"grant_type": {"client_credentials"}, "scope": {"read admin"}})
	req.SetBasicAuth(ccClientID, ccClientSecret)
	rr := httptest.NewRecorder()
	h.Token(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := decodeToken(t, rr)
	if strings.Contains(resp.Scope, "admin") {
		t.Errorf("admin scope must be filtered out, got %q", resp.Scope)
	}
}

// --- authorization code ---

// seedAuthCode stores a valid authorization code for the given client, bound to
// the test redirect URI and PKCE challenge.
//
// @arg st The store to save the authorization code into.
// @arg clientID The client the authorization code is issued to.
func seedAuthCode(st *store.Store, clientID string) {
	st.SaveAuthCode(&store.AuthCode{
		Code:                "the-code",
		ClientID:            clientID,
		RedirectURI:         tokenRedirect,
		Scopes:              []string{"read"},
		CodeChallenge:       testCodeChallenge(),
		CodeChallengeMethod: "S256",
		Subject:             tokenSubject,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	})
}

// acForm builds the form values for an authorization_code token request.
//
// @arg clientID The client_id to authenticate as.
// @arg code The authorization code to exchange.
// @arg verifier The PKCE code_verifier to present.
// @return url.Values The form values for the token request.
func acForm(clientID, code, verifier string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {tokenRedirect},
		"code_verifier": {verifier},
	}
}

// TestAuthorizationCode_PublicClient_Success verifies a public client (PKCE only) can exchange a code.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizationCode_PublicClient_Success(t *testing.T) {
	h, st := newTokenHandler(t)
	seedAuthCode(st, pubClientID)

	rr := httptest.NewRecorder()
	h.Token(rr, postToken(acForm(pubClientID, "the-code", tokenVerifier)))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	resp := decodeToken(t, rr)
	claims, err := token.Verify(tokenJWTSecret, testIssuer, resp.AccessToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != tokenSubject {
		t.Errorf("expected subject %q, got %q", tokenSubject, claims.Subject)
	}
}

// TestAuthorizationCode_ConfidentialClient_Success verifies a confidential client with the correct secret can exchange a code.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizationCode_ConfidentialClient_Success(t *testing.T) {
	h, st := newTokenHandler(t)
	seedAuthCode(st, confClientID)

	req := postToken(acForm(confClientID, "the-code", tokenVerifier))
	req.SetBasicAuth(confClientID, confSecret)
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
}

// TestAuthorizationCode_ConfidentialClient_WrongSecret verifies a wrong client secret yields 401.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizationCode_ConfidentialClient_WrongSecret(t *testing.T) {
	h, st := newTokenHandler(t)
	seedAuthCode(st, confClientID)

	req := postToken(acForm(confClientID, "the-code", tokenVerifier))
	req.SetBasicAuth(confClientID, "wrong")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestAuthorizationCode_UnknownClient verifies an unknown client yields 401.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizationCode_UnknownClient(t *testing.T) {
	h, _ := newTokenHandler(t)
	rr := httptest.NewRecorder()
	h.Token(rr, postToken(acForm("nobody", "the-code", tokenVerifier)))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestAuthorizationCode_MissingCode verifies a missing code or verifier yields 400.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizationCode_MissingCode(t *testing.T) {
	h, _ := newTokenHandler(t)
	form := acForm(pubClientID, "", tokenVerifier)
	rr := httptest.NewRecorder()
	h.Token(rr, postToken(form))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestAuthorizationCode_UnknownCode verifies an unknown code yields 400.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizationCode_UnknownCode(t *testing.T) {
	h, _ := newTokenHandler(t)
	rr := httptest.NewRecorder()
	h.Token(rr, postToken(acForm(pubClientID, "does-not-exist", tokenVerifier)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestAuthorizationCode_ClientIDMismatch verifies a code bound to another client is rejected.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizationCode_ClientIDMismatch(t *testing.T) {
	h, st := newTokenHandler(t)
	seedAuthCode(st, pubClientID) // code belongs to pubClientID

	req := postToken(acForm(confClientID, "the-code", tokenVerifier))
	req.SetBasicAuth(confClientID, confSecret)
	rr := httptest.NewRecorder()
	h.Token(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestAuthorizationCode_RedirectURIMismatch verifies a mismatched redirect_uri is rejected.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizationCode_RedirectURIMismatch(t *testing.T) {
	h, st := newTokenHandler(t)
	seedAuthCode(st, pubClientID)

	form := acForm(pubClientID, "the-code", tokenVerifier)
	form.Set("redirect_uri", "https://evil.example.com/cb")
	rr := httptest.NewRecorder()
	h.Token(rr, postToken(form))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestAuthorizationCode_BadPKCE verifies a wrong code_verifier fails PKCE.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizationCode_BadPKCE(t *testing.T) {
	h, st := newTokenHandler(t)
	seedAuthCode(st, pubClientID)

	rr := httptest.NewRecorder()
	h.Token(rr, postToken(acForm(pubClientID, "the-code", "wrong-verifier")))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestAuthorizationCode_CodeIsSingleUse verifies a code cannot be replayed.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizationCode_CodeIsSingleUse(t *testing.T) {
	h, st := newTokenHandler(t)
	seedAuthCode(st, pubClientID)

	first := httptest.NewRecorder()
	h.Token(first, postToken(acForm(pubClientID, "the-code", tokenVerifier)))
	if first.Code != http.StatusOK {
		t.Fatalf("first exchange should succeed, got %d", first.Code)
	}

	second := httptest.NewRecorder()
	h.Token(second, postToken(acForm(pubClientID, "the-code", tokenVerifier)))
	if second.Code != http.StatusBadRequest {
		t.Errorf("replayed code must be rejected, got %d", second.Code)
	}
}

// TestAuthorizationCode_ExpiredCode verifies an expired code is rejected.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizationCode_ExpiredCode(t *testing.T) {
	h, st := newTokenHandler(t)
	st.SaveAuthCode(&store.AuthCode{
		Code:                "expired",
		ClientID:            pubClientID,
		RedirectURI:         tokenRedirect,
		Scopes:              []string{"read"},
		CodeChallenge:       testCodeChallenge(),
		CodeChallengeMethod: "S256",
		Subject:             tokenSubject,
		ExpiresAt:           time.Now().Add(-1 * time.Minute),
	})

	rr := httptest.NewRecorder()
	h.Token(rr, postToken(acForm(pubClientID, "expired", tokenVerifier)))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for expired code, got %d", rr.Code)
	}
}
