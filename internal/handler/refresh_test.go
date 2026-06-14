package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/clems4ever/mcp-oauth2-proxy/internal/store"
	"github.com/clems4ever/mcp-oauth2-proxy/internal/token"
)

// postRefresh builds a refresh_token grant request for the given client.
//
// @arg clientID The client_id to submit as a form field.
// @arg refreshToken The refresh token to exchange.
// @return *http.Request The form-encoded refresh request.
func postRefresh(clientID, refreshToken string) *http.Request {
	return postToken(url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refreshToken},
	})
}

// seedRefreshToken stores a refresh token for the given client and scopes.
//
// @arg st The store to save the refresh token into.
// @arg clientID The client the token is bound to.
// @arg scopes The scopes recorded on the token.
// @return string The stored refresh token value.
func seedRefreshToken(st *store.Store, clientID string, scopes []string) string {
	const value = "seed-refresh-token"
	st.SaveRefreshToken(&store.RefreshToken{
		Token:     value,
		ClientID:  clientID,
		Subject:   tokenSubject,
		Scopes:    scopes,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	return value
}

// TestAuthorizationCode_IssuesRefreshToken verifies the authorization_code response includes a refresh token.
//
// @arg t The testing context provided by the Go test runner.
func TestAuthorizationCode_IssuesRefreshToken(t *testing.T) {
	h, st := newTokenHandler(t)
	seedAuthCode(st, pubClientID)

	rr := httptest.NewRecorder()
	h.Token(rr, postToken(acForm(pubClientID, "the-code", tokenVerifier)))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	resp := decodeToken(t, rr)
	if resp.RefreshToken == "" {
		t.Error("expected a refresh_token in the authorization_code response")
	}
}

// TestRefreshToken_Success verifies a valid refresh token yields a new access and refresh token.
//
// @arg t The testing context provided by the Go test runner.
func TestRefreshToken_Success(t *testing.T) {
	h, st := newTokenHandler(t)
	rtok := seedRefreshToken(st, pubClientID, []string{"read"})

	rr := httptest.NewRecorder()
	h.Token(rr, postRefresh(pubClientID, rtok))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	resp := decodeToken(t, rr)
	if resp.AccessToken == "" {
		t.Error("expected an access token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected a rotated refresh token")
	}
	if resp.RefreshToken == rtok {
		t.Error("refresh token must be rotated, not reused")
	}
	claims, err := token.Verify(tokenJWTSecret, testIssuer, resp.AccessToken)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if claims.Subject != tokenSubject {
		t.Errorf("expected subject %q, got %q", tokenSubject, claims.Subject)
	}
}

// TestRefreshToken_Rotation verifies the old refresh token is invalidated after use.
//
// @arg t The testing context provided by the Go test runner.
func TestRefreshToken_Rotation(t *testing.T) {
	h, st := newTokenHandler(t)
	rtok := seedRefreshToken(st, pubClientID, []string{"read"})

	first := httptest.NewRecorder()
	h.Token(first, postRefresh(pubClientID, rtok))
	if first.Code != http.StatusOK {
		t.Fatalf("first refresh should succeed, got %d", first.Code)
	}

	second := httptest.NewRecorder()
	h.Token(second, postRefresh(pubClientID, rtok))
	if second.Code != http.StatusBadRequest {
		t.Errorf("reusing a rotated refresh token must fail, got %d", second.Code)
	}
}

// TestRefreshToken_Unknown verifies an unknown refresh token yields invalid_grant.
//
// @arg t The testing context provided by the Go test runner.
func TestRefreshToken_Unknown(t *testing.T) {
	h, _ := newTokenHandler(t)
	rr := httptest.NewRecorder()
	h.Token(rr, postRefresh(pubClientID, "does-not-exist"))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestRefreshToken_Missing verifies a missing refresh_token yields invalid_request.
//
// @arg t The testing context provided by the Go test runner.
func TestRefreshToken_Missing(t *testing.T) {
	h, _ := newTokenHandler(t)
	rr := httptest.NewRecorder()
	h.Token(rr, postToken(url.Values{"grant_type": {"refresh_token"}, "client_id": {pubClientID}}))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestRefreshToken_ClientMismatch verifies a token bound to another client is rejected.
//
// @arg t The testing context provided by the Go test runner.
func TestRefreshToken_ClientMismatch(t *testing.T) {
	h, st := newTokenHandler(t)
	rtok := seedRefreshToken(st, pubClientID, []string{"read"}) // bound to pubClientID

	req := postRefresh(confClientID, rtok)
	req.SetBasicAuth(confClientID, confSecret)
	rr := httptest.NewRecorder()
	h.Token(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestRefreshToken_WrongSecret verifies a confidential client with a wrong secret yields 401.
//
// @arg t The testing context provided by the Go test runner.
func TestRefreshToken_WrongSecret(t *testing.T) {
	h, st := newTokenHandler(t)
	rtok := seedRefreshToken(st, confClientID, []string{"read"})

	req := postRefresh(confClientID, rtok)
	req.SetBasicAuth(confClientID, "wrong")
	rr := httptest.NewRecorder()
	h.Token(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestRefreshToken_ScopeNarrowing verifies requested scopes are restricted to the original set.
//
// @arg t The testing context provided by the Go test runner.
func TestRefreshToken_ScopeNarrowing(t *testing.T) {
	h, st := newTokenHandler(t)
	rtok := seedRefreshToken(st, pubClientID, []string{"read", "write"})

	req := postToken(url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {pubClientID},
		"refresh_token": {rtok},
		"scope":         {"read"},
	})
	rr := httptest.NewRecorder()
	h.Token(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	resp := decodeToken(t, rr)
	if resp.Scope != "read" {
		t.Errorf("expected narrowed scope 'read', got %q", resp.Scope)
	}
}
