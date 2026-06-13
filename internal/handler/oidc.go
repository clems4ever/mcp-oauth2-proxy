package handler

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"time"

	"github.com/clems4ever/mcp-oauth2-proxy/internal/store"
)

// OIDCLogin handles POST /oauth2/oidc/login. It validates the authorization
// request carried by the login form, stores short-lived CSRF state, and
// redirects the browser to the upstream OIDC provider.
//
// @arg w HTTP response writer used to redirect to the provider or report errors.
// @arg r The posted login request carrying the OAuth authorization parameters.
//
// @testcase TestOIDCLogin_RedirectsToProvider verifies a valid request 302s to the provider authorize URL.
// @testcase TestOIDCLogin_UnknownClient verifies an unknown client_id is rejected with 400.
// @testcase TestOIDCLogin_Disabled verifies the endpoint returns 404 when OIDC is not configured.
func (h *Handler) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	log.Printf("[OIDC/login] client_id=%q redirect_uri=%q", clientID, redirectURI)

	if !h.validateAuthRequest(w, clientID, redirectURI, codeChallenge, codeChallengeMethod) {
		return
	}

	state, err := randomToken()
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	nonce, err := randomToken()
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}

	h.store.SaveOIDCState(&store.OIDCState{
		State:               state,
		Nonce:               nonce,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               r.FormValue("scope"),
		ClientState:         r.FormValue("state"),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(time.Duration(h.cfg.Server.AuthCodeTTL) * time.Second),
	})

	http.Redirect(w, r, h.oidc.AuthCodeURL(state, nonce), http.StatusFound)
}

// OIDCCallback handles GET /oauth2/oidc/callback. It validates the returned
// state, exchanges the code for a verified email, enforces the email allowlist,
// and — on success — rejoins the authorization-code flow by issuing a code and
// redirecting back to the MCP client.
//
// @arg w HTTP response writer used to redirect to the client or report errors.
// @arg r The provider callback request carrying state and code (or an error).
//
// @testcase TestOIDCCallback_UnknownState verifies an unknown/expired state yields 400.
// @testcase TestOIDCCallback_Disabled verifies the endpoint returns 404 when OIDC is not configured.
func (h *Handler) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()

	st := h.store.ConsumeOIDCState(q.Get("state"))
	if st == nil {
		log.Printf("[OIDC/callback] unknown or expired state")
		http.Error(w, "invalid_request: unknown or expired state", http.StatusBadRequest)
		return
	}

	// The provider may report an error instead of returning a code.
	if errCode := q.Get("error"); errCode != "" {
		log.Printf("[OIDC/callback] provider returned error=%q", errCode)
		redirectWithError(w, r, st.RedirectURI, st.ClientState, "access_denied", "identity provider returned an error")
		return
	}

	email, err := h.oidc.Exchange(r.Context(), q.Get("code"), st.Nonce)
	if err != nil {
		log.Printf("[OIDC/callback] exchange failed: %v", err)
		redirectWithError(w, r, st.RedirectURI, st.ClientState, "access_denied", "could not verify identity")
		return
	}
	if !h.oidc.EmailAllowed(email) {
		log.Printf("[OIDC/callback] email not in allowlist")
		redirectWithError(w, r, st.RedirectURI, st.ClientState, "access_denied", "this account is not allowed")
		return
	}

	log.Printf("[OIDC/callback] issuing code for client_id=%q via OIDC", st.ClientID)
	h.issueCodeAndRedirect(w, r, authParams{
		ClientID:            st.ClientID,
		RedirectURI:         st.RedirectURI,
		Scope:               st.Scope,
		State:               st.ClientState,
		CodeChallenge:       st.CodeChallenge,
		CodeChallengeMethod: st.CodeChallengeMethod,
	}, email)
}

// randomToken returns a 256-bit cryptographically-random hex string for use as
// an OIDC state or nonce value.
//
// @return string A 64-character hex-encoded random token.
// @error Returns an error if the system random source fails.
//
// @testcase TestOIDCLogin_RedirectsToProvider exercises randomToken via the login redirect.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
