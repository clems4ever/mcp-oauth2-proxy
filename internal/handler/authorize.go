package handler

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/clems4ever/mcp-oauth2-proxy/internal/store"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/login.html
var loginHTML string

var loginTmpl = template.Must(template.New("login").Parse(loginHTML))

// Authorize handles GET and POST /oauth2/authorize.
//
// @arg w HTTP response writer for the login page, redirect, or error.
// @arg r The incoming authorization request (GET shows the form, POST submits it).
//
// @testcase TestAuthorizeGET_Valid verifies GET renders the login form.
// @testcase TestAuthorizePOST_ValidCredentials_Redirects verifies POST issues a code and redirects.
// @testcase TestAuthorize_MethodNotAllowed verifies an unsupported method yields 405.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.authorizeGET(w, r)
	case http.MethodPost:
		h.authorizePOST(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// authorizeGET validates the authorization request and renders the login form.
//
// @arg w HTTP response writer for the login page or error/redirect.
// @arg r The incoming GET authorization request carrying OAuth query params.
//
// @testcase TestAuthorizeGET_Valid verifies a valid request renders the login form.
// @testcase TestAuthorizeGET_UnknownClient verifies an unknown client yields 400.
// @testcase TestAuthorizeGET_UnregisteredRedirectURI verifies an unregistered redirect_uri yields 400.
// @testcase TestAuthorizeGET_WrongResponseType verifies a non-code response_type redirects with an error.
// @testcase TestAuthorizeGET_MissingPKCE verifies a missing PKCE challenge redirects with an error.
// @testcase TestAuthorizeGET_WrongChallengeMethod verifies a non-S256 method redirects with an error.
func (h *Handler) authorizeGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	log.Printf("[AUTHORIZE/GET] client_id=%q redirect_uri=%q response_type=%q code_challenge_method=%q",
		clientID, redirectURI, responseType, codeChallengeMethod)

	// Validate client and redirect_uri before doing anything else.
	// Errors here are returned directly (not via redirect) per RFC 6749 §4.1.2.1.
	client := h.store.FindClient(clientID)
	if client == nil {
		log.Printf("[AUTHORIZE/GET] unknown client_id=%q", clientID)
		http.Error(w, "invalid_request: unknown client_id", http.StatusBadRequest)
		return
	}
	if !clientHasRedirectURI(client, redirectURI) {
		log.Printf("[AUTHORIZE/GET] redirect_uri %q not in registered URIs %v", redirectURI, client.RedirectURIs)
		http.Error(w, "invalid_request: redirect_uri not registered", http.StatusBadRequest)
		return
	}

	// All other errors redirect to the client.
	state := q.Get("state")
	if responseType != "code" {
		redirectWithError(w, r, redirectURI, state, "unsupported_response_type", "only code is supported")
		return
	}
	// OAuth 2.1 mandates PKCE with S256 for all authorization code flows.
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		redirectWithError(w, r, redirectURI, state, "invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}

	// Embed all OAuth params in the form — no server-side session state needed
	// for the password flow. PKCE cryptographically binds the code challenge so
	// it cannot be swapped.
	log.Printf("[AUTHORIZE/GET] showing login for client_id=%q", clientID)
	showLogin(w, h.loginData(authParams{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               q.Get("scope"),
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}, ""))
}

// authParams are the OAuth authorization-request fields shared by the password
// and OIDC login paths.
type authParams struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// loginData builds the login template payload, including whether OIDC login
// should be offered.
//
// @arg p The authorization-request fields to embed as hidden form inputs.
// @arg errMsg An optional error message to display, or "" for none.
// @return map[string]any The template data for the login page.
//
// @testcase TestLoginForm_ShowsGoogleButtonWhenEnabled verifies OIDCEnabled drives the Google button.
// @testcase TestAuthorizePOST_WrongPassword verifies the error message is shown on failed login.
func (h *Handler) loginData(p authParams, errMsg string) map[string]any {
	return map[string]any{
		"ClientID":            p.ClientID,
		"RedirectURI":         p.RedirectURI,
		"Scope":               p.Scope,
		"State":               p.State,
		"CodeChallenge":       p.CodeChallenge,
		"CodeChallengeMethod": p.CodeChallengeMethod,
		"Error":               errMsg,
		"OIDCEnabled":         h.cfg.OIDCEnabled(),
	}
}

// validateAuthRequest verifies the client, redirect_uri and PKCE parameters of a
// posted authorization request. On failure it writes a 400 response and returns
// false.
//
// @arg w HTTP response writer used to report a 400 on failure.
// @arg clientID The client_id to look up and validate.
// @arg redirectURI The redirect_uri that must be registered for the client.
// @arg codeChallenge The PKCE code challenge; must be non-empty.
// @arg codeChallengeMethod The PKCE method; must be S256.
// @return bool True if the request is valid; false (with a 400 already written) otherwise.
//
// @testcase TestOIDCLogin_UnknownClient verifies an unknown client is rejected.
// @testcase TestOIDCLogin_MissingPKCE verifies a missing PKCE challenge is rejected.
// @testcase TestAuthorizePOST_UnknownClient verifies an unknown client is rejected on the password path.
func (h *Handler) validateAuthRequest(w http.ResponseWriter, clientID, redirectURI, codeChallenge, codeChallengeMethod string) bool {
	client := h.store.FindClient(clientID)
	if client == nil {
		http.Error(w, "invalid_request: unknown client_id", http.StatusBadRequest)
		return false
	}
	if !clientHasRedirectURI(client, redirectURI) {
		http.Error(w, "invalid_request: redirect_uri not registered", http.StatusBadRequest)
		return false
	}
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		http.Error(w, "invalid_request: PKCE with code_challenge_method=S256 is required", http.StatusBadRequest)
		return false
	}
	return true
}

// issueCodeAndRedirect mints a single-use authorization code for subject, binds
// it to the authorization request p, and 302-redirects the browser back to the
// client redirect_uri carrying the code (and original state).
//
// @arg w HTTP response writer used for the redirect or error.
// @arg r The current HTTP request (passed through to http.Redirect).
// @arg p The authorization request the code is bound to.
// @arg subject The authenticated subject to embed as the code's Subject.
//
// @testcase TestAuthorizePOST_ValidCredentials_Redirects verifies a code is issued and the browser redirected.
// @testcase TestAuthorizePOST_ScopeEscalation_Filtered verifies scopes are filtered on the issued code.
func (h *Handler) issueCodeAndRedirect(w http.ResponseWriter, r *http.Request, p authParams, subject string) {
	codeBuf := make([]byte, 16)
	if _, err := rand.Read(codeBuf); err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	code := hex.EncodeToString(codeBuf)

	h.store.SaveAuthCode(&store.AuthCode{
		Code:                code,
		ClientID:            p.ClientID,
		RedirectURI:         p.RedirectURI,
		Scopes:              filterScopes(h.cfg.Application.AllowedScopes, strings.Fields(p.Scope)),
		CodeChallenge:       p.CodeChallenge,
		CodeChallengeMethod: p.CodeChallengeMethod,
		Subject:             subject,
		ExpiresAt:           time.Now().Add(time.Duration(h.cfg.Server.AuthCodeTTL) * time.Second),
	})

	redirURL, err := url.Parse(p.RedirectURI)
	if err != nil {
		http.Error(w, "server_error: invalid redirect_uri", http.StatusInternalServerError)
		return
	}
	q := redirURL.Query()
	q.Set("code", code)
	if p.State != "" {
		q.Set("state", p.State)
	}
	redirURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirURL.String(), http.StatusFound)
}

// authorizePOST processes the submitted password login: it re-validates the
// authorization request, checks credentials, and on success issues a code and
// redirects to the client (re-showing the form with an error otherwise).
//
// @arg w HTTP response writer for the redirect, re-rendered form, or error.
// @arg r The posted login request carrying credentials and OAuth params.
//
// @testcase TestAuthorizePOST_ValidCredentials_Redirects verifies success issues a code and redirects.
// @testcase TestAuthorizePOST_WrongPassword verifies a bad password re-renders the form.
// @testcase TestAuthorizePOST_UnknownClient verifies an unknown client yields 400.
// @testcase TestAuthorizePOST_MissingPKCE verifies a missing PKCE challenge yields 400.
func (h *Handler) authorizePOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	log.Printf("[AUTHORIZE/POST] client_id=%q redirect_uri=%q username=%q",
		clientID, redirectURI, r.FormValue("username"))

	// Re-validate the client, redirect_uri and PKCE from the form.
	if !h.validateAuthRequest(w, clientID, redirectURI, codeChallenge, codeChallengeMethod) {
		return
	}

	p := authParams{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               r.FormValue("scope"),
		State:               r.FormValue("state"),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}

	if !h.authenticateUser(r.FormValue("username"), r.FormValue("password")) {
		showLogin(w, h.loginData(p, "Invalid username or password."))
		return
	}

	h.issueCodeAndRedirect(w, r, p, r.FormValue("username"))
}

// authenticateUser reports whether the username/password match a configured
// user, spending constant time on a dummy hash for unknown users to resist
// timing-based enumeration.
//
// @arg username The submitted username.
// @arg password The submitted plaintext password.
// @return bool True if the credentials are valid.
//
// @testcase TestAuthorizePOST_ValidCredentials_Redirects verifies valid credentials authenticate.
// @testcase TestAuthorizePOST_WrongPassword verifies a wrong password fails.
func (h *Handler) authenticateUser(username, password string) bool {
	u := h.cfg.FindUser(username)
	if u == nil {
		// Spend time on a dummy hash to prevent user enumeration via timing.
		bcrypt.CompareHashAndPassword([]byte("$2a$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), []byte(password))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) == nil
}

// showLogin renders the login HTML template with the given data.
//
// @arg w HTTP response writer the rendered HTML is written to.
// @arg data The login template payload (see loginData).
//
// @testcase TestAuthorizeGET_Valid verifies the login form is rendered.
func showLogin(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTmpl.Execute(w, data)
}

// clientHasRedirectURI reports whether uri is one of the client's registered
// redirect URIs (exact match).
//
// @arg client The client whose registered redirect URIs are checked.
// @arg uri The redirect URI to match.
// @return bool True if uri exactly matches a registered redirect URI.
//
// @testcase TestAuthorizeGET_UnregisteredRedirectURI verifies an unregistered URI is rejected.
func clientHasRedirectURI(client *store.Client, uri string) bool {
	for _, u := range client.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// redirectWithError redirects to the client redirect_uri with an OAuth error
// (or returns a 400 directly when no redirect_uri is available).
//
// @arg w HTTP response writer for the redirect or error.
// @arg r The current HTTP request (passed through to http.Redirect).
// @arg redirectURI The client redirect URI to send the error to, or "" for a direct 400.
// @arg state The client state to echo back, if non-empty.
// @arg errCode The OAuth error code.
// @arg errDesc A human-readable error description.
//
// @testcase TestAuthorizeGET_WrongResponseType verifies the error is delivered via redirect.
// @testcase TestOIDCCallback_ProviderError verifies provider errors redirect with access_denied.
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc string) {
	if redirectURI == "" {
		http.Error(w, errCode+": "+errDesc, http.StatusBadRequest)
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", errCode)
	if errDesc != "" {
		q.Set("error_description", errDesc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// verifyPKCE checks that BASE64URL(SHA256(verifier)) == challenge.
//
// @arg challenge The stored PKCE code challenge.
// @arg verifier The code_verifier presented at the token endpoint.
// @return bool True if the verifier hashes to the challenge (constant-time compare).
//
// @testcase TestAuthorizationCode_PublicClient_Success verifies a correct verifier passes PKCE.
// @testcase TestAuthorizationCode_BadPKCE verifies a wrong verifier fails PKCE.
func verifyPKCE(challenge, verifier string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return secureCompare(computed, challenge)
}
