package handler

import (
	"crypto/rand"
	"crypto/sha256"
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

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in</title>
  <style>
    body{font-family:system-ui,sans-serif;max-width:380px;margin:80px auto;padding:0 1.5rem}
    h2{margin-bottom:1.5rem}
    label{display:block;margin-bottom:.25rem;font-size:.9rem;color:#555}
    input[type=text],input[type=password]{width:100%;padding:.55rem .75rem;border:1px solid #ccc;border-radius:6px;box-sizing:border-box;margin-bottom:1rem;font-size:1rem}
    button{width:100%;padding:.65rem;background:#0070f3;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:1rem;font-weight:600}
    button:hover{background:#005ed4}
    .error{background:#fff0f0;border:1px solid #f5c6c6;color:#c00;border-radius:6px;padding:.6rem .9rem;margin-bottom:1rem;font-size:.9rem}
  </style>
</head>
<body>
  <h2>Sign in</h2>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <form method="POST" action="/oauth2/authorize">
    <input type="hidden" name="client_id"             value="{{.ClientID}}">
    <input type="hidden" name="redirect_uri"          value="{{.RedirectURI}}">
    <input type="hidden" name="scope"                 value="{{.Scope}}">
    <input type="hidden" name="state"                 value="{{.State}}">
    <input type="hidden" name="code_challenge"        value="{{.CodeChallenge}}">
    <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
    <label for="u">Username</label>
    <input id="u" name="username" type="text" autocomplete="username" autofocus>
    <label for="p">Password</label>
    <input id="p" name="password" type="password" autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
</body>
</html>`))

// Authorize handles GET and POST /oauth2/authorize.
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

	// Embed all OAuth params in the form — no server-side session state needed.
	// PKCE cryptographically binds the code challenge so it cannot be swapped.
	log.Printf("[AUTHORIZE/GET] showing login for client_id=%q", clientID)
	showLogin(w, map[string]any{
		"ClientID":            clientID,
		"RedirectURI":         redirectURI,
		"Scope":               q.Get("scope"),
		"State":               state,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
		"Error":               "",
	})
}

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

	// Re-validate the client and redirect_uri from the form.
	client := h.store.FindClient(clientID)
	if client == nil {
		http.Error(w, "invalid_request: unknown client_id", http.StatusBadRequest)
		return
	}
	if !clientHasRedirectURI(client, redirectURI) {
		http.Error(w, "invalid_request: redirect_uri not registered", http.StatusBadRequest)
		return
	}
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		http.Error(w, "invalid_request: PKCE with code_challenge_method=S256 is required", http.StatusBadRequest)
		return
	}

	formData := map[string]any{
		"ClientID":            clientID,
		"RedirectURI":         redirectURI,
		"Scope":               r.FormValue("scope"),
		"State":               r.FormValue("state"),
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
		"Error":               "",
	}

	if !h.authenticateUser(r.FormValue("username"), r.FormValue("password")) {
		formData["Error"] = "Invalid username or password."
		showLogin(w, formData)
		return
	}

	// Issue authorization code.
	codeBuf := make([]byte, 16)
	if _, err := rand.Read(codeBuf); err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	code := hex.EncodeToString(codeBuf)

	scope := r.FormValue("scope")
	state := r.FormValue("state")

	h.store.SaveAuthCode(&store.AuthCode{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scopes:              strings.Fields(scope),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Subject:             r.FormValue("username"),
		ExpiresAt:           time.Now().Add(time.Duration(h.cfg.Server.AuthCodeTTL) * time.Second),
	})

	redirURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "server_error: invalid redirect_uri", http.StatusInternalServerError)
		return
	}
	q := redirURL.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	redirURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirURL.String(), http.StatusFound)
}

func (h *Handler) authenticateUser(username, password string) bool {
	u := h.cfg.FindUser(username)
	if u == nil {
		// Spend time on a dummy hash to prevent user enumeration via timing.
		bcrypt.CompareHashAndPassword([]byte("$2a$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), []byte(password))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) == nil
}

func showLogin(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTmpl.Execute(w, data)
}

func clientHasRedirectURI(client *store.DynamicClient, uri string) bool {
	for _, u := range client.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

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
func verifyPKCE(challenge, verifier string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return secureCompare(computed, challenge)
}
