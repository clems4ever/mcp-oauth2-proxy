package handler

import "net/http"

type metadataResponse struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

type protectedResourceResponse struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

// ProtectedResource handles GET /.well-known/oauth-protected-resource (RFC 9728).
// It tells the client which authorization server protects this resource.
func (h *Handler) ProtectedResource(w http.ResponseWriter, r *http.Request) {
	issuer := baseURL(h.cfg, r)
	writeJSON(w, http.StatusOK, protectedResourceResponse{
		Resource:               issuer,
		AuthorizationServers:   []string{issuer},
		BearerMethodsSupported: []string{"header"},
	})
}

// Metadata handles GET /.well-known/oauth-authorization-server (RFC 8414).
func (h *Handler) Metadata(w http.ResponseWriter, r *http.Request) {
	issuer := baseURL(h.cfg, r)
	writeJSON(w, http.StatusOK, metadataResponse{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/oauth2/authorize",
		TokenEndpoint:                     issuer + "/oauth2/token",
		RegistrationEndpoint:              issuer + "/oauth2/register",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "client_credentials"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
	})
}
