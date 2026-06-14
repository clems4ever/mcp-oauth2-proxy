package handler

import "net/http"

type metadataResponse struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
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
//
// @arg w HTTP response writer the JSON metadata document is written to.
// @arg r Incoming HTTP request; only used for routing, its contents are ignored.
//
// @testcase TestProtectedResource_StatusOK verifies a 200 status is returned.
// @testcase TestProtectedResource_ContentType verifies the application/json content type.
// @testcase TestProtectedResource_Body verifies the resource, authorization_servers and bearer_methods_supported fields.
func (h *Handler) ProtectedResource(w http.ResponseWriter, r *http.Request) {
	issuer := baseURL(h.cfg)
	writeJSON(w, http.StatusOK, protectedResourceResponse{
		Resource:               issuer,
		AuthorizationServers:   []string{issuer},
		BearerMethodsSupported: []string{"header"},
	})
}

// Metadata handles GET /.well-known/oauth-authorization-server (RFC 8414).
// It returns the authorization server discovery document as JSON. Dynamic
// client registration is not implemented, so no registration_endpoint is
// advertised.
//
// @arg w HTTP response writer the JSON metadata document is written to.
// @arg r Incoming HTTP request; only used for routing, its contents are ignored.
//
// @testcase TestMetadata_StatusOK verifies a 200 status is returned.
// @testcase TestMetadata_ContentType verifies the application/json content type.
// @testcase TestMetadata_Body verifies the issuer, endpoint and supported-capability fields.
// @testcase TestMetadata_NoRegistrationEndpoint verifies the unimplemented registration endpoint is not advertised.
func (h *Handler) Metadata(w http.ResponseWriter, r *http.Request) {
	issuer := baseURL(h.cfg)
	writeJSON(w, http.StatusOK, metadataResponse{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/oauth2/authorize",
		TokenEndpoint:                     issuer + "/oauth2/token",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "client_credentials", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
	})
}
