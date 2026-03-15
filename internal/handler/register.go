package handler

import (
	"encoding/json"
	"net/http"
)

type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"` // "none" for public clients
}

type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
}

// Register handles POST /oauth2/register (RFC 7591 dynamic client registration).
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req registrationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, "invalid_request", "invalid JSON body", http.StatusBadRequest)
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeError(w, "invalid_request", "redirect_uris is required", http.StatusBadRequest)
		return
	}
	for _, u := range req.RedirectURIs {
		if u == "" {
			writeError(w, "invalid_redirect_uri", "redirect_uris must not contain empty values", http.StatusBadRequest)
			return
		}
	}

	isPublic := req.TokenEndpointAuthMethod == "none"
	client, err := h.store.RegisterClient(req.RedirectURIs, req.ClientName, isPublic)
	if err != nil {
		writeError(w, "server_error", "failed to register client", http.StatusInternalServerError)
		return
	}

	authMethod := "client_secret_basic"
	if isPublic {
		authMethod = "none"
	}

	writeJSON(w, http.StatusCreated, registrationResponse{
		ClientID:                client.ClientID,
		ClientSecret:            client.ClientSecret,
		RedirectURIs:            client.RedirectURIs,
		ClientName:              client.ClientName,
		TokenEndpointAuthMethod: authMethod,
		ClientIDIssuedAt:        client.RegisteredAt.Unix(),
	})
}
