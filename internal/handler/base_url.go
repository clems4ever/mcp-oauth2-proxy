package handler

import "github.com/clems4ever/mcp-oauth2-proxy/config"

// baseURL returns the public base URL configured via the issuer setting.
// Request headers are intentionally ignored to prevent host-header injection.
func baseURL(cfg *config.Config) string {
	return cfg.Server.Issuer
}
