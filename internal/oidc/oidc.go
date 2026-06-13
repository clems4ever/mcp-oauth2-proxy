// Package oidc wraps an upstream OpenID Connect provider used as an alternative
// browser login: it performs discovery, builds the authorization-code URL, and
// exchanges the returned code for a verified end-user email.
package oidc

import (
	"context"
	"fmt"
	"strings"

	"github.com/clems4ever/mcp-oauth2-proxy/config"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Client is a configured OIDC relying party bound to a single provider and a
// fixed set of allowed end-user emails.
type Client struct {
	oauth2   *oauth2.Config
	verifier *gooidc.IDTokenVerifier
	allowed  map[string]struct{}
}

// New performs OIDC discovery against cfg.Issuer and returns a ready Client.
//
// @arg ctx Context governing the discovery HTTP request.
// @arg cfg The validated OIDC configuration (issuer, credentials, scopes, allowed emails).
// @return *Client A client wired to the discovered provider endpoints and verifier.
// @error Returns an error if provider discovery fails.
//
// @testcase TestExchange_Success verifies New builds a working client against a provider.
// @testcase TestNew_DiscoveryError verifies New fails when the issuer is unreachable.
func New(ctx context.Context, cfg *config.OIDCConfig) (*Client, error) {
	provider, err := gooidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %q: %w", cfg.Issuer, err)
	}

	allowed := make(map[string]struct{}, len(cfg.AllowedEmails))
	for _, e := range cfg.AllowedEmails {
		allowed[strings.ToLower(strings.TrimSpace(e))] = struct{}{}
	}

	return &Client{
		oauth2: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
		verifier: provider.Verifier(&gooidc.Config{ClientID: cfg.ClientID}),
		allowed:  allowed,
	}, nil
}

// AuthCodeURL returns the provider authorization URL to redirect the browser to,
// binding the request to the given CSRF state and OIDC nonce.
//
// @arg state Opaque CSRF value echoed back to the callback.
// @arg nonce OIDC nonce bound into the issued ID token.
// @return string The fully-formed provider authorization URL.
//
// @testcase TestAuthCodeURL verifies the URL carries client_id, state, nonce and redirect_uri.
func (c *Client) AuthCodeURL(state, nonce string) string {
	return c.oauth2.AuthCodeURL(state, gooidc.Nonce(nonce))
}

// Exchange swaps an authorization code for tokens, verifies the ID token (its
// signature, audience and nonce), and returns the verified end-user email.
//
// @arg ctx Context governing the token-exchange and JWKS HTTP requests.
// @arg code The authorization code returned by the provider.
// @arg expectedNonce The nonce that must match the ID token's nonce claim.
// @return string The verified email address from the ID token (requires email_verified).
// @error Returns an error if the exchange fails, the ID token is missing or invalid, the nonce mismatches, or the email is unverified.
//
// @testcase TestExchange_Success verifies a valid code yields the verified email.
// @testcase TestExchange_NonceMismatch verifies a mismatched nonce is rejected.
// @testcase TestExchange_UnverifiedEmail verifies an unverified email is rejected.
func (c *Client) Exchange(ctx context.Context, code, expectedNonce string) (string, error) {
	tok, err := c.oauth2.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return "", fmt.Errorf("no id_token in token response")
	}
	idToken, err := c.verifier.Verify(ctx, rawID)
	if err != nil {
		return "", fmt.Errorf("verify id_token: %w", err)
	}
	if idToken.Nonce != expectedNonce {
		return "", fmt.Errorf("nonce mismatch")
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return "", fmt.Errorf("decode id_token claims: %w", err)
	}
	if claims.Email == "" {
		return "", fmt.Errorf("id_token has no email claim")
	}
	if !claims.EmailVerified {
		return "", fmt.Errorf("email %q is not verified", claims.Email)
	}
	return claims.Email, nil
}

// EmailAllowed reports whether email is in the configured allowlist, matched
// case-insensitively.
//
// @arg email The email address to check.
// @return bool True if the email is allowed to authenticate.
//
// @testcase TestEmailAllowed verifies case-insensitive allowlist matching.
func (c *Client) EmailAllowed(email string) bool {
	_, ok := c.allowed[strings.ToLower(strings.TrimSpace(email))]
	return ok
}
