# mcp-oauth2-proxy

An OAuth 2.1-compatible authorization server and reverse proxy designed to add authentication to a plain [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) HTTP server with zero changes to the upstream.

It sits in front of your MCP server, handles all OAuth flows, validates Bearer tokens on every request, and forwards authenticated traffic to the upstream.

## Features

- **Authorization code flow** with PKCE (S256) — used by MCP clients such as Claude
- **Refresh token flow** with rotation — clients renew access tokens without re-authenticating
- **Client credentials flow** — machine-to-machine access
- Browser-based login form with bcrypt password verification
- Optional **OpenID Connect login** (e.g. Google) with an email allowlist, alongside the password form
- JWT access tokens (HS256) with `iss`, `aud`, `sub`, `exp` claims
- Auto-discovery endpoints (RFC 8414 + RFC 9728)
- Transparent reverse proxy to an upstream MCP HTTP server

## Quick start

```bash
git clone https://github.com/clems4ever/mcp-oauth2-proxy
cd mcp-oauth2-proxy
go build -o mcp-oauth2-proxy .
./mcp-oauth2-proxy --config example-config.yaml
```

Or with Docker:

```bash
docker run --rm \
  -p 8080:8080 \
  -v $PWD/example-config.yaml:/config.yaml \
  ghcr.io/clems4ever/mcp-oauth2-proxy --config /config.yaml
```

## Configuration

```yaml
server:
  port: 8080
  issuer: "https://auth.example.com"   # public base URL — must match what clients see
  jwt_secret: "change-me-in-production"
  token_ttl: 3600           # access token lifetime, seconds
  auth_code_ttl: 300        # authorization code lifetime, seconds
  refresh_token_ttl: 2592000 # refresh token lifetime, seconds (default 30 days)
  upstream_url: "http://localhost:9090" # MCP HTTP server to proxy authenticated requests to

# Human users for the authorization code flow.
# Passwords are bcrypt hashes — generate with: htpasswd -bnBC 10 "" <password> | tr -d ':\n'
users:
  - username: alice
    password: "$2a$10$..."

# Single OAuth2 application (used for both flows).
application:
  client_id: "service-client-id"
  client_secret: "service-client-secret"
  allowed_scopes:
    - read
    - write
  redirect_uris:
    - "https://claude.ai/api/mcp/auth_callback"
```

Default config path: `~/.mcp-oauth2.yaml`. Override with `--config`.

Two optional blocks are documented in their own sections below: `oidc` (sign in
with Google / any OIDC provider) and `storage` (persist refresh tokens to disk).

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| `GET` | `/.well-known/oauth-protected-resource` | Protected resource metadata (RFC 9728) |
| `GET/POST` | `/oauth2/authorize` | Authorization endpoint — shows login form, issues auth codes |
| `POST` | `/oauth2/token` | Token endpoint — `authorization_code`, `client_credentials` and `refresh_token` grants |
| `POST` | `/oauth2/oidc/login` | Starts OIDC login (only when `oidc` is configured) |
| `GET` | `/oauth2/oidc/callback` | OIDC provider callback (only when `oidc` is configured) |
| `*` | `/` | Reverse proxy to `upstream_url` (requires valid Bearer token) |

## Token endpoint

### Client credentials

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -u service-client-id:service-client-secret \
  -d "grant_type=client_credentials&scope=read"
```

### Authorization code (PKCE)

The authorization code flow is initiated by the MCP client. The proxy displays a login form, the user authenticates, and an authorization code is returned to the registered `redirect_uri`. The code is then exchanged for a token:

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -u service-client-id:service-client-secret \
  -d "grant_type=authorization_code&code=<code>&redirect_uri=<uri>&code_verifier=<verifier>"
```

The authorization code response includes a `refresh_token`.

### Refresh token

Exchange a refresh token for a new access token (and a rotated refresh token).
The previous refresh token is invalidated on use; an optional `scope` may narrow
the granted scopes (it must be a subset of the original):

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -u service-client-id:service-client-secret \
  -d "grant_type=refresh_token&refresh_token=<refresh_token>"
```

Refresh tokens are issued for the authorization code (and refresh) flows only —
the `client_credentials` grant returns none, since a machine client can simply
request a new token with its credentials.

By default refresh tokens are kept in memory and lost on restart. To make logins
survive restarts, set `storage.path` to persist them in an embedded
[bbolt](https://github.com/etcd-io/bbolt) database (expired tokens are swept
automatically):

```yaml
storage:
  path: "/var/lib/mcp-oauth2/store.db"
```

Authorization codes and login sessions are always in-memory (they are
short-lived).

### Response

```json
{
  "access_token": "eyJhbGci...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "9f8c...",
  "scope": "read write"
}
```

## Google / OIDC login

In addition to the password form, the browser login can authenticate users
against any OpenID Connect provider (Google, Okta, Auth0, Entra, …). When an
`oidc` block is present in the config, the login page shows a **"Sign in with
Google"** button next to the username/password form. Access is restricted to an
**email allowlist** — only verified emails you list may sign in.

1. Create an OAuth client at your provider. For Google: *APIs & Services →
   Credentials → Create OAuth client ID → Web application*.
2. Add this proxy's callback as an authorized redirect URI:
   `<issuer base URL>/oauth2/oidc/callback`
   (e.g. `https://auth.example.com/oauth2/oidc/callback`).
3. Add the `oidc` block to your config:

```yaml
oidc:
  issuer: "https://accounts.google.com"   # OIDC issuer; endpoints are discovered automatically
  client_id: "xxxxxxxx.apps.googleusercontent.com"
  client_secret: "your-google-client-secret"
  # redirect_url defaults to <server.issuer>/oauth2/oidc/callback
  scopes: ["openid", "email", "profile"]  # optional; this is the default
  allowed_emails:
    - alice@example.com
```

How it works: the proxy redirects the browser to the provider, validates the
returned ID token (signature, audience, nonce) and `email_verified`, checks the
email against `allowed_emails`, and then issues its own authorization code — so
the downstream MCP token exchange is unchanged. The issued access token's `sub`
claim is the user's email.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `~/.mcp-oauth2.yaml` | Path to the configuration file |

## Security notes

- PKCE with `S256` is required for all authorization code flows (OAuth 2.1)
- User passwords must be stored as bcrypt hashes
- A `jwt_secret` is **required**: the server refuses to start with an empty one. Use a strong random value in production
- The `issuer` value is taken from config — request `Host` headers are never trusted
- The proxy serves plain HTTP; terminate TLS in front of it (e.g. a reverse proxy), since tokens and passwords would otherwise travel in cleartext
