# mcp-oauth2-proxy

An OAuth 2.1-compatible authorization server and reverse proxy designed to add authentication to a plain [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) HTTP server with zero changes to the upstream.

It sits in front of your MCP server, handles all OAuth flows, validates Bearer tokens on every request, and forwards authenticated traffic to the upstream.

## Features

- **Authorization code flow** with PKCE (S256) — used by MCP clients such as Claude
- **Client credentials flow** — machine-to-machine access
- Browser-based login form with bcrypt password verification
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
  token_ttl: 3600       # access token lifetime, seconds
  auth_code_ttl: 300    # authorization code lifetime, seconds
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

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| `GET` | `/.well-known/oauth-protected-resource` | Protected resource metadata (RFC 9728) |
| `GET/POST` | `/oauth2/authorize` | Authorization endpoint — shows login form, issues auth codes |
| `POST` | `/oauth2/token` | Token endpoint — `authorization_code` and `client_credentials` grants |
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

### Response

```json
{
  "access_token": "eyJhbGci...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `~/.mcp-oauth2.yaml` | Path to the configuration file |

## Security notes

- PKCE with `S256` is required for all authorization code flows (OAuth 2.1)
- User passwords must be stored as bcrypt hashes
- Set a strong random `jwt_secret` in production
- The `issuer` value is taken from config — request `Host` headers are never trusted
