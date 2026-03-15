# mcp-oauth2-go

An OAuth2 authorization server implementing the **client credentials grant** (RFC 6749 §4.4), supporting multiple configured applications.

## Quick start

```bash
git clone https://github.com/clems4ever/mcp-oauth2-go
cd mcp-oauth2-go
go build -o mcp-oauth2-go .
./mcp-oauth2-go --config example-config.yaml
```

## Configuration

```yaml
server:
  port: 8080
  jwt_secret: "change-me-in-production"
  token_ttl: 3600  # access token lifetime in seconds

applications:
  - name: my-service
    client_id: "service-client-id"
    client_secret: "service-client-secret"
    allowed_scopes:
      - read
      - write

  - name: analytics
    client_id: "analytics-client-id"
    client_secret: "analytics-client-secret"
    allowed_scopes:
      - analytics:read
```

Default config path: `~/.mcp-oauth2.yaml`. Override with `--config`.

## Token endpoint

```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

grant_type=client_credentials[&scope=read write]
```

Alternatively, pass `client_id` and `client_secret` as form fields.

**Success (200):**
```json
{
  "access_token": "eyJhbGci...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

**Error (400/401):**
```json
{
  "error": "invalid_client",
  "error_description": "invalid client credentials"
}
```

### Example with curl

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -u service-client-id:service-client-secret \
  -d "grant_type=client_credentials&scope=read"
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `~/.mcp-oauth2.yaml` | Path to the configuration file |
