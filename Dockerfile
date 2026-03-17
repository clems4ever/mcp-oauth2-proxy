# ---- build stage ----
FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /mcp-oauth2-proxy .

# ---- runtime stage ----
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /mcp-oauth2-proxy /mcp-oauth2-proxy

ENTRYPOINT ["/mcp-oauth2-proxy"]
