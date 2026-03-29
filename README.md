# jwt-guard

A lightweight reverse proxy that validates JWT tokens before forwarding requests upstream. Built in Rust with async I/O for high throughput and low latency.

## How it works

```
Client ──Bearer token──> jwt-guard ──validated──> Upstream
                            │
                        JWKS Cache
                      (auto-refreshed)
```

1. Extracts the `Authorization: Bearer <token>` header
2. Tries each configured auth scheme in order (as listed in `JWT_GUARD_AUTH_SCHEMES`)
3. Validates the token signature against the scheme's JWKS
4. On first successful validation, forwards the request upstream
5. Optionally injects `X-JWT-Payload` (raw base64url payload) and `X-JWT-Scheme` headers

## Quick start

```yaml
# compose.yml
services:
  jwt-guard:
    image: jwt-guard
    build: .
    ports:
      - "3000:3000"
    environment:
      PORT: 3000
      JWT_GUARD_TARGET_URL: http://upstream:8000

      JWT_GUARD_AUTH_SCHEMES: GOOGLE
      JWT_GUARD_GOOGLE_ISSUER: https://accounts.google.com
      JWT_GUARD_GOOGLE_JWKS_URI: https://www.googleapis.com/oauth2/v3/certs
```

```sh
docker compose up
curl -H "Authorization: Bearer <token>" http://localhost:3000/any/path
```

## Configuration

All configuration is via environment variables.

### Required

| Variable                 | Description                                                   |
| ------------------------ | ------------------------------------------------------------- |
| `JWT_GUARD_TARGET_URL`   | Upstream URL to forward validated requests to (HTTP or HTTPS) |
| `JWT_GUARD_AUTH_SCHEMES` | Comma-separated list of scheme names, tried in order          |

### Per-scheme

For each scheme name in `JWT_GUARD_AUTH_SCHEMES`, the following variables are available. The scheme name in the variable must match the case used in `AUTH_SCHEMES`.

| Variable                     | Required | Description                                                                                                                            |
| ---------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `JWT_GUARD_{NAME}_JWKS_URI`  | Yes*     | JWKS endpoint URL                                                                                                                      |
| `JWT_GUARD_{NAME}_ISSUER`    | No       | Issuer URL. If set, enables OpenID Connect discovery and issuer claim validation. If omitted, validation relies on JWKS signature only |
| `JWT_GUARD_{NAME}_AUDIENCE`  | No       | Expected `aud` claim (single value)                                                                                                    |
| `JWT_GUARD_{NAME}_AUDIENCES` | No       | Expected `aud` claims (comma-separated)                                                                                                |

\* Required unless `_ISSUER` is set and supports `.well-known/openid-configuration` discovery (which provides the JWKS URI automatically).

### Forwarding

| Variable                          | Default | Description                                                                                                                      |
| --------------------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `JWT_GUARD_FORWARD_PAYLOAD`       | `true`  | Forward the raw JWT payload upstream. `true`/`1` uses `X-JWT-Payload`; a value starting with `x-` sets a custom header name      |
| `JWT_GUARD_FORWARD_SCHEME`        | `false` | Forward the matched scheme name upstream. `true`/`1` uses `X-JWT-Scheme`; a value starting with `x-` sets a custom header name   |
| `JWT_GUARD_FORWARD_AUTHORIZATION` | `false` | Forward the original `Authorization` header upstream                                                                             |

### Server

| Variable                   | Default | Description                                   |
| -------------------------- | ------- | --------------------------------------------- |
| `PORT`                     | `8000`  | Port to listen on                             |
| `JWT_GUARD_LOGGING_FORMAT` | `text`  | Log format: `none`, `text`, or `google_cloud` |

When `google_cloud` is set, access logs are emitted as structured JSON with `httpRequest` and `severity` fields compatible with Cloud Logging. Trace context is extracted from the `X-Cloud-Trace-Context` header. The GCP project ID is read from `GOOGLE_CLOUD_PROJECT` if set, otherwise fetched from the metadata server.

### Advanced

| Variable                     | Default | Description                            |
| ---------------------------- | ------- | -------------------------------------- |
| `JWT_GUARD_JWKS_REFRESH`     | `900`   | JWKS cache refresh interval in seconds |
| `JWT_GUARD_UPSTREAM_TIMEOUT` | `30`    | Upstream request timeout in seconds    |

## Multiple providers

```sh
JWT_GUARD_AUTH_SCHEMES=GOOGLE,GITHUB,AZURE

JWT_GUARD_GOOGLE_ISSUER=https://accounts.google.com
JWT_GUARD_GOOGLE_JWKS_URI=https://www.googleapis.com/oauth2/v3/certs

JWT_GUARD_GITHUB_JWKS_URI=https://token.actions.githubusercontent.com/.well-known/jwks

JWT_GUARD_AZURE_ISSUER=https://login.microsoftonline.com/{tenant}/v2.0
JWT_GUARD_AZURE_AUDIENCE=api://my-app
```

Schemes are tried in the order listed. The first successful signature validation wins.

## Error responses

Errors are returned as JSON when the request `Accept` header includes `application/json` or `*/*`, otherwise as plain text.

| Status | Meaning                                                                                 |
| ------ | --------------------------------------------------------------------------------------- |
| `401`  | Missing/invalid auth header, bad JWT, signature mismatch, expired token, wrong audience |
| `502`  | JWKS fetch failure or upstream connection error                                         |

## Development

```sh
# Run tests (34 security + 5 load)
cargo test

# Docker Compose with hot reload
docker compose up --watch
```

## Benchmarking

Compares jwt-guard against Envoy proxy, both doing JWT validation in front of the same upstream.

```sh
# Prerequisites: docker, openssl, node, hey
./bench/run.sh              # 1000 requests, 50 concurrency
./bench/run.sh 5000 100     # custom
```

## Docker

The production image uses a [distroless](https://github.com/GoogleContainerTools/distroless) base (~20MB) and runs as a non-root user.

```sh
docker build -t jwt-guard .
docker run -e JWT_GUARD_TARGET_URL=http://backend:8080 \
           -e JWT_GUARD_AUTH_SCHEMES=MY_IDP \
           -e JWT_GUARD_MY_IDP_JWKS_URI=https://idp.example.com/.well-known/jwks.json \
           -p 3000:8000 \
           jwt-guard
```
