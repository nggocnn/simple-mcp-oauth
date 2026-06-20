# Simple MCP OAuth — Python

A minimal MCP server (Streamable HTTP transport) that authenticates callers with
OAuth 2.0 / OIDC bearer tokens and calls a downstream API on the user's behalf
via OAuth Token Exchange (RFC 8693). Built on **FastMCP**, **Starlette**, and
**PyJWT**. A line-for-line TypeScript port lives in [`../typescript`](../typescript).

## How it works

- **`/mcp`** — the MCP endpoint, wrapped by an ASGI auth middleware
  (`AuthMiddleware` in `src/server.py`). Every request must carry a `Bearer`
  access token, validated against the configured OIDC issuer(s): signature via
  JWKS, issuer, expiry, and audience. The required scope is then checked before
  the request reaches the MCP server.
- **`/.well-known/oauth-protected-resource`** — OAuth Protected Resource
  Metadata (RFC 9728), also served at the canonical path that includes the
  resource's path component. Unauthenticated `/mcp` requests get a `401` with a
  `WWW-Authenticate` header pointing here.
- **`/healthz`** — liveness probe.

The verified identity is carried per-request in a `ContextVar` (`current_user`)
that the middleware sets and the tools read.

### Tools

- **`whoami`** — returns the authenticated subject, email, issuer, and roles.
- **`api_call`** — requires the `downstream-reader` realm role; exchanges the
  caller's token for a downstream token and calls
  `${DOWNSTREAM_BASE_URL}/api/search?q=...`.

## Project layout

```txt
src/
  config.py            # env-driven configuration singleton
  server.py            # ASGI app: metadata + health routes, MCP behind auth
  tools.py             # FastMCP server + whoami / api_call tools
  auth/
    providers.py       # OIDC discovery + access-token verification
    downstream.py      # RFC 8693 token exchange
```

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `PUBLIC_URL` | yes | — | Public base URL of this server |
| `RESOURCE` | yes | — | Resource identifier (the `/mcp` URL) |
| `PORT` | no | `3000` | Listen port |
| `SERVER_NAME` | no | `Simple MCP OAuth` | MCP server name |
| `OIDC_ISSUER` / `OIDC_ISSUERS` | yes | — | Trusted issuer(s), comma-separated |
| `SUPPORTED_SCOPES` | no | `openid profile email` | Advertised scopes |
| `REQUIRED_SCOPES` | no | = `SUPPORTED_SCOPES` | Scope(s) required on `/mcp` |
| `CLIENT_ID` / `CLIENT_SECRET` | for token exchange | — | Confidential client creds |
| `DOWNSTREAM_STRATEGY` | no | `token-exchange` | Downstream credential strategy |
| `DOWNSTREAM_AUDIENCE` | no | `downstream-api` | Audience requested in the exchange |
| `DOWNSTREAM_BASE_URL` | for `api_call` | — | Base URL of the downstream API |
| `REQUEST_TIMEOUT` | no | `20` | HTTP timeout (seconds) |

## Run locally

Using [uv](https://docs.astral.sh/uv/):

```bash
uv sync
PUBLIC_URL=http://localhost:3000 RESOURCE=http://localhost:3000/mcp \
  OIDC_ISSUER=http://localhost:8080/realms/mcp-demo \
  uv run simple-mcp-oauth
```

## Run with Docker Compose

Brings up Keycloak (issuer), a mock downstream API, and this server:

```bash
docker compose up --build
```

The MCP endpoint is then at `http://localhost:3000/mcp`. See
[`../../docs/VERIFICATION.md`](../../docs/VERIFICATION.md) to verify the flow.
