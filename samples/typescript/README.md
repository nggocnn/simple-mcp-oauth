# Simple MCP OAuth — TypeScript

A minimal MCP server (Streamable HTTP transport) that authenticates callers with
OAuth 2.0 / OIDC bearer tokens and calls a downstream API on the user's behalf
via OAuth Token Exchange (RFC 8693). This is a 1:1 port of the Python sample in
[`../python`](../python).

## How it works

- **`/mcp`** — the MCP endpoint, guarded by `authMiddleware`. Every request must
  carry a `Bearer` access token. The token is validated against the configured
  OIDC issuer(s) (signature via JWKS, issuer, expiry, audience). The required
  scope is then checked before the request reaches the MCP server.
- **`/.well-known/oauth-protected-resource`** — OAuth Protected Resource Metadata
  (RFC 9728), also served at the canonical path that includes the resource path.
  Unauthenticated `/mcp` requests get a `401` with a `WWW-Authenticate` header
  pointing here.
- **`/healthz`** — liveness probe.

### Tools

- **`whoami`** — returns the authenticated subject, email, issuer, and roles.
- **`api_call`** — requires the `downstream-reader` realm role; exchanges the
  caller's token for a downstream token and calls
  `${DOWNSTREAM_BASE_URL}/api/search?q=...`.

The verified identity is carried per-request in an `AsyncLocalStorage` store
(`currentUser`) that the middleware sets and the tools read — the TypeScript
analogue of Python's `ContextVar`.

## Project layout

```
src/
  config.ts            # env-driven configuration singleton
  server.ts            # Express app: metadata + health routes, MCP behind auth
  tools.ts             # MCP server factory + whoami / api_call tools
  auth/
    providers.ts       # OIDC discovery + access-token verification (jose)
    downstream.ts      # RFC 8693 token exchange
    metadata.ts        # Protected Resource Metadata (RFC 9728)
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

```bash
npm install
npm run build
PUBLIC_URL=http://localhost:3000 RESOURCE=http://localhost:3000/mcp \
  OIDC_ISSUER=http://localhost:8080/realms/mcp-demo \
  npm start
```

`npm run dev` recompiles on change. `npm run typecheck` checks types without emitting.

## Run with Docker Compose

Brings up Keycloak (issuer), a mock downstream API, and this server:

```bash
docker compose up --build
```

The MCP endpoint is then at `http://localhost:3000/mcp`. See
[`../../docs/VERIFICATION.md`](../../docs/VERIFICATION.md) to verify the flow.
