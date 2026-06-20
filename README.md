# simple-mcp-oauth

A minimal, end-to-end reference for securing a **Model Context Protocol (MCP)**
server with **OAuth 2.0 / OIDC** — and for calling a downstream API *as the
authenticated user* via **OAuth Token Exchange (RFC 8693)**.

The same server is implemented twice — in **Python** and **TypeScript** — so you
can compare the two stacks line for line. Both expose identical endpoints and
pass the same [verification suite](docs/VERIFICATION.md).

## What it demonstrates

- **Protected Resource Metadata (RFC 9728)** — the server publishes where its
  tokens come from, served at both the bare and resource-suffixed well-known paths.
- **Bearer-token enforcement** — every `/mcp` request must carry a JWT that is
  signature-valid, from a trusted issuer, unexpired, and **audience-bound** to
  this server (RFC 8707) — the guard against confused-deputy token replay.
- **Scope gating** — a token must carry the required scope to reach the tools.
- **Per-user identity in tools** — tools see the real caller, not a service
  account. `whoami` echoes it back.
- **Tool-level authorization** — `api_call` additionally requires a realm role
  (`downstream-reader`), so a valid token is necessary but not sufficient.
- **Token Exchange (RFC 8693)** — to call the downstream API, the server swaps
  the user's token for a fresh one audience-bound to that API, preserving the
  user's identity. No token is ever used outside its intended audience.
- **Header-injection hardening** — token-derived text is sanitized before it
  reaches the `WWW-Authenticate` header.

## Layout

| Path | What's there |
| --- | --- |
| [`samples/python`](samples/python) | Python implementation (FastMCP + Starlette + PyJWT) |
| [`samples/typescript`](samples/typescript) | TypeScript implementation (MCP SDK + Express + jose) |
| [`samples/keycloak`](samples/keycloak) | Pre-built Keycloak realm (issuer) used by both samples |
| [`docs/VERIFICATION.md`](docs/VERIFICATION.md) | The 10 correctness/security properties and how to verify them |

## Quick start

Pick a sample and bring up its full stack (Keycloak issuer + mock downstream +
the MCP server) with Docker Compose:

```bash
cd samples/python        # or: cd samples/typescript
docker compose up --build
```

Then the MCP endpoint is at `http://localhost:3000/mcp`, Keycloak at
`http://localhost:8080`. Follow [`docs/VERIFICATION.md`](docs/VERIFICATION.md)
to exercise and verify the full OAuth flow.

The demo realm ships two users: **alice** / `alice` (has the `downstream-reader`
role) and **bob** / `bob` (does not).

## License

MIT — see [LICENSE](LICENSE).
