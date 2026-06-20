# Keycloak demo realm

`realm-export.json` is a self-contained Keycloak realm (`mcp-demo`) that acts as
the OIDC **authorization server** for both the Python and TypeScript samples. The
`docker compose` setup in each sample imports it automatically on startup
(`start-dev --import-realm`), so you normally don't touch this directly.

Keycloak **26.2+** is required: Standard Token Exchange v2 (used for RFC 8693)
is only default-enabled from that version onward. The samples pin `26.3`.

## What's in the realm

### Clients

| Client | Type | Purpose |
| --- | --- | --- |
| `mcp-client` | public, auth-code + PKCE | The MCP client (IDE/agent) that logs the user in and obtains an access token. Redirect URIs allow common local + editor callbacks. |
| `mcp-server` | confidential (`serviceAccountsEnabled`, Standard Token Exchange enabled) | This MCP server. Uses its client credentials to perform the RFC 8693 token exchange. Secret: `mcp-server-secret-change-me`. |
| `downstream-api` | confidential | Represents the downstream API; exists so `downstream-api` is a valid audience. Secret: `downstream-secret-change-me`. |

### Realm roles

| Role | Meaning |
| --- | --- |
| `mcp-user` | Baseline role for anyone allowed to use the MCP server. |
| `downstream-reader` | Additional role required by the `api_call` tool. |

### Users

| Username | Password | Roles |
| --- | --- | --- |
| `alice` | `alice` | `mcp-user`, `downstream-reader`, `offline_access` |
| `bob` | `bob` | `mcp-user`, `offline_access` |

Alice can use `api_call`; bob holds a valid token but is refused at the tool
level — demonstrating per-user authorization.

### The `mcp:tools` scope

This client scope is the heart of the audience binding. When requested, its two
audience mappers stamp the access token's `aud` claim with:

- **`http://localhost:3000/mcp`** — the MCP server's resource id, so the token is
  accepted by this resource server (RFC 8707).
- **`mcp-server`** — lets the token exchange recognize `mcp-server` as the actor.

Other standard scopes (`openid`, `profile`, `email`, `roles`, `offline_access`,
…) are also present.

## Getting a token by hand

The samples expect tokens minted by this realm. For testing you can grab one
with the resource-owner password grant (real clients use auth-code + PKCE):

```bash
curl -s http://localhost:8080/realms/mcp-demo/protocol/openid-connect/token \
  -d grant_type=password -d client_id=mcp-client \
  -d username=alice -d password=alice \
  -d 'scope=openid mcp:tools'
```

The token's `aud` will include `http://localhost:3000/mcp`. See
[`../../docs/VERIFICATION.md`](../../docs/VERIFICATION.md) for the full set of
checks, including the token-exchange flow.

## Admin console

While the stack is up, the Keycloak admin console is at
`http://localhost:8080` (`admin` / `admin`). Changes made there are **not**
persisted back to `realm-export.json` — edit the JSON to make changes stick.
