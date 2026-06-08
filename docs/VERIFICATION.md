# Verifying the MCP OAuth flow

This file is the single place to confirm the server behaves like a correct MCP OAuth resource server.
Each check maps to one requirement of the MCP Authorization spec or a security property worth asserting.

Contents:

- [Verifying the MCP OAuth flow](#verifying-the-mcp-oauth-flow)
  - [1. Prerequisites: bring the stack up](#1-prerequisites-bring-the-stack-up)
  - [2. What "correct" means: the 10 properties to verify](#2-what-correct-means-the-10-properties-to-verify)
  - [3. One-command automated suite](#3-one-command-automated-suite)
  - [4. Step-by-step manual checks](#4-step-by-step-manual-checks)
    - [4.1 Discovery (property 1)](#41-discovery-property-1)
    - [4.2 Challenge (property 2)](#42-challenge-property-2)
    - [4.3 Login and inspect the token (properties 3 and 4)](#43-login-and-inspect-the-token-properties-3-and-4)
    - [4.4 Reject bad tokens (property 4)](#44-reject-bad-tokens-property-4)
    - [4.5 Call tools as the user (properties 5 and 6)](#45-call-tools-as-the-user-properties-5-and-6)
    - [4.6 Token exchange (property 8)](#46-token-exchange-property-8)
    - [4.7 Security hardening checks (properties 7, 9, 10)](#47-security-hardening-checks-properties-7-9-10)
  - [5. Minimal smoke test](#5-minimal-smoke-test)
  - [6. Environment verified against](#6-environment-verified-against)

---

## 1. Prerequisites: bring the stack up

```bash
cd samples/python
docker compose up --build
```

This starts Keycloak (realm pre-imported) on `http://localhost:8080`, the MCP server on
`http://localhost:3000/mcp`, and a mock downstream API on `http://localhost:8888`. Test users:
`alice` / `alice` (has `downstream-reader` role) and `bob` / `bob` (does not).

---

## 2. What "correct" means: the 10 properties to verify

| # | Property | Spec basis |
| --- | --- | --- |
| 1 | Protected Resource Metadata is served publicly (both the bare and resource-suffixed paths) | RFC 9728 |
| 2 | A request with no token is refused with `401` + `WWW-Authenticate` pointing at the metadata | MCP auth / RFC 9728 |
| 3 | A user token is audience-bound to this server (`aud` contains `http://localhost:3000/mcp`) | RFC 8707 |
| 4 | Malformed tokens and tokens for a wrong audience or issuer are rejected with `401` | confused-deputy guard |
| 5 | A valid token reaches the tools (`tools/list` returns 2 tools) | MCP transport |
| 6 | The tool sees the real per-user identity (alice and bob differ) | per-user design |
| 7 | A valid user without the required role is refused at the tool level (alice passes, bob is Forbidden) | per-user authorization |
| 8 | The server can call a downstream as the user via token exchange (`aud` becomes `downstream-api`) | RFC 8693 |
| 9 | Token-derived error text cannot corrupt the `WWW-Authenticate` header (forged `iss` with CRLF/quotes yields a clean `401`, no injected headers, no `500`) | hardening |
| 10 | End-to-end: alice's `api_call` traverses token exchange and reaches the mock downstream, returning a structured result | integration |

Identifiers in this realm:

- Resource id (and expected `aud` value): `http://localhost:3000/mcp`
- Token also carries `aud: mcp-server` (so the server can act as the token-exchange client)
- Downstream audience (exchange target): `downstream-api`

---

## 3. One-command automated suite

Paste this into a shell with the stack running. It prints PASS/FAIL for all 10 properties (14 checks
total; properties 1, 2, 4, and 9 contribute two checks each).

```bash
PASS=0; FAIL=0
check(){ if [ "$1" = "$2" ]; then echo "  PASS  $3"; PASS=$((PASS+1)); else echo "  FAIL  $3 (got '$1' want '$2')"; FAIL=$((FAIL+1)); fi; }
tok(){ curl -s http://localhost:8080/realms/mcp-demo/protocol/openid-connect/token \
  -d grant_type=password -d client_id=mcp-client -d username="$1" -d password="$2" -d scope=openid \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'; }
ALICE=$(tok alice alice); BOB=$(tok bob bob)

# 1) Protected Resource Metadata is public (both paths)
check "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/.well-known/oauth-protected-resource)" 200 "PRM served (root path)"
check "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/.well-known/oauth-protected-resource/mcp)" 200 "PRM served (canonical resource-suffixed path)"

# 2) No token -> 401 + WWW-Authenticate
check "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:3000/mcp -H 'Content-Type: application/json' -d '{}')" 401 "no token -> 401"
check "$(curl -s -D - -o /dev/null -X POST http://localhost:3000/mcp -H 'Content-Type: application/json' -d '{}' | grep -ic 'www-authenticate.*oauth-protected-resource')" 1 "WWW-Authenticate -> resource_metadata URL"

# 3) Token aud contains the resource id
check "$(echo "$ALICE" | cut -d. -f2 | python3 -c 'import sys,base64,json; s=sys.stdin.read().strip(); s+="="*(-len(s)%4); a=json.loads(base64.urlsafe_b64decode(s)).get("aud"); print("http://localhost:3000/mcp" in (a if isinstance(a,list) else [a]))')" True "user token aud contains the resource id"

# 4) Reject malformed and foreign-audience tokens
check "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:3000/mcp -H 'Authorization: Bearer bad.tok.en' -H 'Content-Type: application/json' -d '{}')" 401 "garbage token -> 401"
WRONG=$(curl -s http://localhost:8080/realms/mcp-demo/protocol/openid-connect/token -d grant_type=client_credentials -d client_id=mcp-server -d client_secret=mcp-server-secret-change-me | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
check "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST http://localhost:3000/mcp -H "Authorization: Bearer $WRONG" -H 'Content-Type: application/json' -d '{}')" 401 "wrong audience (mcp-server service account) -> 401"

# 5) Valid token -> tools/list returns 2 tools
check "$(curl -s --max-time 10 -X POST http://localhost:3000/mcp -H "Authorization: Bearer $ALICE" -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | sed 's/^data: //' | grep -E '^\{' | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["result"]["tools"]))')" 2 "tools/list -> 2 tools"

# 6) Per-user identity: alice has downstream-reader, bob does not
check "$(curl -s --max-time 10 -X POST http://localhost:3000/mcp -H "Authorization: Bearer $ALICE" -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}' | sed 's/^data: //' | grep -E '^\{' | python3 -c 'import sys,json; t=json.loads(json.load(sys.stdin)["result"]["content"][0]["text"]); print("downstream-reader" in t["roles"])')" True "whoami(alice) includes downstream-reader role"

# 7) Tool-level role gate: bob holds a valid token but lacks downstream-reader
check "$(curl -s --max-time 10 -X POST http://localhost:3000/mcp -H "Authorization: Bearer $BOB" -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"api_call","arguments":{"query":"demo"}}}' | sed 's/^data: //' | grep -E '^\{' | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["content"][0]["text"].split(":")[0])')" "Forbidden" "role gate -> bob is Forbidden"

# 8) RFC 8693 token exchange -> exchanged token aud = downstream-api
check "$(curl -s http://localhost:8080/realms/mcp-demo/protocol/openid-connect/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange -d client_id=mcp-server -d client_secret=mcp-server-secret-change-me \
  -d subject_token="$ALICE" -d subject_token_type=urn:ietf:params:oauth:token-type:access_token -d audience=downstream-api \
  | python3 -c 'import sys,json,base64; t=json.load(sys.stdin)["access_token"]; p=t.split(".")[1]; p+="="*(-len(p)%4); print(json.loads(base64.urlsafe_b64decode(p)).get("aud"))')" downstream-api "token exchange -> aud=downstream-api"

# 9) Forged iss with CRLF/quotes -> clean 401, no injected header
EVIL=$(python3 -c 'import base64,json
b=lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
print(b({"alg":"RS256","typ":"JWT"})+"."+b({"iss":"https://evil.example/x\"\r\nSet-Cookie: pwn=1","sub":"x"})+".sig")')
check "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:3000/mcp -H "Authorization: Bearer $EVIL" -H 'Content-Type: application/json' -d '{}')" 401 "forged iss with CRLF/quotes -> clean 401 (not 500)"
check "$(curl -s -D - -o /dev/null -X POST http://localhost:3000/mcp -H "Authorization: Bearer $EVIL" -H 'Content-Type: application/json' -d '{}' | grep -ci '^set-cookie')" 0 "no injected Set-Cookie header"

# 10) End-to-end: alice api_call -> token exchange -> mock-api -> success
check "$(curl -s --max-time 20 -X POST http://localhost:3000/mcp -H "Authorization: Bearer $ALICE" -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"api_call","arguments":{"query":"hello"}}}' | sed 's/^data: //' | grep -E '^\{' | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["content"][0]["text"].split()[0])')" "Called" "end-to-end: alice api_call reaches mock-api"

echo "RESULT: $PASS passed, $FAIL failed"
```

Expected: `RESULT: 14 passed, 0 failed`.

---

## 4. Step-by-step manual checks

Run these one at a time to see each requirement in isolation.

### 4.1 Discovery (property 1)

```bash
curl -s http://localhost:3000/.well-known/oauth-protected-resource | python3 -m json.tool
```

Expect `resource: "http://localhost:3000/mcp"` and `authorization_servers` listing the Keycloak realm.
Both the bare path and the resource-suffixed path (`/mcp` appended) return this document.

### 4.2 Challenge (property 2)

```bash
curl -i -X POST http://localhost:3000/mcp -H 'Content-Type: application/json' -d '{}'
```

Expect `401` and `WWW-Authenticate: Bearer resource_metadata="...oauth-protected-resource/mcp", error="invalid_token"`.

### 4.3 Login and inspect the token (properties 3 and 4)

```bash
TOKEN=$(curl -s http://localhost:8080/realms/mcp-demo/protocol/openid-connect/token \
  -d grant_type=password -d client_id=mcp-client \
  -d username=alice -d password=alice -d scope=openid \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

echo "$TOKEN" | cut -d. -f2 | python3 -c '
import sys,base64,json; s=sys.stdin.read().strip(); s+="="*(-len(s)%4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(s)), indent=2))'
```

Confirm `aud` includes `http://localhost:3000/mcp` and `mcp-server`, `sub` is set, and
`realm_access.roles` lists `mcp-user` and `downstream-reader`.

### 4.4 Reject bad tokens (property 4)

```bash
# malformed
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3000/mcp \
  -H 'Authorization: Bearer not.a.jwt' -H 'Content-Type: application/json' -d '{}'   # -> 401

# wrong audience (service account token; aud does not include http://localhost:3000/mcp)
WRONG=$(curl -s http://localhost:8080/realms/mcp-demo/protocol/openid-connect/token \
  -d grant_type=client_credentials -d client_id=mcp-server -d client_secret=mcp-server-secret-change-me \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer $WRONG" -H 'Content-Type: application/json' -d '{}'       # -> 401
```

### 4.5 Call tools as the user (properties 5 and 6)

```bash
who(){ curl -s -X POST http://localhost:3000/mcp -H "Authorization: Bearer $1" \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}' \
  | sed 's/^data: //' | grep -E '^\{'; }

ALICE=$(curl -s http://localhost:8080/realms/mcp-demo/protocol/openid-connect/token -d grant_type=password -d client_id=mcp-client -d username=alice -d password=alice -d scope=openid | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

BOB=$(curl -s http://localhost:8080/realms/mcp-demo/protocol/openid-connect/token -d grant_type=password -d client_id=mcp-client -d username=bob -d password=bob -d scope=openid | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
who "$ALICE"; who "$BOB"
```

Alice and Bob return different `sub`, `email`, and `roles` (alice has `downstream-reader`, bob does not).

### 4.6 Token exchange (property 8)

```bash
curl -s http://localhost:8080/realms/mcp-demo/protocol/openid-connect/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=mcp-server -d client_secret=mcp-server-secret-change-me \
  -d subject_token="$ALICE" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=downstream-api \
  | python3 -c '
import sys,json,base64
t=json.load(sys.stdin)["access_token"]; p=t.split(".")[1]; p+="="*(-len(p)%4)
c=json.loads(base64.urlsafe_b64decode(p))
print("aud:", c.get("aud"), "  email:", c.get("email"))'
```

Confirm `aud` is `downstream-api` and `email` is still `alice@example.com` (identity preserved through
the exchange).

### 4.7 Security hardening checks (properties 7, 9, 10)

**Role gate (property 7).** Call `api_call` with Bob's token:

```bash
curl -s -X POST http://localhost:3000/mcp -H "Authorization: Bearer $BOB" \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"api_call","arguments":{"query":"demo"}}}' \
  | sed 's/^data: //' | grep -E '^\{'
# result.content[0].text starts with "Forbidden: bob@example.com lacks ..."
```

**Header sanitization (property 9).** Forge an (unsigned) token whose `iss` claim embeds CRLF and
quotes. The server must answer a clean `401` with no injected header:

```bash
EVIL=$(python3 -c 'import base64,json
b=lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
print(b({"alg":"RS256","typ":"JWT"})+"."+b({"iss":"https://evil.example/x\"\r\nSet-Cookie: pwn=1","sub":"x"})+".sig")')

curl -s -D - -o /dev/null -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer $EVIL" -H 'Content-Type: application/json' -d '{}' \
  | grep -i 'www-authenticate\|set-cookie'
# expect ONE www-authenticate line with the sanitized description, NO set-cookie header.
```

**End-to-end downstream call (property 10).** Call `api_call` as alice -- the role gate passes,
the server exchanges her token for a `downstream-api`-audience token, then calls the mock downstream.
The tool result starts with `Called http://mock-api:8888/api/search?q=hello` and contains the echo
response (query params + forwarded headers) from the mock server:

```bash
curl -s -X POST http://localhost:3000/mcp -H "Authorization: Bearer $ALICE" \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"api_call","arguments":{"query":"hello"}}}' \
  | sed 's/^data: //' | grep -E '^\{'
# result.content[0].text: "Called http://mock-api:8888/api/search?q=hello\nacting as: <sub>\nstatus: 200\nbody: ..."
```

---

## 5. Minimal smoke test

The quickest "is it alive and enforcing auth" check:

```bash
# 1) Get a user token (real clients use auth-code + PKCE in a browser)
TOKEN=$(curl -s http://localhost:8080/realms/mcp-demo/protocol/openid-connect/token \
  -d grant_type=password -d client_id=mcp-client \
  -d username=alice -d password=alice -d scope=openid \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# 2) No token -> 401 + WWW-Authenticate
curl -i -X POST http://localhost:3000/mcp -H 'Content-Type: application/json' -d '{}'

# 3) With token -> tools/list succeeds
curl -s -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Note: `api_call` returns a live response from the mock downstream (`mendhak/http-https-echo`) that
echoes the request back as JSON, including the forwarded `Authorization` header and query string.

---

## 6. Environment verified against

- Docker Engine 29.x, Keycloak 26.3, Python 3.14-slim (server image), `mendhak/http-https-echo:latest` (mock downstream).
- `fastmcp` >= 3.4.2, `httpx` >= 0.28.1, `pyjwt` >= 2.13.0, `starlette` >= 1.2.1, `uvicorn` >= 0.32.0.
- Keycloak 26.3 is required: Standard Token Exchange v2 is only default-enabled from 26.2 onward.
