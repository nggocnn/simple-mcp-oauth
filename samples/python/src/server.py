from __future__ import annotations

import json
import sys

import uvicorn

from urllib.parse import urlparse
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import config
from .tools import mcp, current_user
from .auth.providers import verify_access_token, warm_providers, TokenError

_RESOURCE_PATH = urlparse(config.resource).path.rstrip("/")
METADATA_PATH = "/.well-known/oauth-protected-resource"
CANONICAL_METADATA_PATH = f"{METADATA_PATH}{_RESOURCE_PATH}"

def protected_resource_metadata(_request: Request) -> JSONResponse:
    return JSONResponse({
        "resource": config.resource,
        "authorization_servers": config.issuers,
        "bearer_methods_supported": ["header"],
        "scopes_supported": config.supported_scopes,
        "resource_documentation": f"{config.public_url}/",
    })

def healthz(_request: Request) -> JSONResponse:
    return JSONResponse({"ok": True})

def _header_safe(value: str) -> str:
    cleaned = "".join(c if " " <= c <= "~" else " " for c in value).replace('"', "'")
    return cleaned[:200]


class AuthMiddleware:

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
    
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return
        
        auth_header = Headers(scope=scope).get("authorization", "")
        if not auth_header.startswith("Bearer "):
            await self._challenge(send, "invalid_token", "Missing Bearer token")
            return

        token = auth_header[len("Bearer "):].strip()
        try:
            user = verify_access_token(token)
        except TokenError as e:
            await self._challenge(send, "invalid_token", str(e))
            return
        
        reset = current_user.set(user)
        try:
            await self.app(scope, receive, send)
        finally:
            current_user.reset(reset)

    async def _challenge(self, send: Send, error: str, description: str) -> None:
        safe = _header_safe(description)
        metadata_url = f"{config.public_url}{CANONICAL_METADATA_PATH}"
        body = json.dumps({
            "error": error,
            "error_description": safe
        })
        headers = [
            (b"content-type", b"application/json"),
            (b"www-authenticate", f'Bearer resource_metadata="{metadata_url}", error="{_header_safe(error)}", error_description="{safe}"'.encode()),
        ]
        await send({"type": "http.response.start", "status": 401, "headers": headers})
        await send({"type": "http.response.body", "body": body.encode("utf-8")})

def build_app() -> Starlette:
    # Streamable HTTP transport served at /mcp (FastMCP "http" transport).
    mcp_app = mcp.http_app(path="/mcp", transport="http")

    routes = [
        Route(METADATA_PATH, protected_resource_metadata),
        Route("/healthz", healthz),
        Mount("/", app=AuthMiddleware(mcp_app)),
    ]
    if CANONICAL_METADATA_PATH != METADATA_PATH:
        routes.insert(1, Route(CANONICAL_METADATA_PATH, protected_resource_metadata))

    # The MCP app's lifespan must run so its session manager starts.
    return Starlette(routes=routes, lifespan=mcp_app.lifespan)

def main() -> None:
    warm_providers()

    print(
        f"{config.server_name} listening on :{config.port} "
        f"(mcp endpoint: {config.public_url}/mcp)",
        file=sys.stderr,
    )
    uvicorn.run(build_app(), host="0.0.0.0", port=config.port)

if __name__ == "__main__":
    main()