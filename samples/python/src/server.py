"""ASGI application: OAuth-protected MCP endpoint plus public metadata.

Wiring overview:

* ``GET /.well-known/oauth-protected-resource`` (and the resource-suffixed
  canonical path) serve OAuth Protected Resource Metadata (RFC 9728) publicly.
* ``GET /healthz`` is an unauthenticated liveness probe.
* Everything under ``/mcp`` is wrapped by :class:`AuthMiddleware`, which
  enforces a valid, audience-bound, sufficiently-scoped bearer token before the
  MCP transport ever sees the request.
"""

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

# Metadata is served both at the bare well-known path and at the path that
# includes the resource's path component, which is the location a client
# derives from the resource identifier (RFC 9728 / RFC 8414 style).
_RESOURCE_PATH = urlparse(config.resource).path.rstrip("/")
METADATA_PATH = "/.well-known/oauth-protected-resource"
CANONICAL_METADATA_PATH = f"{METADATA_PATH}{_RESOURCE_PATH}"


def protected_resource_metadata(_request: Request) -> JSONResponse:
    """Serve the OAuth Protected Resource Metadata document (RFC 9728)."""
    return JSONResponse(
        {
            "resource": config.resource,
            "authorization_servers": config.issuers,
            "bearer_methods_supported": ["header"],
            "scopes_supported": config.supported_scopes,
            "resource_documentation": f"{config.public_url}/",
        }
    )


def healthz(_request: Request) -> JSONResponse:
    """Liveness probe."""
    return JSONResponse({"ok": True})


def _header_safe(value: str) -> str:
    """Sanitize a string for safe inclusion in an HTTP header value.

    Token-derived text (e.g. a forged ``iss``) ends up in the
    ``WWW-Authenticate`` header, so we drop anything outside printable ASCII —
    neutralizing CR/LF header-injection — and downgrade double quotes to single
    quotes so the header's quoted strings can't be broken out of. Capped at 200
    chars to keep the header bounded.
    """
    cleaned = "".join(c if " " <= c <= "~" else " " for c in value).replace('"', "'")
    return cleaned[:200]


class AuthMiddleware:
    """ASGI middleware that enforces OAuth on ``/mcp`` requests.

    Requests outside ``/mcp`` pass straight through. For ``/mcp``, it requires a
    Bearer token, verifies it, checks the required scopes, and stashes the
    resulting user in the ``current_user`` ContextVar for the tools to read.
    Any failure short-circuits with a 401 challenge.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Only guard the MCP endpoint; metadata/health are public.
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        auth_header = Headers(scope=scope).get("authorization", "")
        if not auth_header.startswith("Bearer "):
            await self._challenge(send, "invalid_token", "Missing Bearer token")
            return

        token = auth_header[len("Bearer ") :].strip()
        try:
            user = verify_access_token(token)
        except TokenError as e:
            await self._challenge(send, "invalid_token", str(e))
            return

        # Scope gate: the token must carry at least one required scope.
        required = set(config.required_scopes)
        if required and not required.intersection(user.scopes):
            await self._challenge(
                send,
                "insufficient_scope",
                f"Token is missing required scope(s): {', '.join(sorted(required))}",
            )
            return

        # Bind the identity for the duration of this request, then always reset
        # it so it can't leak into another request on the same task.
        reset = current_user.set(user)
        try:
            await self.app(scope, receive, send)
        finally:
            current_user.reset(reset)

    async def _challenge(self, send: Send, error: str, description: str) -> None:
        """Send a 401 with a ``WWW-Authenticate`` header pointing at metadata."""
        safe = _header_safe(description)
        metadata_url = f"{config.public_url}{CANONICAL_METADATA_PATH}"
        body = json.dumps({"error": error, "error_description": safe})
        headers = [
            (b"content-type", b"application/json"),
            (
                b"www-authenticate",
                f'Bearer resource_metadata="{metadata_url}", error="{_header_safe(error)}", error_description="{safe}"'.encode(),
            ),
        ]
        await send({"type": "http.response.start", "status": 401, "headers": headers})
        await send({"type": "http.response.body", "body": body.encode("utf-8")})


def build_app() -> Starlette:
    """Assemble the Starlette app: metadata + health routes, MCP behind auth."""
    # Streamable HTTP transport served at /mcp (FastMCP "http" transport).
    mcp_app = mcp.http_app(path="/mcp", transport="http", stateless_http=True)

    routes = [
        Route(METADATA_PATH, protected_resource_metadata),
        Route("/healthz", healthz),
        Mount("/", app=AuthMiddleware(mcp_app)),
    ]
    # Only add the resource-suffixed metadata route when it actually differs
    # from the bare path (i.e. the resource has a non-empty path component).
    if CANONICAL_METADATA_PATH != METADATA_PATH:
        routes.insert(1, Route(CANONICAL_METADATA_PATH, protected_resource_metadata))

    # The MCP app's lifespan must run so its session manager starts.
    return Starlette(routes=routes, lifespan=mcp_app.lifespan)


def main() -> None:
    """Entry point: warm provider caches, then serve with uvicorn."""
    warm_providers()

    print(
        f"{config.server_name} listening on :{config.port} "
        f"(mcp endpoint: {config.public_url}/mcp)",
        file=sys.stderr,
    )
    uvicorn.run(build_app(), host="0.0.0.0", port=config.port)


if __name__ == "__main__":
    main()
