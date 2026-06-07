from __future__ import annotations

import json
import httpx

from contextvars import ContextVar
from urllib.parse import urlparse
from fastmcp import FastMCP

from .config import config
from .auth.providers import AuthenticatedUser

current_user: ContextVar[AuthenticatedUser | None] = ContextVar(
    "current_user", default=None
)

mcp = FastMCP(config.server_name)

@mcp.tool(description="whoami")
def whoami() -> str:
    user = current_user.get()

    if user is None:
        return json.dumps({"note": "No OAuth user. Running with PAT."})

    return json.dumps(
        {
            "subject": user.subject,
            "email": user.email,
            "issuer": user.issuer,
            "roles": user.roles,
        }
    )


@mcp.tool()
def api_call() -> str:
    user = current_user.get()

    pass