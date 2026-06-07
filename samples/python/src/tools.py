from __future__ import annotations

import json
import httpx

from contextvars import ContextVar
from urllib.parse import urlparse
from fastmcp import FastMCP

from .config import config
from .auth.providers import AuthenticatedUser
from .auth.downstream import resolve_downstream_credential

current_user: ContextVar[AuthenticatedUser | None] = ContextVar(
    "current_user", default=None
)

mcp = FastMCP(config.server_name)

REQUIRED_DOWNSTREAM_ROLE = "downstream-reader"


@mcp.tool(description="whoami")
def whoami() -> str:
    user = current_user.get()

    if user is None:
        return json.dumps({"error": "No authenticated user."})

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

    if user is None:
        return "Forbidden: no authenticated user."

    if REQUIRED_DOWNSTREAM_ROLE not in user.roles:
        return f"Forbidden: '{user.email or user.subject} lacks the required '{REQUIRED_DOWNSTREAM_ROLE}' role."

    url = f"{config.downstream_base_url}/api/search?q={quote_plus(query)}"
    try:
        cred = resolve_downstream_credential(user)
        resp = httpx.get(
            url,
            headers={"Authorization": cred.authorization_header},
            timeout=config.request_timeout,
        )
    except Exception as e:
        return f"Downstream call failed: {e}"

    return f"Called {url}\nacting as: {cred.acting_as}\nstatus: {resp.status}\nbody: {resp.text}"
