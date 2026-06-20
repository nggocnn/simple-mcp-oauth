"""The MCP server instance and the tools it exposes.

Two tools are registered:

* ``whoami``   — echoes the caller's verified identity.
* ``api_call`` — calls the downstream API on the user's behalf, gated on a role.

The authenticated user is not passed as a tool argument; it is carried in a
:class:`contextvars.ContextVar` that the auth middleware (see ``server.py``)
sets for the duration of each request. ``current_user.get()`` returns it inside
a tool, or ``None`` if the request somehow reached a tool unauthenticated.
"""

from __future__ import annotations

import json
import httpx

from contextvars import ContextVar
from urllib.parse import quote_plus
from fastmcp import FastMCP

from .config import config
from .auth.providers import AuthenticatedUser
from .auth.downstream import resolve_downstream_credential

# Per-request identity, set by the auth middleware and read inside tools.
current_user: ContextVar[AuthenticatedUser | None] = ContextVar(
    "current_user", default=None
)

mcp = FastMCP(config.server_name)

# Realm role required to use the downstream-calling tool. In the demo, alice has
# it and bob does not — demonstrating per-user authorization at the tool level.
REQUIRED_DOWNSTREAM_ROLE = "downstream-reader"


@mcp.tool(description="whoami")
def whoami() -> str:
    """Return the caller's identity (subject, email, issuer, roles) as JSON."""
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
def api_call(query: str) -> str:
    """Call the downstream search API as the user, returning the raw result.

    Enforces the ``downstream-reader`` role, then exchanges the user's token for
    a downstream-audience token (see :func:`resolve_downstream_credential`) and
    forwards it. The response string reports the URL, the acting identity, and
    the downstream status/body so the flow is observable end-to-end.
    """
    user = current_user.get()

    if user is None:
        return "Forbidden: no authenticated user."

    # Tool-level authorization: a valid token is necessary but not sufficient.
    if REQUIRED_DOWNSTREAM_ROLE not in user.roles:
        return f"Forbidden: {user.email or user.subject} lacks the required '{REQUIRED_DOWNSTREAM_ROLE}' role."

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

    return f"Called {url}\nacting as: {cred.acting_as}\nstatus: {resp.status_code}\nbody: {resp.text}"
