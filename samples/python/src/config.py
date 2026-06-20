"""Runtime configuration, read once from environment variables at import time.

Every knob the server needs is collected here so the rest of the code can import
a single ``config`` object instead of reaching into ``os.environ`` directly. The
defaults are chosen for the bundled Keycloak demo (see ``samples/keycloak``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _issuers() -> list[str]:
    """Parse the trusted OIDC issuer list from the environment.

    Accepts either ``OIDC_ISSUERS`` (comma-separated, for multi-issuer setups)
    or ``OIDC_ISSUER`` (single value). Trailing slashes are stripped so issuer
    comparisons elsewhere can be exact string matches.
    """
    raw = os.environ.get("OIDC_ISSUERS") or os.environ.get("OIDC_ISSUER")
    return [s.strip().rstrip("/") for s in raw.split(",") if s.strip()]


@dataclass
class Config:
    """Immutable view of the server's configuration.

    Field defaults are evaluated from the environment when this module is first
    imported. Required variables (``PUBLIC_URL``, ``RESOURCE``) intentionally
    raise ``AttributeError`` if unset, failing fast at startup rather than
    serving misconfigured.
    """

    # Human-readable name advertised to MCP clients.
    server_name: str = os.environ.get("SERVER_NAME", "Simple MCP OAuth")
    # Externally reachable base URL; used to build absolute metadata URLs.
    public_url: str = os.environ.get("PUBLIC_URL").rstrip("/")
    # This server's resource identifier — the value clients must put in the
    # token's ``aud`` claim (RFC 8707). For the demo this is the /mcp URL.
    resource: str = os.environ.get("RESOURCE")
    port: int = int(os.environ.get("PORT", "3000"))

    # Authorization servers we trust to mint access tokens.
    issuers: list[str] = field(default_factory=_issuers)

    # Scopes advertised in Protected Resource Metadata (informational).
    supported_scopes: list[str] = field(
        default_factory=lambda: os.environ.get(
            "SUPPORTED_SCOPES", "openid profile email"
        ).split()
    )

    # Scopes a token must carry (any one of them) to reach the MCP endpoint.
    # Defaults to the supported set when not explicitly configured.
    required_scopes: list[str] = field(
        default_factory=lambda: (
            os.environ.get("REQUIRED_SCOPES") or
            os.environ.get("SUPPORTED_SCOPES", "openid profile email")
        ).split()
    )

    # Confidential client credentials used to perform token exchange.
    client_id: str = os.environ.get("CLIENT_ID")
    client_secret: str = os.environ.get("CLIENT_SECRET")

    # How to obtain a credential for the downstream API ("token-exchange").
    downstream_strategy: str = os.environ.get("DOWNSTREAM_STRATEGY", "token-exchange")
    # Audience requested for the exchanged downstream token.
    downstream_audience: str = os.environ.get("DOWNSTREAM_AUDIENCE", "downstream-api")
    # Base URL of the downstream API the ``api_call`` tool talks to.
    downstream_base_url: str = os.environ.get("DOWNSTREAM_BASE_URL")

    # Timeout (seconds) for all outbound HTTP calls.
    request_timeout: int = int(os.environ.get("REQUEST_TIMEOUT", "20"))

    def audience_matches(self, aud) -> bool:
        """Return True if ``aud`` (string or list) contains our resource id.

        Tokens are accepted only when explicitly audience-bound to this server,
        which is what stops a token minted for some other resource in the same
        realm from being replayed here (the "confused deputy" guard).
        """
        if aud is None:
            return False

        values = aud if isinstance(aud, list) else [aud]

        return self.resource in values


# Module-level singleton imported throughout the app.
config = Config()
