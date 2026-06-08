from __future__ import annotations

import os
from dataclasses import dataclass, field


def _issuers() -> list[str]:
    raw = os.environ.get("OIDC_ISSUERS") or os.environ.get("OIDC_ISSUER")
    return [s.strip().rstrip("/") for s in raw.split(",") if s.strip()]


@dataclass
class Config:
    server_name: str = os.environ.get("SERVER_NAME", "Simple MCP OAuth")
    public_url: str = os.environ.get("PUBLIC_URL").rstrip("/")
    resource: str = os.environ.get("RESOURCE")
    port: int = int(os.environ.get("PORT", "3000"))

    issuers: list[str] = field(default_factory=_issuers)

    supported_scopes: list[str] = field(
        default_factory=lambda: os.environ.get(
            "SUPPORTED_SCOPES", "openid profile email"
        ).split()
    )

    required_scopes: list[str] = field(
        default_factory=lambda: (
            os.environ.get("REQUIRED_SCOPES") or
            os.environ.get("SUPPORTED_SCOPES", "openid profile email")
        ).split()
    )

    client_id: str = os.environ.get("CLIENT_ID")
    client_secret: str = os.environ.get("CLIENT_SECRET")

    downstream_strategy: str = os.environ.get("DOWNSTREAM_STRATEGY", "token-exchange")
    downstream_audience: str = os.environ.get("DOWNSTREAM_AUDIENCE", "downstream-api")
    downstream_base_url: str = os.environ.get("DOWNSTREAM_BASE_URL")

    request_timeout: int = int(os.environ.get("REQUEST_TIMEOUT", "20"))

    def audience_matches(self, aud) -> bool:
        if aud is None:
            return False

        values = aud if isinstance(aud, list) else [aud]

        return self.resource in values


config = Config()
