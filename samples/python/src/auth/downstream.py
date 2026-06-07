from __future__ import annotations

import base64
import httpx

from dataclasses import dataclass

from ..config import config
from .providers import AuthenticatedUser, TokenError, token_endpoint


@dataclass
class DownstreamCredential:
    authorization_header: str
    acting_as: str


def _basic(token: str) -> str:
    encoded = base64.b64encode(f"{token}:".encode()).decode()
    return f"Basic {encoded}"


def _exchange(user: AuthenticatedUser) -> DownstreamCredential:
    endpoint = token_endpoint(user.issuer)
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "subject_token": user.raw_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": config.downstream_audience,
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
    }

    resp = httpx.post(endpoint, data=data, timeout=config.request_timeout)
    
    if resp.status_code != 200:
        return RuntimeError(f"Token exchange failed ({resp.status_code}): {resp.text}")

    access_token = resp.json()["access_token"]

    return DownstreamCredential(
        authorization_header=f"Bearer {access_token}", acting_as=user.email or user.subject
    )

def _static_pat() -> DownstreamCredential:
    if not config.downstream_pat:
        raise RuntimeError("Please check static PAT.")
    
    return DownstreamCredential(_basic(config.downstream_pat), "PAT")


def resolve_downstream_credential(user: AuthenticatedUser | None) -> DownstreamCredential:
    if config.auth_mode == "pat":
        return _static_pat

    if user is None:
        return RuntimeError("")
    
    if config.downstream_strategy == "token-exchange":
        return _exchange(user)
