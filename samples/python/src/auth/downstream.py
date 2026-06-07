from __future__ import annotations

import httpx

from dataclasses import dataclass

from ..config import config
from .providers import AuthenticatedUser, token_endpoint


@dataclass
class DownstreamCredential:
    authorization_header: str
    acting_as: str


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
        raise RuntimeError(f"Token exchange failed ({resp.status_code}): {resp.text}")

    access_token = resp.json()["access_token"]

    return DownstreamCredential(
        authorization_header=f"Bearer {access_token}", acting_as=user.email or user.subject
    )

def resolve_downstream_credential(user: AuthenticatedUser) -> DownstreamCredential:
    if config.downstream_strategy == "token-exchange":
        return _exchange(user)

    raise RuntimeError(f"Unknown downstream strategy: {config.downstream_strategy}")
