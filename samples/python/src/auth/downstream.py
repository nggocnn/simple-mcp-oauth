"""Obtaining a credential to call the downstream API as the current user.

The MCP server is a confidential OAuth client. Rather than forwarding the user's
own token (which is audience-bound to *this* server), it performs an RFC 8693
token exchange to get a fresh token whose audience is the downstream API, while
preserving the user's identity. This keeps each token scoped to exactly one
audience.
"""

from __future__ import annotations

import httpx

from dataclasses import dataclass

from ..config import config
from .providers import AuthenticatedUser, token_endpoint


@dataclass
class DownstreamCredential:
    """A ready-to-use Authorization header plus who the call acts as."""

    authorization_header: str
    acting_as: str


def _exchange(user: AuthenticatedUser) -> DownstreamCredential:
    """Exchange the user's access token for a downstream-audience token (RFC 8693).

    Sends a token-exchange grant to the issuer's token endpoint using this
    server's confidential client credentials, with the user's token as the
    subject. The returned token is audience-bound to ``downstream_audience``.
    """
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
        authorization_header=f"Bearer {access_token}",
        acting_as=user.email or user.subject,
    )


def resolve_downstream_credential(user: AuthenticatedUser) -> DownstreamCredential:
    """Return a downstream credential for ``user`` per the configured strategy.

    Only ``token-exchange`` is implemented; the indirection leaves room for
    other strategies (e.g. a static service token) without touching callers.
    """
    if config.downstream_strategy == "token-exchange":
        return _exchange(user)

    raise RuntimeError(f"Unknown downstream strategy: {config.downstream_strategy}")
