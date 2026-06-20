"""OIDC provider discovery and access-token verification.

This module is the trust boundary of the server: it turns an opaque bearer
string into a verified :class:`AuthenticatedUser`, or raises :class:`TokenError`.
Discovered providers (JWKS client + token endpoint) are cached per issuer so we
only hit the discovery document once.
"""

from __future__ import annotations

import httpx
import jwt

from jwt import PyJWKClient
from dataclasses import dataclass, field
from typing import Any

from ..config import config


class TokenError(Exception):
    """Raised when a token is missing, malformed, untrusted, or fails validation."""


@dataclass
class AuthenticatedUser:
    """The verified identity behind a request, derived from token claims."""

    subject: str
    issuer: str
    email: str | None = None
    scopes: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    raw_token: str = ""  # kept so it can be used as the subject of a token exchange
    claims: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Provider:
    """Cached per-issuer discovery result."""

    issuer: str
    jwks_client: PyJWKClient  # fetches/caches the signing keys for verification
    token_endpoint: str  # used later for token exchange


# issuer -> _Provider. Populated lazily by _discover() and reused thereafter.
_registry: dict[str, _Provider] = {}


def _discover(issuer: str) -> _Provider:
    """Fetch (and cache) the issuer's OIDC discovery document.

    Reads ``/.well-known/openid-configuration`` to learn the JWKS URI and token
    endpoint. Subsequent calls for the same issuer return the cached provider.
    """
    cached = _registry.get(issuer)
    if cached:
        return cached

    resp = httpx.get(
        f"{issuer}/.well-known/openid-configuration", timeout=config.request_timeout
    )
    resp.raise_for_status()

    doc = resp.json()

    provider = _Provider(
        issuer=issuer,
        jwks_client=PyJWKClient(doc["jwks_uri"]),
        token_endpoint=doc["token_endpoint"],
    )

    _registry[issuer] = provider

    return provider


def warm_providers() -> None:
    """Pre-discover all configured issuers at startup.

    Best-effort: failures (e.g. the issuer not being up yet) are swallowed so a
    transiently-unreachable provider doesn't crash boot — it will be retried on
    the first request that needs it.
    """
    for issuer in config.issuers:
        try:
            _discover(issuer)
        except Exception as e:
            pass


def token_endpoint(issuer: str) -> str:
    """Return the OAuth token endpoint for ``issuer`` (used by token exchange)."""
    return _discover(issuer).token_endpoint


def verify_access_token(token: str) -> str:
    """Validate a bearer token and return the :class:`AuthenticatedUser`.

    The checks, in order:

    1. Decode (without verifying) to read the ``iss`` claim.
    2. Reject any issuer not in the trusted list.
    3. Verify signature, issuer, and expiry against the issuer's JWKS.
    4. Verify the audience explicitly contains our resource id.

    Any failure raises :class:`TokenError`; the caller turns that into a 401.
    """

    # Step 1: peek at the unverified claims just to find the issuer. We do NOT
    # trust anything here — it only tells us which provider to verify against.
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        raise TokenError("Malformed token") from e

    # Step 2: the issuer must be one we explicitly trust.
    issuer = str(unverified.get("iss", "")).rstrip("/")
    if not issuer or issuer not in config.issuers:
        raise TokenError(f"Untrusted issuer: {issuer or '<none>'}")

    # Step 3: cryptographically verify the token with the issuer's signing key.
    # Audience is checked manually below (verify_aud=False) so we control the
    # error message and matching logic.
    provider = _discover(issuer)
    try:
        signing_key = provider.jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256", "ES256"],
            issuer=issuer,
            options={"verify_aud": False},
        )

    except Exception as e:
        raise TokenError(f"Signature/issuer/expiry verification failed: {e}")

    # Step 4: the token must be audience-bound to this resource server.
    if not config.audience_matches(claims.get("aud")):
        raise TokenError(
            f"Token audience {claims.get("aud")!r} does not include {config.resource}"
        )

    # Keycloak puts realm roles under realm_access.roles; scopes are a
    # space-delimited string in the standard "scope" claim.
    realm_roles = (claims.get("realm_access") or {}).get("roles", [])
    scope = claims.get("scope", "")

    return AuthenticatedUser(
        subject=str(claims.get("sub")),
        issuer=issuer,
        email=str(claims.get("email")),
        scopes=scope.split() if isinstance(scope, str) else [],
        roles=realm_roles,
        raw_token=token,
        claims=claims,
    )
