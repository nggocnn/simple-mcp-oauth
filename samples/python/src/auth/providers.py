from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient

from ..config import config


class TokenError(Exception):
    """Raised when a token is missing, malformed, untrusted, or fails validation."""


@dataclass
class AuthenticatedUser:
    subject: str
    issuer: str
    email: str | None = None
    scopes: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    raw_tokens: str = ""
    claims: dict[str, Any] = field(default_factory=dict)

@dataclass
class _Provider:
    issuer: str
    jwks_client: PyJWKClient
    token_endpoint: str


_registry: dict[str, _Provider] = {}


def _discover(issuer: str) -> _Provider:
    cached = _registry.get(issuer)
    if cached:
        return cached

    resp = httpx.get(f"{issuer}/.well-known/openid-configuration", timeout=10)
    resp.raise_for_status()

    doc = resp.json()

    provider = _Provider(
        issuer=issuer,
        jwks_client=PyJWKClient(doc["jwks_uri"]),
        token_endpoint=doc["token_endpoint"]
    )

    _registry[issuer] = provider

    return provider

def warm_providers() -> None:
    pass

def token_endpoint(issuer: str) -> str:
    return _discover(issuer).token_endpoint

def verify_access_token(token: str) -> str:

    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        raise TokenError("Malformed token") from e
    
    issuer = str(unverified.get("iss", "")).rstrip("/")
    if not issuer or issuer not in config.issuers:
        raise TokenError(f"Untrusted issuer: {issuer or '<none>'}")
    
    provider = _discover(issuer)
    try:
        signing_key = provider.jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256", "ES256"],
            issuer=issuer,
            options={"verify_aud": False}
        )

    except Exception as e:
        raise TokenError(f"Signature/issuer/expiry verification failed: {e}")
    
    if not config.audience_matches(claims.get("aud")):
        raise TokenError(f"Token audience {claims.get("aud")!r} does not include {config.resource}")
    
    realm_roles = (claims.get("realm_access") or {}).get("roles", [])
    scope = claims.get("scope", "")

    return AuthenticatedUser(
        subject=str(claims.get("sub")),
        issuer=issuer,
        email=str(claims.get("email")),
        scopes=scope.split() if isinstance(scope, str) else [],
        roles=realm_roles,
        raw_tokens=token,
        claims=claims
    )
