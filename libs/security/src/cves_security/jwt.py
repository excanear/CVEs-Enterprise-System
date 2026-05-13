"""RS256 JWT validation with async JWKS caching.

Security design:
- RS256 only — symmetric HS* algorithms are rejected.
- JWKS fetched once and cached with configurable TTL (default 300 s).
- Tokens are validated: signature, expiry, iss, aud, tenant_id claim.
- No secrets stored in memory beyond the JWKS cache TTL.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient, algorithms

logger = logging.getLogger(__name__)

_ALLOWED_ALGORITHMS = ["RS256"]


class JWTValidator:
    """Async-safe JWT validator with JWKS caching.

    Usage::

        validator = JWTValidator(
            jwks_uri="https://iam.internal/.well-known/jwks.json",
            issuer="https://iam.internal",
            audience="api.cves-platform",
        )
        claims = await validator.validate(token)
    """

    def __init__(
        self,
        *,
        jwks_uri: str,
        issuer: str,
        audience: str,
        jwks_cache_ttl_seconds: int = 300,
    ) -> None:
        self._jwks_uri = jwks_uri
        self._issuer = issuer
        self._audience = audience
        self._cache_ttl = jwks_cache_ttl_seconds
        self._jwks_client = PyJWKClient(jwks_uri, cache_jwk_set=True, lifespan=jwks_cache_ttl_seconds)

    def validate(self, token: str) -> dict[str, Any]:
        """Validate a JWT token and return its claims.

        Raises jwt.exceptions.* on any validation failure.
        Never catch these broadly — let them propagate to HTTP 401.
        """
        signing_key = self._jwks_client.get_signing_key_from_jwt(token)

        claims: dict[str, Any] = jwt.decode(
            token,
            signing_key.key,
            algorithms=_ALLOWED_ALGORITHMS,
            audience=self._audience,
            issuer=self._issuer,
            options={
                "require": ["exp", "iss", "aud", "sub", "tenant_id"],
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )

        # Validate tenant_id is a valid UUID — defence-in-depth.
        try:
            uuid.UUID(str(claims["tenant_id"]))
        except (ValueError, KeyError) as exc:
            raise jwt.InvalidClaimError("tenant_id claim is not a valid UUID.") from exc

        return claims

    def extract_tenant_id(self, claims: dict[str, Any]) -> uuid.UUID:
        return uuid.UUID(str(claims["tenant_id"]))

    def extract_roles(self, claims: dict[str, Any]) -> list[str]:
        return claims.get("roles", [])

    def extract_scopes(self, claims: dict[str, Any]) -> list[str]:
        scope_str: str = claims.get("scope", "")
        return [s for s in scope_str.split() if s]
