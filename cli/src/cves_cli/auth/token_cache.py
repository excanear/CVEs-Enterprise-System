"""JWT token cache with automatic refresh before expiry."""
from __future__ import annotations

import time
from typing import Any

import jwt

from cves_cli.auth.keyring import delete_secret, get_secret, set_secret

_REFRESH_BUFFER_SECONDS = 60  # refresh token 60s before expiry


def _decode_claims(token: str) -> dict[str, Any]:
    """Decode JWT without signature verification (just parse claims)."""
    return jwt.decode(token, options={"verify_signature": False}, algorithms=["RS256", "HS256"])


def get_cached_token(auth_name: str) -> str | None:
    """Return cached access token if still valid, else None."""
    token = get_secret(f"token:{auth_name}", env_var="CVES_TOKEN")
    if not token:
        return None
    try:
        claims = _decode_claims(token)
        exp = claims.get("exp", 0)
        if time.time() < (exp - _REFRESH_BUFFER_SECONDS):
            return token
    except Exception:
        pass
    return None


def store_token(auth_name: str, access_token: str, refresh_token: str | None = None) -> None:
    set_secret(f"token:{auth_name}", access_token)
    if refresh_token:
        set_secret(f"refresh:{auth_name}", refresh_token)


def get_refresh_token(auth_name: str) -> str | None:
    return get_secret(f"refresh:{auth_name}")


def clear_tokens(auth_name: str) -> None:
    delete_secret(f"token:{auth_name}")
    delete_secret(f"refresh:{auth_name}")


def get_token_claims(auth_name: str) -> dict[str, Any] | None:
    token = get_cached_token(auth_name) or get_secret(f"token:{auth_name}")
    if not token:
        return None
    try:
        return _decode_claims(token)
    except Exception:
        return None
