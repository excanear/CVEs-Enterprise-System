"""Tenant context propagation — JWT claims → RLS ContextVar.

This module is the single bridge between the authentication layer (JWT/API key)
and the database layer (PostgreSQL RLS via cves_db.rls.set_tenant).

Call establish_tenant_context() at the top of every authenticated request
handler. It will:
  1. Extract tenant_id from JWT claims or APIKeyRecord.
  2. Set the cves_db RLS ContextVar.
  3. Bind tenant_id to structlog context vars.
"""
from __future__ import annotations

import uuid
from typing import Any

from cves_db.rls import set_tenant


async def establish_tenant_context(
    tenant_id: uuid.UUID,
    *,
    correlation_id: uuid.UUID | None = None,
) -> None:
    """Set the tenant_id in all downstream context propagation layers.

    Parameters
    ----------
    tenant_id:
        UUID of the authenticated tenant.
    correlation_id:
        Optional correlation ID to bind for structured logging.
    """
    set_tenant(tenant_id)

    try:
        import structlog

        structlog.contextvars.bind_contextvars(tenant_id=str(tenant_id))
        if correlation_id:
            structlog.contextvars.bind_contextvars(correlation_id=str(correlation_id))
    except ImportError:
        pass


async def clear_tenant_context() -> None:
    """Clear tenant context at the end of a request lifecycle."""
    set_tenant(None)
    try:
        import structlog

        structlog.contextvars.clear_contextvars()
    except ImportError:
        pass


def get_tenant_id_from_claims(claims: dict[str, Any]) -> uuid.UUID:
    """Extract and validate tenant_id from JWT claims dict."""
    raw = claims.get("tenant_id")
    if not raw:
        raise ValueError("JWT claims missing tenant_id.")
    try:
        return uuid.UUID(str(raw))
    except ValueError as exc:
        raise ValueError(f"Invalid tenant_id UUID in JWT: {raw}") from exc
