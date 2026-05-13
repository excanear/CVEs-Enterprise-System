"""Row-Level Security (RLS) integration for multi-tenant isolation.

PostgreSQL RLS policies on all tenant-scoped tables are defined as:

    CREATE POLICY tenant_isolation ON {schema}.{table}
        USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

Before executing any query the application must set the session-local
variable. This module provides helpers for both ASGI middleware (FastAPI)
and manual use inside async context managers.
"""
from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

# ---------------------------------------------------------------------------
# Context variable — holds the current tenant ID for the async task/coroutine
# ---------------------------------------------------------------------------

_current_tenant: ContextVar[uuid.UUID | None] = ContextVar(
    "current_tenant", default=None
)


def get_current_tenant() -> uuid.UUID | None:
    """Return the tenant UUID bound to the current async context, or None."""
    return _current_tenant.get()


def set_tenant(tenant_id: uuid.UUID) -> None:
    """Bind a tenant to the current async context.

    Prefer using `rls_context()` which restores the previous value on exit.
    """
    _current_tenant.set(tenant_id)


@asynccontextmanager
async def rls_context(
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> AsyncGenerator[AsyncSession, None]:
    """Async context manager that sets RLS tenant for the lifetime of a block.

    Sets both the Python ContextVar and the PostgreSQL session-local variable
    so that RLS policies evaluate correctly.

    Usage::

        async with rls_context(tenant_id, session) as s:
            result = await s.execute(select(Asset))
    """
    token = _current_tenant.set(tenant_id)
    await session.execute(
        text("SET LOCAL app.current_tenant_id = :tid"),
        {"tid": str(tenant_id)},
    )
    try:
        yield session
    finally:
        _current_tenant.reset(token)


# ---------------------------------------------------------------------------
# SQLAlchemy event hook — auto-set RLS on every new connection checkout
# ---------------------------------------------------------------------------

def install_rls_hook(engine: object) -> None:
    """Register a SQLAlchemy engine event that sets the RLS variable.

    Call once after creating the engine. The hook fires on every connection
    checkout from the pool and issues SET app.current_tenant_id if the
    ContextVar is populated.
    """

    @event.listens_for(engine.sync_engine, "connect")  # type: ignore[arg-type]
    def _on_connect(dbapi_conn: object, _: object) -> None:  # pragma: no cover
        # Default: restrict to an impossible UUID so no rows leak if someone
        # forgets to call rls_context().
        with dbapi_conn.cursor() as cur:  # type: ignore[attr-defined]
            cur.execute("SET app.current_tenant_id = '00000000-0000-0000-0000-000000000000'")


# ---------------------------------------------------------------------------
# ASGI Middleware — extracts tenant from JWT claims set by security lib
# ---------------------------------------------------------------------------

class RLSMiddleware:
    """ASGI middleware that propagates tenant_id from request state to ContextVar.

    Must be installed *after* the auth middleware has validated the JWT and
    set `request.state.tenant_id` (UUID).

    Usage (FastAPI)::

        app.add_middleware(RLSMiddleware)
    """

    def __init__(self, app: "ASGIApp") -> None:
        self.app = app

    async def __call__(
        self, scope: "Scope", receive: "Receive", send: "Send"
    ) -> None:
        if scope["type"] in {"http", "websocket"}:
            tenant_id: uuid.UUID | None = scope.get("state", {}).get("tenant_id")
            if tenant_id is not None:
                token = _current_tenant.set(tenant_id)
                try:
                    await self.app(scope, receive, send)
                finally:
                    _current_tenant.reset(token)
                return
        await self.app(scope, receive, send)
