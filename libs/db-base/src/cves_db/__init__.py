"""cves_db — Shared database base library."""

from .session import AsyncSessionFactory, get_async_session
from .base_model import Base, TenantMixin, TimestampMixin, VersionedMixin
from .outbox import OutboxEntry, OutboxMixin
from .rls import RLSMiddleware, rls_context, set_tenant
from .pagination import CursorPage, CursorPagination, SortDirection
from .types import UUIDv7, TenantId

__all__ = [
    "AsyncSessionFactory",
    "get_async_session",
    "Base",
    "TenantMixin",
    "TimestampMixin",
    "VersionedMixin",
    "OutboxEntry",
    "OutboxMixin",
    "RLSMiddleware",
    "rls_context",
    "set_tenant",
    "CursorPage",
    "CursorPagination",
    "SortDirection",
    "UUIDv7",
    "TenantId",
]
