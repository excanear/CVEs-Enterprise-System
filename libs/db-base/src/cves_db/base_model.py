"""SQLAlchemy declarative base with shared mixins.

All models must inherit from `Base`. Multi-tenant models must also
inherit from `TenantMixin`. Tables with optimistic concurrency control
inherit from `VersionedMixin`.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, MappedColumn, mapped_column


class Base(DeclarativeBase):
    """Project-wide declarative base.

    All ORM models inherit from this class. Using a single shared Base
    ensures Alembic autogenerate sees the complete metadata graph.
    """


# ---------------------------------------------------------------------------
# Mixins
# ---------------------------------------------------------------------------

class TimestampMixin:
    """Adds created_at / updated_at columns managed by the DB server clock."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="Wall-clock time the row was first inserted (UTC, immutable).",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        doc="Wall-clock time the row was last modified (UTC).",
    )


class TenantMixin:
    """Adds tenant_id column with index.

    All multi-tenant tables must include this mixin so that Row-Level
    Security policies can filter by current_setting('app.current_tenant_id').
    """

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        doc="Owning tenant. Immutable after row creation.",
    )


class VersionedMixin:
    """Optimistic concurrency control via a monotonically increasing version.

    Services must include `WHERE version = :expected_version` on UPDATE
    statements and raise `OptimisticLockError` when the rowcount is 0.
    """

    version: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        doc="Monotonically increasing version for optimistic locking.",
    )


class SoftDeleteMixin:
    """Logical deletion via deleted_at timestamp.

    Repositories must filter `WHERE deleted_at IS NULL` in all reads unless
    explicitly querying deleted records.
    """

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        doc="Set when the row is logically deleted; NULL means active.",
    )

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None

    def soft_delete(self) -> None:
        self.deleted_at = datetime.now(tz=timezone.utc)


class AuditMixin(TimestampMixin):
    """Adds created_by / updated_by alongside timestamps."""

    created_by: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
        doc="Identity (user_id or service name) that created the row.",
    )
    updated_by: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
        doc="Identity that last updated the row.",
    )
