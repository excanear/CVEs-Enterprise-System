"""SQLAlchemy ORM models for the scan-orchestrator service.

Schema: scan_orchestrator (isolated from other BCs).
All tables use tenant_id + HASH partitioning and standard mixins from cves_db.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cves_db.base_model import Base, TenantMixin, TimestampMixin


class ScanModel(Base, TenantMixin, TimestampMixin):
    """Persists Scan aggregates."""

    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_tenant_status", "tenant_id", "status"),
        Index("ix_scans_correlation_id", "correlation_id"),
        {"schema": "scan_orchestrator"},
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    scan_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="NORMAL")
    initiated_by: Mapped[str] = mapped_column(String(256), nullable=False)
    correlation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    # Targets stored as JSONB array for fast query
    targets: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    config_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Progress counters
    tasks_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tasks_completed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tasks_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tasks_retrying: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Timing
    scheduled_at: Mapped[datetime | None] = mapped_column(nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)

    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    assigned_worker_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    tasks: Mapped[list["ScanTaskModel"]] = relationship(
        "ScanTaskModel", back_populates="scan", lazy="noload"
    )


class ScanTaskModel(Base, TenantMixin, TimestampMixin):
    """Persists individual ScanTask entities."""

    __tablename__ = "scan_tasks"
    __table_args__ = (
        Index("ix_scan_tasks_scan_id_status", "scan_id", "status"),
        Index("ix_scan_tasks_tenant_status", "tenant_id", "status"),
        Index("ix_scan_tasks_target", "target"),
        {"schema": "scan_orchestrator"},
    )

    task_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_orchestrator.scans.scan_id", ondelete="CASCADE"),
        nullable=False,
    )
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    task_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="QUEUED")
    priority_score: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    assigned_worker_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    dispatched_at: Mapped[datetime | None] = mapped_column(nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    next_retry_at: Mapped[datetime | None] = mapped_column(nullable=True)

    result: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)

    scan: Mapped["ScanModel"] = relationship("ScanModel", back_populates="tasks")
