"""SQLAlchemy ORM models for the reporting schema.

Tables:
  reporting.exposure_records   — denormalized exposure facts from ACL
  reporting.cluster_records    — cluster summaries from ACL
  reporting.remediation_records— remediation steps from ACL
  reporting.path_records       — ranked attack paths from ACL
  reporting.reports            — generated report metadata + content
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from cves_db.base_model import Base, TimestampMixin

_SCHEMA = "reporting"


class ExposureRecordModel(Base, TimestampMixin):
    """One row per ACL exposure.prioritized event received."""

    __tablename__ = "exposure_records"
    __table_args__ = {"schema": _SCHEMA}

    exposure_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(36), nullable=False)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    exposure_type: Mapped[str] = mapped_column(String(64), nullable=False)
    tier: Mapped[str] = mapped_column(String(20), nullable=False)
    composite_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )


class ClusterRecordModel(Base, TimestampMixin):
    """One row per ACL cluster.created event received."""

    __tablename__ = "cluster_records"
    __table_args__ = {"schema": _SCHEMA}

    cluster_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(36), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tier: Mapped[str] = mapped_column(String(20), nullable=False)
    host: Mapped[str | None] = mapped_column(String(512), nullable=True)
    avg_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    poc_triggered_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    exposure_types: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )


class RemediationRecordModel(Base, TimestampMixin):
    """One row per ACL remediation.generated event received."""

    __tablename__ = "remediation_records"
    __table_args__ = {"schema": _SCHEMA}

    cluster_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(36), nullable=False)
    exposure_type: Mapped[str] = mapped_column(String(64), nullable=False)
    steps: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    llm_enriched: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    llm_narrative: Mapped[str | None] = mapped_column(Text, nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )


class PathRecordModel(Base, TimestampMixin):
    """Attack paths received from ACL path.ranked events (latest per tenant)."""

    __tablename__ = "path_records"
    __table_args__ = {"schema": _SCHEMA}

    path_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(36), nullable=False)
    paths_json: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )


class ReportModel(Base, TimestampMixin):
    """Generated report metadata and rendered content."""

    __tablename__ = "reports"
    __table_args__ = {"schema": _SCHEMA}

    report_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)
    report_format: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_bytes: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
