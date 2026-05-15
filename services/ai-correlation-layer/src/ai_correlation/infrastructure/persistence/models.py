"""SQLAlchemy ORM models for ai_correlation schema.

Tracks correlation sessions and cluster metadata.
Evidence items and detailed results are kept in Redis (ephemeral).
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from cves_db.base_model import Base, TimestampMixin

_SCHEMA = "ai_correlation"


class CorrelationSessionModel(Base, TimestampMixin):
    """One correlation run per tenant — tracks lifecycle and statistics."""

    __tablename__ = "correlation_sessions"
    __table_args__ = {"schema": _SCHEMA}

    session_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    path_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cluster_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    prioritized_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class EvidenceClusterModel(Base, TimestampMixin):
    """Persisted cluster record — summary only, items in Redis."""

    __tablename__ = "evidence_clusters"
    __table_args__ = {"schema": _SCHEMA}

    cluster_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    tier: Mapped[str] = mapped_column(String(20), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    host: Mapped[str | None] = mapped_column(String(512), nullable=True)
    exposure_types: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    avg_confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    poc_triggered_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
