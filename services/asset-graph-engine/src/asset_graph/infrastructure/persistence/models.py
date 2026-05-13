"""SQLAlchemy ORM model for asset_graph schema.

Only tracks Kafka ingestion job metadata (provenance + audit).
The actual graph data lives in Neo4j — not in PostgreSQL.
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from cves_db.base_model import Base, TimestampMixin

_SCHEMA = "asset_graph"


class IngestionJobModel(Base, TimestampMixin):
    """Records every Kafka event processed by AGE for audit and replay tracking."""

    __tablename__ = "ingestion_jobs"
    __table_args__ = {"schema": _SCHEMA}

    job_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    topic: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="PROCESSED"
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload_summary: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
