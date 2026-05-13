"""SQLAlchemy ORM models for the Discovery Engine.

Schema: discovery_engine (isolated per-BC in PostgreSQL).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cves_db.base_model import Base, TenantMixin, TimestampMixin


class DiscoveryJobModel(Base, TenantMixin, TimestampMixin):
    __tablename__ = "discovery_jobs"
    __table_args__ = (
        Index("ix_discovery_jobs_tenant_status", "tenant_id", "status"),
        Index("ix_discovery_jobs_target_domain", "target_domain"),
        {"schema": "discovery_engine"},
    )

    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    target_domain: Mapped[str] = mapped_column(String(256), nullable=False)
    scope_domains: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    sources: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    initiated_by: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    assets_found: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    endpoints_found: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    assets: Mapped[list["DiscoveredAssetModel"]] = relationship(
        "DiscoveredAssetModel", back_populates="job", lazy="noload"
    )


class DiscoveredAssetModel(Base, TenantMixin, TimestampMixin):
    __tablename__ = "discovered_assets"
    __table_args__ = (
        Index("ix_discovered_assets_job_id", "job_id"),
        Index("ix_discovered_assets_tenant_type", "tenant_id", "asset_type"),
        Index("ix_discovered_assets_value", "value"),
        Index("ix_discovered_assets_status", "tenant_id", "status"),
        {"schema": "discovery_engine"},
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovery_engine.discovery_jobs.job_id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="NEW")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    parent_asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(nullable=False)
    # 'metadata' is a reserved word in some DBs — use column name alias
    asset_metadata: Mapped[dict] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    job: Mapped["DiscoveryJobModel"] = relationship("DiscoveryJobModel", back_populates="assets")
