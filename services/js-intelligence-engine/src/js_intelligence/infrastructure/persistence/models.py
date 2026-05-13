from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cves_db.base_model import Base, TimestampMixin

_SCHEMA = "js_intelligence"


class JSAnalysisJobModel(Base, TimestampMixin):
    __tablename__ = "js_analysis_jobs"
    __table_args__ = {"schema": _SCHEMA}

    job_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    options: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    stats: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    result: Mapped["JSIntelligenceResultModel | None"] = relationship(
        "JSIntelligenceResultModel",
        back_populates="job",
        uselist=False,
        lazy="noload",
    )


class JSIntelligenceResultModel(Base, TimestampMixin):
    __tablename__ = "js_intelligence_results"
    __table_args__ = {"schema": _SCHEMA}

    result_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    job_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey(f"{_SCHEMA}.js_analysis_jobs.job_id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    bundles: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    source_map_entries: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    hidden_routes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    dependency_graph: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    bundler_signature: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    job: Mapped["JSAnalysisJobModel"] = relationship(
        "JSAnalysisJobModel",
        back_populates="result",
    )
