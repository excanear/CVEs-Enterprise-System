"""ORM models for the Exposure Validation Engine.

Schema: exposure_validation
Tables: validation_jobs, validation_results
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cves_db.base_model import Base, TimestampMixin

_SCHEMA = "exposure_validation"


class ValidationJobModel(Base, TimestampMixin):
    __tablename__ = "validation_jobs"
    __table_args__ = {"schema": _SCHEMA}

    job_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    exposure_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    options: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    stats: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    result: Mapped["ValidationResultModel | None"] = relationship(
        "ValidationResultModel",
        back_populates="job",
        lazy="noload",
        foreign_keys="ValidationResultModel.job_id",
    )


class ValidationResultModel(Base, TimestampMixin):
    __tablename__ = "validation_results"
    __table_args__ = {"schema": _SCHEMA}

    result_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    job_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey(f"{_SCHEMA}.validation_jobs.job_id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    final_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    signal_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    correlation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stages_passed: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    reachability_probe: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    middleware_findings: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    parser_findings: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    poc_result: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    job: Mapped["ValidationJobModel"] = relationship(
        "ValidationJobModel",
        back_populates="result",
        foreign_keys=[job_id],
    )
