from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cves_db.base_model import Base, TimestampMixin

_SCHEMA = "runtime_analysis"


class AnalysisSessionModel(Base, TimestampMixin):
    __tablename__ = "analysis_sessions"
    __table_args__ = {"schema": _SCHEMA}

    session_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    options: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    result: Mapped["AnalysisResultModel | None"] = relationship(
        "AnalysisResultModel",
        back_populates="session",
        uselist=False,
        lazy="noload",
    )


class AnalysisResultModel(Base, TimestampMixin):
    __tablename__ = "analysis_results"
    __table_args__ = {"schema": _SCHEMA}

    result_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey(f"{_SCHEMA}.analysis_sessions.session_id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    intercepted_apis: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    websocket_endpoints: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    spa_routes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    framework_fingerprints: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    dom_snapshot: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    hydration_markers: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    session: Mapped["AnalysisSessionModel"] = relationship(
        "AnalysisSessionModel",
        back_populates="result",
    )
