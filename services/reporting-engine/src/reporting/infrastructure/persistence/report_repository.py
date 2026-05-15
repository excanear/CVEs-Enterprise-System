"""PostgreSQL repository for Reporting Engine.

Implements both ReportRepository and EvidenceStore domain ports.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from reporting.domain.entities.report import Report, ReportFormat, ReportStatus, ReportType
from reporting.infrastructure.persistence.models import (
    ClusterRecordModel,
    ExposureRecordModel,
    PathRecordModel,
    RemediationRecordModel,
    ReportModel,
)

log = structlog.get_logger(__name__)


def _model_to_report(m: ReportModel) -> Report:
    return Report(
        report_id=m.report_id,
        tenant_id=m.tenant_id,
        report_type=ReportType(m.report_type),
        report_format=ReportFormat(m.report_format),
        status=ReportStatus(m.status),
        finding_count=m.finding_count,
        content=m.content,
        content_bytes=m.content_bytes,
        error=m.error,
        created_at=m.created_at if m.created_at else datetime.now(UTC),
        generated_at=m.generated_at,
    )


class PGReportingRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    # ── ReportRepository ──────────────────────────────────────────────────────

    async def save(self, report: Report) -> None:
        async with self._sf() as session:
            model = ReportModel(
                report_id=report.report_id,
                tenant_id=report.tenant_id,
                report_type=report.report_type.value,
                report_format=report.report_format.value,
                status=report.status.value,
                finding_count=report.finding_count,
                content=report.content,
                content_bytes=report.content_bytes,
                error=report.error,
                generated_at=report.generated_at,
            )
            session.add(model)
            await session.commit()

    async def update(self, report: Report) -> None:
        async with self._sf() as session:
            result = await session.get(ReportModel, report.report_id)
            if result is None:
                return
            result.status = report.status.value
            result.finding_count = report.finding_count
            result.content = report.content
            result.content_bytes = report.content_bytes
            result.error = report.error
            result.generated_at = report.generated_at
            await session.commit()

    async def get(self, report_id: str) -> Report | None:
        async with self._sf() as session:
            model = await session.get(ReportModel, report_id)
            if model is None:
                return None
            return _model_to_report(model)

    async def list_by_tenant(
        self, tenant_id: str, limit: int = 50, offset: int = 0
    ) -> list[Report]:
        async with self._sf() as session:
            stmt = (
                select(ReportModel)
                .where(ReportModel.tenant_id == tenant_id)
                .order_by(ReportModel.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [_model_to_report(r) for r in rows]

    # ── EvidenceStore ─────────────────────────────────────────────────────────

    async def upsert_exposure(self, record: dict) -> None:
        async with self._sf() as session:
            stmt = (
                insert(ExposureRecordModel)
                .values(**record)
                .on_conflict_do_update(
                    index_elements=["exposure_id"],
                    set_={k: v for k, v in record.items() if k != "exposure_id"},
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def upsert_cluster(self, record: dict) -> None:
        async with self._sf() as session:
            stmt = (
                insert(ClusterRecordModel)
                .values(**record)
                .on_conflict_do_update(
                    index_elements=["cluster_id"],
                    set_={k: v for k, v in record.items() if k != "cluster_id"},
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def upsert_remediation(self, record: dict) -> None:
        async with self._sf() as session:
            stmt = (
                insert(RemediationRecordModel)
                .values(**record)
                .on_conflict_do_update(
                    index_elements=["cluster_id"],
                    set_={k: v for k, v in record.items() if k != "cluster_id"},
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def upsert_path(self, record: dict) -> None:
        async with self._sf() as session:
            stmt = (
                insert(PathRecordModel)
                .values(**record)
                .on_conflict_do_update(
                    index_elements=["path_id"],
                    set_={k: v for k, v in record.items() if k != "path_id"},
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def list_exposures(self, tenant_id: str) -> list[dict]:
        async with self._sf() as session:
            stmt = select(ExposureRecordModel).where(
                ExposureRecordModel.tenant_id == tenant_id
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [
                {
                    "exposure_id": r.exposure_id,
                    "target_url": r.target_url,
                    "exposure_type": r.exposure_type,
                    "tier": r.tier,
                    "composite_score": r.composite_score,
                    "rationale": r.rationale,
                    "session_id": r.session_id,
                    "recorded_at": r.recorded_at.isoformat() if r.recorded_at else None,
                }
                for r in rows
            ]

    async def list_clusters(self, tenant_id: str) -> list[dict]:
        async with self._sf() as session:
            stmt = select(ClusterRecordModel).where(
                ClusterRecordModel.tenant_id == tenant_id
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [
                {
                    "cluster_id": r.cluster_id,
                    "size": r.size,
                    "tier": r.tier,
                    "host": r.host,
                    "avg_confidence": r.avg_confidence,
                    "poc_triggered_count": r.poc_triggered_count,
                    "exposure_types": r.exposure_types,
                    "session_id": r.session_id,
                    "recorded_at": r.recorded_at.isoformat() if r.recorded_at else None,
                }
                for r in rows
            ]

    async def list_remediations(self, tenant_id: str) -> list[dict]:
        async with self._sf() as session:
            stmt = select(RemediationRecordModel).where(
                RemediationRecordModel.tenant_id == tenant_id
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [
                {
                    "cluster_id": r.cluster_id,
                    "exposure_type": r.exposure_type,
                    "steps": r.steps,
                    "llm_enriched": r.llm_enriched,
                    "llm_narrative": r.llm_narrative,
                    "session_id": r.session_id,
                    "recorded_at": r.recorded_at.isoformat() if r.recorded_at else None,
                }
                for r in rows
            ]

    async def list_paths(self, tenant_id: str, limit: int = 10) -> list[dict]:
        async with self._sf() as session:
            stmt = (
                select(PathRecordModel)
                .where(PathRecordModel.tenant_id == tenant_id)
                .order_by(PathRecordModel.recorded_at.desc())
                .limit(limit)
            )
            rows = (await session.execute(stmt)).scalars().all()
            paths: list[dict] = []
            for r in rows:
                paths.extend(r.paths_json if isinstance(r.paths_json, list) else [])
            return paths
