"""PostgreSQL repositories for Exposure Validation Engine."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cves_db.types import TenantId
from cves_event_schemas.eve.eve_events import ExposureType, ValidationVerdict

from exposure_validation.domain.entities.validation_job import (
    JobStatus,
    ValidationJob,
)
from exposure_validation.domain.entities.validation_result import ValidationResult
from exposure_validation.domain.value_objects.middleware_findings import MiddlewareFindings
from exposure_validation.domain.value_objects.parser_findings import ParserFindings
from exposure_validation.domain.value_objects.poc_result import PoCResult
from exposure_validation.domain.value_objects.reachability_probe import ReachabilityProbeResult
from exposure_validation.infrastructure.persistence.models import (
    ValidationJobModel,
    ValidationResultModel,
)


def _job_to_domain(m: ValidationJobModel) -> ValidationJob:
    return ValidationJob(
        job_id=m.job_id,
        tenant_id=m.tenant_id,
        target_url=m.target_url,
        correlation_id=m.correlation_id,
        exposure_type=ExposureType(m.exposure_type),
        options=m.options or {},
        status=JobStatus(m.status),
        result_id=m.result_id,
        failure_reason=m.failure_reason,
        stats=m.stats or {},
        created_at=m.created_at.replace(tzinfo=UTC) if m.created_at else datetime.now(UTC),
        started_at=m.started_at.replace(tzinfo=UTC) if m.started_at else None,
        finished_at=m.finished_at.replace(tzinfo=UTC) if m.finished_at else None,
    )


def _result_to_domain(m: ValidationResultModel) -> ValidationResult:
    rp_data = m.reachability_probe or {}
    mf_data = m.middleware_findings or {}
    pf_data = m.parser_findings or {}
    poc_data = m.poc_result or {}

    return ValidationResult(
        result_id=m.result_id,
        job_id=m.job_id,
        verdict=ValidationVerdict(m.verdict),
        final_confidence=m.final_confidence,
        reachability_probe=ReachabilityProbeResult(**rp_data),
        middleware_findings=MiddlewareFindings(**mf_data),
        parser_findings=ParserFindings(**pf_data),
        poc_result=PoCResult(**poc_data),
        signal_count=m.signal_count,
        correlation_count=m.correlation_count,
        stages_passed=tuple(m.stages_passed or []),
        created_at=m.created_at.replace(tzinfo=UTC) if m.created_at else datetime.now(UTC),
    )


class PostgresValidationJobRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = session_factory

    async def save(self, job: ValidationJob) -> None:
        async with self._factory() as db:
            async with db.begin():
                existing = await db.get(ValidationJobModel, job.job_id)
                if existing is None:
                    db.add(ValidationJobModel(
                        job_id=job.job_id,
                        tenant_id=job.tenant_id,
                        target_url=job.target_url,
                        correlation_id=job.correlation_id,
                        exposure_type=job.exposure_type.value,
                        status=job.status.value,
                        failure_reason=job.failure_reason,
                        result_id=job.result_id,
                        options=job.options,
                        stats=job.stats,
                        started_at=job.started_at,
                        finished_at=job.finished_at,
                    ))
                else:
                    existing.status = job.status.value
                    existing.failure_reason = job.failure_reason
                    existing.result_id = job.result_id
                    existing.stats = job.stats
                    existing.started_at = job.started_at
                    existing.finished_at = job.finished_at

    async def get(self, job_id: str) -> ValidationJob | None:
        async with self._factory() as db:
            m = await db.get(ValidationJobModel, job_id)
            return _job_to_domain(m) if m else None

    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ValidationJob]:
        async with self._factory() as db:
            rows = await db.execute(
                select(ValidationJobModel)
                .where(ValidationJobModel.tenant_id == str(tenant_id))
                .order_by(ValidationJobModel.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return [_job_to_domain(r) for r in rows.scalars().all()]


class PostgresValidationResultRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = session_factory

    async def save(self, result: ValidationResult) -> None:
        async with self._factory() as db:
            async with db.begin():
                db.add(ValidationResultModel(
                    result_id=result.result_id,
                    job_id=result.job_id,
                    verdict=result.verdict.value,
                    final_confidence=result.final_confidence,
                    signal_count=result.signal_count,
                    correlation_count=result.correlation_count,
                    stages_passed=list(result.stages_passed),
                    reachability_probe=result.reachability_probe.model_dump(),
                    middleware_findings=result.middleware_findings.model_dump(),
                    parser_findings=result.parser_findings.model_dump(),
                    poc_result=result.poc_result.model_dump(),
                ))

    async def get(self, result_id: str) -> ValidationResult | None:
        async with self._factory() as db:
            m = await db.get(ValidationResultModel, result_id)
            return _result_to_domain(m) if m else None

    async def get_by_job(self, job_id: str) -> ValidationResult | None:
        async with self._factory() as db:
            row = await db.execute(
                select(ValidationResultModel)
                .where(ValidationResultModel.job_id == job_id)
            )
            m = row.scalar_one_or_none()
            return _result_to_domain(m) if m else None
