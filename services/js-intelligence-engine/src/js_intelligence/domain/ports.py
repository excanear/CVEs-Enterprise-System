from __future__ import annotations

from typing import Protocol, runtime_checkable

from cves_db.types import TenantId

from js_intelligence.domain.entities.js_analysis_job import JSAnalysisJob
from js_intelligence.domain.entities.js_intelligence_result import JSIntelligenceResult


@runtime_checkable
class JSAnalysisJobRepository(Protocol):
    async def save(self, job: JSAnalysisJob) -> None: ...
    async def get(self, job_id: str) -> JSAnalysisJob | None: ...
    async def list_by_tenant(
        self, tenant_id: TenantId, limit: int, offset: int
    ) -> list[JSAnalysisJob]: ...


@runtime_checkable
class JSIntelligenceResultRepository(Protocol):
    async def save(self, result: JSIntelligenceResult) -> None: ...
    async def get(self, result_id: str) -> JSIntelligenceResult | None: ...
    async def get_by_job(self, job_id: str) -> JSIntelligenceResult | None: ...


@runtime_checkable
class JSIntelligenceEventPublisher(Protocol):
    async def publish_result(
        self,
        job: JSAnalysisJob,
        result: JSIntelligenceResult,
    ) -> None: ...
