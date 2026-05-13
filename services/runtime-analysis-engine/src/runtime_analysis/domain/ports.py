from __future__ import annotations

from typing import Protocol

from cves_db.types import TenantId

from runtime_analysis.domain.entities.analysis_result import AnalysisResult
from runtime_analysis.domain.entities.analysis_session import AnalysisSession


class AnalysisSessionRepository(Protocol):
    async def save(self, session: AnalysisSession) -> None: ...
    async def get(self, session_id: str) -> AnalysisSession | None: ...
    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AnalysisSession]: ...


class AnalysisResultRepository(Protocol):
    async def save(self, result: AnalysisResult) -> None: ...
    async def get(self, result_id: str) -> AnalysisResult | None: ...
    async def get_by_session(self, session_id: str) -> AnalysisResult | None: ...


class RuntimeEventPublisher(Protocol):
    async def publish_result(
        self,
        session: AnalysisSession,
        result: AnalysisResult,
    ) -> None: ...
