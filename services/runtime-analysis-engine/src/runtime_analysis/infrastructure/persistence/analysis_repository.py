from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cves_db.types import TenantId

from runtime_analysis.domain.entities.analysis_result import AnalysisResult
from runtime_analysis.domain.entities.analysis_session import (
    AnalysisSession,
    SessionStatus,
)
from runtime_analysis.domain.value_objects.dom_snapshot import DOMSnapshot
from runtime_analysis.domain.value_objects.framework_fingerprint import (
    FrameworkFingerprint,
)
from runtime_analysis.domain.value_objects.intercepted_api import InterceptedAPI
from runtime_analysis.domain.value_objects.spa_route import SPARoute
from runtime_analysis.domain.value_objects.websocket_endpoint import WebSocketEndpoint
from runtime_analysis.infrastructure.persistence.models import (
    AnalysisResultModel,
    AnalysisSessionModel,
)


# ──────────────────────────────────────────────────────────────────────────────
# Mappers
# ──────────────────────────────────────────────────────────────────────────────


def _session_to_domain(m: AnalysisSessionModel) -> AnalysisSession:
    s = AnalysisSession(
        session_id=m.session_id,
        tenant_id=m.tenant_id,  # type: ignore[arg-type]
        target_url=m.target_url,
        correlation_id=m.correlation_id,
        status=SessionStatus(m.status),
        failure_reason=m.failure_reason,
        result_id=m.result_id,
        options=m.options or {},
        created_at=m.created_at.replace(tzinfo=UTC) if m.created_at else datetime.now(UTC),
        started_at=m.started_at.replace(tzinfo=UTC) if m.started_at else None,
        finished_at=m.finished_at.replace(tzinfo=UTC) if m.finished_at else None,
    )
    return s


def _result_to_domain(m: AnalysisResultModel) -> AnalysisResult:
    return AnalysisResult(
        result_id=m.result_id,
        session_id=m.session_id,
        intercepted_apis=tuple(
            InterceptedAPI(**a) for a in (m.intercepted_apis or [])
        ),
        websocket_endpoints=tuple(
            WebSocketEndpoint(**w) for w in (m.websocket_endpoints or [])
        ),
        spa_routes=tuple(SPARoute(**r) for r in (m.spa_routes or [])),
        framework_fingerprints=tuple(
            FrameworkFingerprint(**f) for f in (m.framework_fingerprints or [])
        ),
        dom_snapshot=DOMSnapshot(**m.dom_snapshot) if m.dom_snapshot else None,
        hydration_markers=m.hydration_markers or {},
        created_at=m.created_at.replace(tzinfo=UTC) if m.created_at else datetime.now(UTC),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Repositories
# ──────────────────────────────────────────────────────────────────────────────


class PostgresAnalysisSessionRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = session_factory

    async def save(self, session: AnalysisSession) -> None:
        async with self._factory() as db:
            async with db.begin():
                existing = await db.get(AnalysisSessionModel, session.session_id)
                if existing is None:
                    db.add(
                        AnalysisSessionModel(
                            session_id=session.session_id,
                            tenant_id=str(session.tenant_id),
                            target_url=session.target_url,
                            correlation_id=session.correlation_id,
                            status=session.status.value,
                            failure_reason=session.failure_reason,
                            result_id=session.result_id,
                            options=session.options,
                            started_at=session.started_at,
                            finished_at=session.finished_at,
                        )
                    )
                else:
                    existing.status = session.status.value
                    existing.failure_reason = session.failure_reason
                    existing.result_id = session.result_id
                    existing.started_at = session.started_at
                    existing.finished_at = session.finished_at

    async def get(self, session_id: str) -> AnalysisSession | None:
        async with self._factory() as db:
            m = await db.get(AnalysisSessionModel, session_id)
            return _session_to_domain(m) if m else None

    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AnalysisSession]:
        async with self._factory() as db:
            result = await db.execute(
                select(AnalysisSessionModel)
                .where(AnalysisSessionModel.tenant_id == str(tenant_id))
                .order_by(AnalysisSessionModel.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return [_session_to_domain(m) for m in result.scalars()]


class PostgresAnalysisResultRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = session_factory

    async def save(self, result: AnalysisResult) -> None:
        async with self._factory() as db:
            async with db.begin():
                existing = await db.get(AnalysisResultModel, result.result_id)
                if existing is None:
                    db.add(
                        AnalysisResultModel(
                            result_id=result.result_id,
                            session_id=result.session_id,
                            intercepted_apis=[a.model_dump() for a in result.intercepted_apis],
                            websocket_endpoints=[
                                w.model_dump() for w in result.websocket_endpoints
                            ],
                            spa_routes=[r.model_dump() for r in result.spa_routes],
                            framework_fingerprints=[
                                f.model_dump() for f in result.framework_fingerprints
                            ],
                            dom_snapshot=result.dom_snapshot.model_dump()
                            if result.dom_snapshot
                            else None,
                            hydration_markers=result.hydration_markers,
                        )
                    )

    async def get(self, result_id: str) -> AnalysisResult | None:
        async with self._factory() as db:
            m = await db.get(AnalysisResultModel, result_id)
            return _result_to_domain(m) if m else None

    async def get_by_session(self, session_id: str) -> AnalysisResult | None:
        async with self._factory() as db:
            result = await db.execute(
                select(AnalysisResultModel).where(
                    AnalysisResultModel.session_id == session_id
                )
            )
            m = result.scalar_one_or_none()
            return _result_to_domain(m) if m else None
