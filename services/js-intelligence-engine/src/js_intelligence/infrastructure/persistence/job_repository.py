from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cves_db.types import TenantId

from js_intelligence.domain.entities.js_analysis_job import JSAnalysisJob, JobStatus
from js_intelligence.domain.entities.js_intelligence_result import JSIntelligenceResult
from js_intelligence.domain.value_objects.bundler_signature import BundlerSignature
from js_intelligence.domain.value_objects.dependency_graph import (
    DependencyGraph,
    DependencyNode,
)
from js_intelligence.domain.value_objects.hidden_route import HiddenRoute
from js_intelligence.domain.value_objects.js_bundle import JSBundle
from js_intelligence.domain.value_objects.source_map_entry import SourceMapEntry
from js_intelligence.infrastructure.persistence.models import (
    JSAnalysisJobModel,
    JSIntelligenceResultModel,
)


# ──────────────────────────────────────────────────────────────────────────────
# Mappers
# ──────────────────────────────────────────────────────────────────────────────


def _job_to_domain(m: JSAnalysisJobModel) -> JSAnalysisJob:
    return JSAnalysisJob(
        job_id=m.job_id,
        tenant_id=TenantId(m.tenant_id),
        target_url=m.target_url,
        correlation_id=m.correlation_id,
        status=JobStatus(m.status),
        failure_reason=m.failure_reason,
        result_id=m.result_id,
        options=m.options or {},
        stats=m.stats or {},
        created_at=m.created_at.replace(tzinfo=UTC) if m.created_at else datetime.now(UTC),
        started_at=m.started_at.replace(tzinfo=UTC) if m.started_at else None,
        finished_at=m.finished_at.replace(tzinfo=UTC) if m.finished_at else None,
    )


def _result_to_domain(m: JSIntelligenceResultModel) -> JSIntelligenceResult:
    graph_data = m.dependency_graph or {}
    nodes = tuple(
        DependencyNode(**n) for n in graph_data.get("nodes", [])
    )
    edges = tuple(
        tuple(e) for e in graph_data.get("edges", [])
    )
    cycle_nodes = tuple(graph_data.get("cycle_node_ids", []))
    dep_graph = DependencyGraph(nodes=nodes, edges=edges, cycle_node_ids=cycle_nodes)

    sig_data = m.bundler_signature or {}
    bundler_sig = BundlerSignature(**sig_data) if sig_data else BundlerSignature()

    return JSIntelligenceResult(
        result_id=m.result_id,
        job_id=m.job_id,
        bundles=tuple(JSBundle(**b) for b in (m.bundles or [])),
        source_map_entries=tuple(
            SourceMapEntry(**e) for e in (m.source_map_entries or [])
        ),
        hidden_routes=tuple(HiddenRoute(**r) for r in (m.hidden_routes or [])),
        dependency_graph=dep_graph,
        bundler_signature=bundler_sig,
        created_at=m.created_at.replace(tzinfo=UTC) if m.created_at else datetime.now(UTC),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Repositories
# ──────────────────────────────────────────────────────────────────────────────


class PostgresJSAnalysisJobRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = session_factory

    async def save(self, job: JSAnalysisJob) -> None:
        async with self._factory() as db:
            async with db.begin():
                existing = await db.get(JSAnalysisJobModel, job.job_id)
                if existing is None:
                    db.add(
                        JSAnalysisJobModel(
                            job_id=job.job_id,
                            tenant_id=str(job.tenant_id),
                            target_url=job.target_url,
                            correlation_id=job.correlation_id,
                            status=job.status.value,
                            failure_reason=job.failure_reason,
                            result_id=job.result_id,
                            options=job.options,
                            stats=job.stats,
                            started_at=job.started_at,
                            finished_at=job.finished_at,
                        )
                    )
                else:
                    existing.status = job.status.value
                    existing.failure_reason = job.failure_reason
                    existing.result_id = job.result_id
                    existing.stats = job.stats
                    existing.started_at = job.started_at
                    existing.finished_at = job.finished_at

    async def get(self, job_id: str) -> JSAnalysisJob | None:
        async with self._factory() as db:
            m = await db.get(JSAnalysisJobModel, job_id)
            return _job_to_domain(m) if m else None

    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        limit: int = 50,
        offset: int = 0,
    ) -> list[JSAnalysisJob]:
        async with self._factory() as db:
            result = await db.execute(
                select(JSAnalysisJobModel)
                .where(JSAnalysisJobModel.tenant_id == str(tenant_id))
                .order_by(JSAnalysisJobModel.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return [_job_to_domain(m) for m in result.scalars()]


class PostgresJSIntelligenceResultRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = session_factory

    async def save(self, result: JSIntelligenceResult) -> None:
        async with self._factory() as db:
            async with db.begin():
                existing = await db.get(JSIntelligenceResultModel, result.result_id)
                if existing is None:
                    dep_graph_data = {
                        "nodes": [n.model_dump() for n in result.dependency_graph.nodes],
                        "edges": list(result.dependency_graph.edges),
                        "cycle_node_ids": list(result.dependency_graph.cycle_node_ids),
                    }
                    db.add(
                        JSIntelligenceResultModel(
                            result_id=result.result_id,
                            job_id=result.job_id,
                            bundles=[b.model_dump() for b in result.bundles],
                            source_map_entries=[e.model_dump() for e in result.source_map_entries],
                            hidden_routes=[r.model_dump() for r in result.hidden_routes],
                            dependency_graph=dep_graph_data,
                            bundler_signature=result.bundler_signature.model_dump(),
                        )
                    )

    async def get(self, result_id: str) -> JSIntelligenceResult | None:
        async with self._factory() as db:
            m = await db.get(JSIntelligenceResultModel, result_id)
            return _result_to_domain(m) if m else None

    async def get_by_job(self, job_id: str) -> JSIntelligenceResult | None:
        async with self._factory() as db:
            result = await db.execute(
                select(JSIntelligenceResultModel).where(
                    JSIntelligenceResultModel.job_id == job_id
                )
            )
            m = result.scalar_one_or_none()
            return _result_to_domain(m) if m else None
