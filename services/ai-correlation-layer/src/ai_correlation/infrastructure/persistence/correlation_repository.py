"""PostgreSQL repository for AI Correlation Layer sessions and clusters."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ai_correlation.domain.entities.correlation_session import (
    CorrelationSession,
    SessionStatus,
)
from ai_correlation.domain.entities.evidence_cluster import EvidenceCluster
from ai_correlation.infrastructure.persistence.models import (
    CorrelationSessionModel,
    EvidenceClusterModel,
)


class PostgresCorrelationRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = session_factory

    # ── Sessions ──────────────────────────────────────────────────────────

    async def save_session(self, session: CorrelationSession) -> None:
        async with self._factory() as db:
            async with db.begin():
                db.add(
                    CorrelationSessionModel(
                        session_id=session.session_id,
                        tenant_id=session.tenant_id,
                        status=session.status.value,
                        evidence_count=session.evidence_count,
                        path_count=session.path_count,
                        cluster_count=session.cluster_count,
                        prioritized_count=session.prioritized_count,
                        error=session.error,
                        completed_at=session.completed_at,
                    )
                )

    async def update_session(self, session: CorrelationSession) -> None:
        async with self._factory() as db:
            async with db.begin():
                model = await db.get(CorrelationSessionModel, session.session_id)
                if model is None:
                    return
                model.status = session.status.value
                model.evidence_count = session.evidence_count
                model.path_count = session.path_count
                model.cluster_count = session.cluster_count
                model.prioritized_count = session.prioritized_count
                model.error = session.error
                model.completed_at = session.completed_at

    async def get_session(self, session_id: str) -> CorrelationSession | None:
        async with self._factory() as db:
            model = await db.get(CorrelationSessionModel, session_id)
            if model is None:
                return None
            return _model_to_session(model)

    # ── Clusters ──────────────────────────────────────────────────────────

    async def save_cluster(self, cluster: EvidenceCluster) -> None:
        async with self._factory() as db:
            async with db.begin():
                stmt = (
                    pg_insert(EvidenceClusterModel)
                    .values(
                        cluster_id=cluster.cluster_id,
                        session_id=cluster.session_id,
                        tenant_id=cluster.tenant_id,
                        tier=cluster.tier.value,
                        size=cluster.size,
                        host=cluster.host,
                        exposure_types=cluster.exposure_types,
                        avg_confidence=cluster.avg_confidence,
                        poc_triggered_count=cluster.poc_triggered_count,
                    )
                    .on_conflict_do_update(
                        index_elements=["cluster_id"],
                        set_={
                            "size": cluster.size,
                            "tier": cluster.tier.value,
                            "avg_confidence": cluster.avg_confidence,
                            "poc_triggered_count": cluster.poc_triggered_count,
                        },
                    )
                )
                await db.execute(stmt)

    async def list_clusters(
        self, tenant_id: str, session_id: str | None = None
    ) -> list[EvidenceCluster]:
        async with self._factory() as db:
            q = select(EvidenceClusterModel).where(
                EvidenceClusterModel.tenant_id == tenant_id
            )
            if session_id:
                q = q.where(EvidenceClusterModel.session_id == session_id)
            result = await db.execute(q.order_by(EvidenceClusterModel.created_at.desc()))
            rows = result.scalars().all()
            return [_cluster_model_to_entity(r) for r in rows]


def _model_to_session(m: CorrelationSessionModel) -> CorrelationSession:
    s = CorrelationSession(
        session_id=m.session_id,
        tenant_id=m.tenant_id,
        status=SessionStatus(m.status),
        evidence_count=m.evidence_count,
        path_count=m.path_count,
        cluster_count=m.cluster_count,
        prioritized_count=m.prioritized_count,
        error=m.error,
        created_at=m.created_at,
        updated_at=m.updated_at,
        completed_at=m.completed_at,
    )
    return s


def _cluster_model_to_entity(m: EvidenceClusterModel) -> EvidenceCluster:
    from cves_event_schemas.acl.acl_events import RiskTier

    return EvidenceCluster(
        cluster_id=m.cluster_id,
        tenant_id=m.tenant_id,
        session_id=m.session_id,
        tier=RiskTier(m.tier),
        host=m.host,
        created_at=m.created_at,
    )
