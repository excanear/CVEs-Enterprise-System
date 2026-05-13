"""PostgreSQL repository for AGE ingestion job tracking."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cves_db.types import uuid7

from asset_graph.infrastructure.persistence.models import IngestionJobModel


class PostgresIngestionJobRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = session_factory

    async def record(
        self,
        tenant_id: str,
        event_type: str,
        topic: str = "",
        status: str = "PROCESSED",
        error: str | None = None,
        payload_summary: dict | None = None,
    ) -> str:
        job_id = str(uuid7())
        async with self._factory() as db:
            async with db.begin():
                db.add(
                    IngestionJobModel(
                        job_id=job_id,
                        tenant_id=tenant_id,
                        event_type=event_type,
                        topic=topic,
                        status=status,
                        error=error,
                        payload_summary=payload_summary or {},
                        processed_at=datetime.now(UTC),
                    )
                )
        return job_id

    async def count_by_tenant(self, tenant_id: str) -> int:
        async with self._factory() as db:
            result = await db.execute(
                select(func.count(IngestionJobModel.job_id)).where(
                    IngestionJobModel.tenant_id == tenant_id
                )
            )
            return result.scalar_one()
