"""PostgreSQL repository implementations for Discovery Engine.

Implements the domain ports DiscoveredAssetRepository and DiscoveryJobRepository.
Uses AsyncSession from cves_db — caller must have already entered an RLS context.
"""
from __future__ import annotations

import uuid
from datetime import timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ...domain.entities.discovered_asset import (
    AssetStatus,
    AssetType,
    DiscoveredAsset,
    DiscoverySource,
)
from ...domain.entities.discovery_job import DiscoveryJob, DiscoverySourceConfig, JobStatus
from .models import DiscoveredAssetModel, DiscoveryJobModel


# ── Domain ↔ ORM mappers ──────────────────────────────────────────────────────

def _asset_to_domain(row: DiscoveredAssetModel) -> DiscoveredAsset:
    def _dt(v):
        if v is None:
            return None
        return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v

    return DiscoveredAsset(
        asset_id=row.asset_id,
        tenant_id=row.tenant_id,
        job_id=row.job_id,
        asset_type=AssetType(row.asset_type),
        value=row.value,
        source=DiscoverySource(row.source),
        status=AssetStatus(row.status),
        confidence=row.confidence,
        parent_asset_id=row.parent_asset_id,
        correlation_id=row.correlation_id,
        first_seen_at=_dt(row.first_seen_at),
        last_seen_at=_dt(row.last_seen_at),
        metadata=dict(row.asset_metadata or {}),
        tags=list(row.tags or []),
    )


def _job_to_domain(row: DiscoveryJobModel) -> DiscoveryJob:
    def _dt(v):
        if v is None:
            return None
        return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v

    return DiscoveryJob(
        job_id=row.job_id,
        tenant_id=row.tenant_id,
        target_domain=row.target_domain,
        scope_domains=list(row.scope_domains or []),
        sources=[DiscoverySourceConfig(s) for s in (row.sources or [])],
        status=JobStatus(row.status),
        initiated_by=row.initiated_by,
        correlation_id=row.correlation_id,
        created_at=_dt(row.created_at),
        started_at=_dt(row.started_at),
        completed_at=_dt(row.completed_at),
        failure_reason=row.failure_reason,
        assets_found=row.assets_found,
        endpoints_found=row.endpoints_found,
    )


# ── Asset repository ──────────────────────────────────────────────────────────

class PostgresDiscoveredAssetRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, asset: DiscoveredAsset) -> None:
        existing = await self._session.get(DiscoveredAssetModel, asset.asset_id)
        if existing:
            existing.status = asset.status
            existing.confidence = asset.confidence
            existing.last_seen_at = asset.last_seen_at
            existing.asset_metadata = asset.metadata
            existing.tags = asset.tags
        else:
            row = DiscoveredAssetModel(
                asset_id=asset.asset_id,
                tenant_id=asset.tenant_id,
                job_id=asset.job_id,
                asset_type=asset.asset_type,
                value=asset.value,
                source=asset.source,
                status=asset.status,
                confidence=asset.confidence,
                parent_asset_id=asset.parent_asset_id,
                correlation_id=asset.correlation_id,
                first_seen_at=asset.first_seen_at,
                last_seen_at=asset.last_seen_at,
                asset_metadata=asset.metadata,
                tags=asset.tags,
            )
            self._session.add(row)
        await self._session.flush()

    async def save_batch(self, assets: list[DiscoveredAsset]) -> None:
        for asset in assets:
            await self.save(asset)

    async def get(self, asset_id: uuid.UUID) -> DiscoveredAsset | None:
        row = await self._session.get(DiscoveredAssetModel, asset_id)
        return _asset_to_domain(row) if row else None

    async def get_by_value(self, tenant_id: uuid.UUID, value: str) -> DiscoveredAsset | None:
        stmt = (
            select(DiscoveredAssetModel)
            .where(
                DiscoveredAssetModel.tenant_id == tenant_id,
                DiscoveredAssetModel.value == value,
            )
            .limit(1)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return _asset_to_domain(row) if row else None

    async def list_by_job(self, job_id: uuid.UUID) -> list[DiscoveredAsset]:
        stmt = select(DiscoveredAssetModel).where(DiscoveredAssetModel.job_id == job_id)
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_asset_to_domain(r) for r in rows]

    async def list_by_type(
        self, tenant_id: uuid.UUID, asset_type: AssetType
    ) -> list[DiscoveredAsset]:
        stmt = select(DiscoveredAssetModel).where(
            DiscoveredAssetModel.tenant_id == tenant_id,
            DiscoveredAssetModel.asset_type == asset_type,
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_asset_to_domain(r) for r in rows]

    async def update_status(self, asset_id: uuid.UUID, status: AssetStatus) -> None:
        await self._session.execute(
            update(DiscoveredAssetModel)
            .where(DiscoveredAssetModel.asset_id == asset_id)
            .values(status=status)
        )


# ── Job repository ────────────────────────────────────────────────────────────

class PostgresDiscoveryJobRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, job: DiscoveryJob) -> None:
        existing = await self._session.get(DiscoveryJobModel, job.job_id)
        if existing:
            existing.status = job.status
            existing.started_at = job.started_at
            existing.completed_at = job.completed_at
            existing.failure_reason = job.failure_reason
            existing.assets_found = job.assets_found
            existing.endpoints_found = job.endpoints_found
        else:
            row = DiscoveryJobModel(
                job_id=job.job_id,
                tenant_id=job.tenant_id,
                target_domain=job.target_domain,
                scope_domains=job.scope_domains,
                sources=[s.value for s in job.sources],
                status=job.status,
                initiated_by=job.initiated_by,
                correlation_id=job.correlation_id,
                started_at=job.started_at,
                completed_at=job.completed_at,
                failure_reason=job.failure_reason,
                assets_found=job.assets_found,
                endpoints_found=job.endpoints_found,
            )
            self._session.add(row)
        await self._session.flush()

    async def get(self, job_id: uuid.UUID) -> DiscoveryJob | None:
        row = await self._session.get(DiscoveryJobModel, job_id)
        return _job_to_domain(row) if row else None

    async def list_by_tenant(
        self, tenant_id: uuid.UUID, limit: int = 50
    ) -> list[DiscoveryJob]:
        stmt = (
            select(DiscoveryJobModel)
            .where(DiscoveryJobModel.tenant_id == tenant_id)
            .order_by(DiscoveryJobModel.created_at.desc())
            .limit(limit)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_job_to_domain(r) for r in rows]

    async def update_status(self, job_id: uuid.UUID, status: JobStatus) -> None:
        await self._session.execute(
            update(DiscoveryJobModel)
            .where(DiscoveryJobModel.job_id == job_id)
            .values(status=status)
        )
