"""DiscoveryJob entity — tracks a full discovery pipeline execution."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from cves_db.types import uuid7


class JobStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class DiscoverySourceConfig(StrEnum):
    PASSIVE_DNS = "PASSIVE_DNS"
    CT_LOGS = "CT_LOGS"
    ROBOTS_SITEMAP = "ROBOTS_SITEMAP"
    CRAWLER = "CRAWLER"
    ENDPOINT_EXTRACTION = "ENDPOINT_EXTRACTION"


_ALL_SOURCES: list[DiscoverySourceConfig] = list(DiscoverySourceConfig)


@dataclass
class DiscoveryJob:
    job_id: uuid.UUID
    tenant_id: uuid.UUID
    target_domain: str
    scope_domains: list[str]
    sources: list[DiscoverySourceConfig]
    status: JobStatus = JobStatus.PENDING
    initiated_by: str = ""
    correlation_id: uuid.UUID | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failure_reason: str | None = None
    assets_found: int = 0
    endpoints_found: int = 0
    error_detail: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        tenant_id: uuid.UUID,
        target_domain: str,
        *,
        scope_domains: list[str] | None = None,
        sources: list[DiscoverySourceConfig] | None = None,
        initiated_by: str = "",
        correlation_id: uuid.UUID | None = None,
    ) -> "DiscoveryJob":
        domain = target_domain.lower().strip()
        return cls(
            job_id=uuid7(),
            tenant_id=tenant_id,
            target_domain=domain,
            scope_domains=scope_domains or [domain],
            sources=sources or _ALL_SOURCES,
            initiated_by=initiated_by,
            correlation_id=correlation_id,
        )

    # ── State transitions ─────────────────────────────────────────────────

    def start(self) -> None:
        self.status = JobStatus.RUNNING
        self.started_at = datetime.now(timezone.utc)

    def complete(self, *, assets_found: int = 0, endpoints_found: int = 0) -> None:
        self.status = JobStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc)
        self.assets_found = assets_found
        self.endpoints_found = endpoints_found

    def fail(self, reason: str, detail: dict | None = None) -> None:
        self.status = JobStatus.FAILED
        self.completed_at = datetime.now(timezone.utc)
        self.failure_reason = reason
        self.error_detail = detail or {}

    def cancel(self) -> None:
        self.status = JobStatus.CANCELLED
        self.completed_at = datetime.now(timezone.utc)

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def is_terminal(self) -> bool:
        return self.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED)
