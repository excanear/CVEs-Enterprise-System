"""Application commands for the Discovery Engine."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from ..domain.entities.discovery_job import DiscoverySourceConfig


@dataclass(frozen=True)
class RunDiscoveryCommand:
    tenant_id: uuid.UUID
    target_domain: str
    initiated_by: str
    correlation_id: uuid.UUID
    scope_domains: list[str] = field(default_factory=list)
    sources: list[DiscoverySourceConfig] = field(default_factory=list)
    max_depth: int = 3
    max_pages: int = 200
    max_rps: float = 5.0
    allow_internal: bool = False


@dataclass(frozen=True)
class CancelDiscoveryCommand:
    job_id: uuid.UUID
    tenant_id: uuid.UUID
    cancelled_by: str
