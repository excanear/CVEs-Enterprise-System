"""Application commands — input contracts for the orchestration service."""
from __future__ import annotations

import uuid
from typing import Annotated

from pydantic import BaseModel, Field, field_validator

from ..domain.entities.scan import ScanPriority, ScanType
from ..domain.value_objects.scan_config import ScanConfig


class SubmitScanCommand(BaseModel):
    """Command to submit a new scan for orchestration."""

    tenant_id: uuid.UUID
    scan_type: ScanType
    targets: Annotated[list[str], Field(min_length=1, max_length=5000)]
    priority: ScanPriority = ScanPriority.NORMAL
    initiated_by: str = Field(max_length=256)
    correlation_id: uuid.UUID
    config: ScanConfig = Field(default_factory=ScanConfig)
    schedule_cron: str | None = Field(
        default=None,
        description="Optional cron expression for recurring scans. None = run once immediately.",
    )

    @field_validator("targets")
    @classmethod
    def _deduplicate_targets(cls, v: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for t in v:
            t = t.strip()
            if t and t not in seen:
                seen.add(t)
                out.append(t)
        return out


class CancelScanCommand(BaseModel):
    tenant_id: uuid.UUID
    scan_id: uuid.UUID
    cancelled_by: str


class RetryFailedTasksCommand(BaseModel):
    tenant_id: uuid.UUID
    scan_id: uuid.UUID
    requested_by: str
