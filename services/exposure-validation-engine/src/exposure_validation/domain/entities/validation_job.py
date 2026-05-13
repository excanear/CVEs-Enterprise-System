"""ValidationJob entity — tracks the lifecycle of a single validation run.

State machine:
  PENDING → RUNNING → COMPLETED
                    ↘ FAILED
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from cves_db.types import uuid7

from cves_event_schemas.eve.eve_events import ExposureType


class JobStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


_VALID_TRANSITIONS: dict[JobStatus, set[JobStatus]] = {
    JobStatus.PENDING: {JobStatus.RUNNING, JobStatus.FAILED},
    JobStatus.RUNNING: {JobStatus.COMPLETED, JobStatus.FAILED},
    JobStatus.COMPLETED: set(),
    JobStatus.FAILED: set(),
}


@dataclass
class ValidationJob:
    job_id: str
    tenant_id: str
    target_url: str
    correlation_id: str
    exposure_type: ExposureType
    options: dict[str, Any]
    status: JobStatus
    result_id: str | None = None
    failure_reason: str | None = None
    stats: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @classmethod
    def create(
        cls,
        *,
        tenant_id: str,
        target_url: str,
        correlation_id: str,
        exposure_type: ExposureType,
        options: dict[str, Any] | None = None,
    ) -> "ValidationJob":
        return cls(
            job_id=str(uuid7()),
            tenant_id=tenant_id,
            target_url=target_url,
            correlation_id=correlation_id,
            exposure_type=exposure_type,
            options=options or {},
            status=JobStatus.PENDING,
        )

    def _transition(self, target: JobStatus) -> None:
        if target not in _VALID_TRANSITIONS[self.status]:
            raise ValueError(
                f"Invalid transition: {self.status} → {target}"
            )
        self.status = target

    def start(self) -> None:
        self._transition(JobStatus.RUNNING)
        self.started_at = datetime.now(UTC)

    def complete(self, result_id: str, stats: dict[str, Any] | None = None) -> None:
        self._transition(JobStatus.COMPLETED)
        self.result_id = result_id
        self.stats = stats or {}
        self.finished_at = datetime.now(UTC)

    def fail(self, reason: str) -> None:
        self._transition(JobStatus.FAILED)
        self.failure_reason = reason
        self.finished_at = datetime.now(UTC)

    @property
    def is_terminal(self) -> bool:
        return self.status in (JobStatus.COMPLETED, JobStatus.FAILED)

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None
