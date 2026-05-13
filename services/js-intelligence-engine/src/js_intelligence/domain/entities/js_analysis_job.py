from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from cves_db.types import TenantId, uuid7


class JobStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


_VALID_TRANSITIONS: dict[JobStatus, frozenset[JobStatus]] = {
    JobStatus.PENDING: frozenset({JobStatus.RUNNING, JobStatus.FAILED}),
    JobStatus.RUNNING: frozenset({JobStatus.COMPLETED, JobStatus.FAILED}),
    JobStatus.COMPLETED: frozenset(),
    JobStatus.FAILED: frozenset(),
}


@dataclass
class JSAnalysisJob:
    """Aggregate root for a single JS static-analysis job."""

    job_id: str
    tenant_id: TenantId
    target_url: str
    correlation_id: str
    options: dict
    status: JobStatus = JobStatus.PENDING
    result_id: str | None = None
    failure_reason: str | None = None
    stats: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        target_url: str,
        correlation_id: str,
        options: dict | None = None,
    ) -> "JSAnalysisJob":
        return cls(
            job_id=uuid7(),
            tenant_id=tenant_id,
            target_url=target_url,
            correlation_id=correlation_id,
            options=options or {},
        )

    # ------------------------------------------------------------------
    # State machine
    # ------------------------------------------------------------------

    def _transition(self, new_status: JobStatus) -> None:
        allowed = _VALID_TRANSITIONS[self.status]
        if new_status not in allowed:
            raise ValueError(
                f"Invalid transition {self.status!s} → {new_status!s}"
            )
        self.status = new_status

    def start(self) -> None:
        self._transition(JobStatus.RUNNING)
        self.started_at = datetime.now(UTC)

    def complete(self, result_id: str, stats: dict | None = None) -> None:
        self._transition(JobStatus.COMPLETED)
        self.result_id = result_id
        self.stats = stats or {}
        self.finished_at = datetime.now(UTC)

    def fail(self, reason: str) -> None:
        self._transition(JobStatus.FAILED)
        self.failure_reason = reason[:2048]  # cap length
        self.finished_at = datetime.now(UTC)

    @property
    def is_terminal(self) -> bool:
        return self.status in {JobStatus.COMPLETED, JobStatus.FAILED}

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at is None or self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()
