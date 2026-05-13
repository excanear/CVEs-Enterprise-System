"""ScanTask entity — an individual unit of work within a Scan.

Each ScanTask maps to a single target (IP, FQDN, URL) and scan type.
Tasks are the atomic units dispatched to workers.

State machine:
  QUEUED → DISPATCHED → RUNNING → COMPLETED
                                 ↘ FAILED
       ↑___________________________↗ (RETRYING requeues back to QUEUED)
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class TaskStatus(StrEnum):
    QUEUED = "QUEUED"
    DISPATCHED = "DISPATCHED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RETRYING = "RETRYING"
    DLQ = "DLQ"


class TaskType(StrEnum):
    ICMP_PING = "ICMP_PING"
    PORT_SCAN = "PORT_SCAN"
    SERVICE_DETECTION = "SERVICE_DETECTION"
    WEB_CRAWL = "WEB_CRAWL"
    BANNER_GRAB = "BANNER_GRAB"
    SSL_PROBE = "SSL_PROBE"
    VULN_PROBE = "VULN_PROBE"
    DNS_ENUMERATION = "DNS_ENUMERATION"


_VALID_TRANSITIONS: dict[TaskStatus, set[TaskStatus]] = {
    TaskStatus.QUEUED: {TaskStatus.DISPATCHED, TaskStatus.FAILED},
    TaskStatus.DISPATCHED: {TaskStatus.RUNNING, TaskStatus.QUEUED, TaskStatus.FAILED},
    TaskStatus.RUNNING: {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.RETRYING},
    TaskStatus.RETRYING: {TaskStatus.QUEUED},
    TaskStatus.COMPLETED: set(),
    TaskStatus.FAILED: {TaskStatus.RETRYING, TaskStatus.DLQ},
    TaskStatus.DLQ: set(),
}


@dataclass
class ScanTask:
    """Atomic unit of work dispatched to a scan worker."""

    task_id: uuid.UUID
    scan_id: uuid.UUID
    tenant_id: uuid.UUID
    target: str                  # IP, FQDN, URL
    task_type: TaskType
    priority_score: int          # 0–100; higher = dispatched first
    config: dict = field(default_factory=dict)

    status: TaskStatus = TaskStatus.QUEUED
    attempt_count: int = 0
    max_attempts: int = 3
    assigned_worker_id: uuid.UUID | None = None

    created_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    dispatched_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    next_retry_at: datetime | None = None

    result: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None
    last_error_code: str | None = None

    # ── Transitions ────────────────────────────────────────────────────────

    def dispatch(self, worker_id: uuid.UUID) -> None:
        self._transition_to(TaskStatus.DISPATCHED)
        self.assigned_worker_id = worker_id
        self.dispatched_at = datetime.now(tz=timezone.utc)

    def start(self) -> None:
        self._transition_to(TaskStatus.RUNNING)
        self.started_at = datetime.now(tz=timezone.utc)
        self.attempt_count += 1

    def complete(self, result: dict[str, Any]) -> None:
        self._transition_to(TaskStatus.COMPLETED)
        self.result = result
        self.completed_at = datetime.now(tz=timezone.utc)

    def fail(self, error: str, error_code: str | None = None) -> None:
        self._transition_to(TaskStatus.FAILED)
        self.error_message = error
        self.last_error_code = error_code
        self.completed_at = datetime.now(tz=timezone.utc)

    def mark_retrying(self, retry_at: datetime) -> None:
        self._transition_to(TaskStatus.RETRYING)
        self.next_retry_at = retry_at
        self.error_message = None

    def requeue(self) -> None:
        self._transition_to(TaskStatus.QUEUED)
        self.assigned_worker_id = None
        self.dispatched_at = None
        self.started_at = None
        self.completed_at = None

    def move_to_dlq(self) -> None:
        self._transition_to(TaskStatus.DLQ)
        self.completed_at = datetime.now(tz=timezone.utc)

    # ── Queries ───────────────────────────────────────────────────────────

    @property
    def can_retry(self) -> bool:
        return self.attempt_count < self.max_attempts

    @property
    def is_terminal(self) -> bool:
        return self.status in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.DLQ}

    @property
    def execution_duration_ms(self) -> int | None:
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds() * 1000)
        return None

    # ── Internals ─────────────────────────────────────────────────────────

    def _transition_to(self, target: TaskStatus) -> None:
        allowed = _VALID_TRANSITIONS.get(self.status, set())
        if target not in allowed:
            raise ValueError(
                f"Invalid task transition: {self.status} → {target} "
                f"(task_id={self.task_id})"
            )
        self.status = target
