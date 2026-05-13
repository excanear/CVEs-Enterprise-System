"""Scan aggregate root — owns the lifecycle of a single scan operation.

State machine:
  PENDING → SCHEDULED → RUNNING → COMPLETED
                                 ↘ FAILED
                                 ↘ CANCELLED
                                 ↘ PARTIAL   (some tasks OK, some failed)

Rules:
  - Scan transitions are uni-directional and validated.
  - A Scan owns all ScanTasks — tasks cannot exist without a Scan.
  - Progress is computed from task counters, not stored redundantly.
  - Domain events are staged via OutboxMixin.collect_events().
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scan_task import ScanTask


class ScanStatus(StrEnum):
    PENDING = "PENDING"
    SCHEDULED = "SCHEDULED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanType(StrEnum):
    NETWORK_DISCOVERY = "NETWORK_DISCOVERY"
    PORT_SCAN = "PORT_SCAN"
    WEB_CRAWL = "WEB_CRAWL"
    VULNERABILITY_PROBE = "VULNERABILITY_PROBE"
    FULL = "FULL"


class ScanPriority(StrEnum):
    CRITICAL = "CRITICAL"   # score 100
    HIGH = "HIGH"           # score 75
    NORMAL = "NORMAL"       # score 50
    LOW = "LOW"             # score 25

    def as_score(self) -> int:
        return {"CRITICAL": 100, "HIGH": 75, "NORMAL": 50, "LOW": 25}[self.value]


_VALID_TRANSITIONS: dict[ScanStatus, set[ScanStatus]] = {
    ScanStatus.PENDING: {ScanStatus.SCHEDULED, ScanStatus.CANCELLED},
    ScanStatus.SCHEDULED: {ScanStatus.RUNNING, ScanStatus.CANCELLED},
    ScanStatus.RUNNING: {
        ScanStatus.COMPLETED, ScanStatus.PARTIAL,
        ScanStatus.FAILED, ScanStatus.CANCELLED,
    },
    ScanStatus.COMPLETED: set(),
    ScanStatus.PARTIAL: set(),
    ScanStatus.FAILED: {ScanStatus.SCHEDULED},   # allow re-schedule
    ScanStatus.CANCELLED: set(),
}


@dataclass
class Scan:
    """Scan aggregate root."""

    scan_id: uuid.UUID
    tenant_id: uuid.UUID
    scan_type: ScanType
    priority: ScanPriority
    initiated_by: str
    config_snapshot: dict                # frozen copy of ScanConfig at submission time
    targets: list[str]                   # CIDR blocks, FQDNs, IP addresses, URLs
    correlation_id: uuid.UUID

    status: ScanStatus = ScanStatus.PENDING
    scheduled_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failure_reason: str | None = None

    tasks_total: int = 0
    tasks_completed: int = 0
    tasks_failed: int = 0
    tasks_retrying: int = 0

    assigned_worker_ids: list[uuid.UUID] = field(default_factory=list)
    _domain_events: list[dict] = field(default_factory=list, repr=False)

    # ── Transitions ────────────────────────────────────────────────────────

    def schedule(self, scheduled_at: datetime | None = None) -> None:
        self._transition_to(ScanStatus.SCHEDULED)
        self.scheduled_at = scheduled_at or datetime.now(tz=timezone.utc)
        self._emit("scan.scheduled", {"scan_id": str(self.scan_id), "scheduled_at": self.scheduled_at.isoformat()})

    def start(self, worker_id: uuid.UUID) -> None:
        self._transition_to(ScanStatus.RUNNING)
        self.started_at = datetime.now(tz=timezone.utc)
        if worker_id not in self.assigned_worker_ids:
            self.assigned_worker_ids.append(worker_id)
        self._emit("scan.started", {"scan_id": str(self.scan_id), "worker_id": str(worker_id)})

    def complete(self) -> None:
        status = (
            ScanStatus.PARTIAL
            if self.tasks_failed > 0 and self.tasks_completed > 0
            else ScanStatus.COMPLETED
        )
        self._transition_to(status)
        self.completed_at = datetime.now(tz=timezone.utc)
        self._emit(
            "scan.completed",
            {
                "scan_id": str(self.scan_id),
                "status": self.status,
                "tasks_total": self.tasks_total,
                "tasks_completed": self.tasks_completed,
                "tasks_failed": self.tasks_failed,
                "duration_seconds": self._duration_seconds(),
            },
        )

    def fail(self, reason: str) -> None:
        self._transition_to(ScanStatus.FAILED)
        self.failure_reason = reason
        self.completed_at = datetime.now(tz=timezone.utc)
        self._emit("scan.failed", {"scan_id": str(self.scan_id), "reason": reason})

    def cancel(self, cancelled_by: str) -> None:
        self._transition_to(ScanStatus.CANCELLED)
        self.completed_at = datetime.now(tz=timezone.utc)
        self._emit("scan.cancelled", {"scan_id": str(self.scan_id), "cancelled_by": cancelled_by})

    # ── Task accounting ───────────────────────────────────────────────────

    def register_tasks(self, count: int) -> None:
        """Called when tasks are initially enqueued for this scan."""
        self.tasks_total += count

    def on_task_completed(self) -> None:
        self.tasks_completed += 1

    def on_task_failed(self) -> None:
        self.tasks_failed += 1

    def on_task_retrying(self, delta: int = 1) -> None:
        self.tasks_retrying += delta

    @property
    def progress_pct(self) -> float:
        if not self.tasks_total:
            return 0.0
        return round((self.tasks_completed + self.tasks_failed) / self.tasks_total * 100, 2)

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            ScanStatus.COMPLETED, ScanStatus.PARTIAL,
            ScanStatus.FAILED, ScanStatus.CANCELLED,
        }

    # ── Domain events ─────────────────────────────────────────────────────

    def collect_events(self) -> list[dict]:
        evts = self._domain_events.copy()
        self._domain_events.clear()
        return evts

    # ── Internals ─────────────────────────────────────────────────────────

    def _transition_to(self, target: ScanStatus) -> None:
        allowed = _VALID_TRANSITIONS.get(self.status, set())
        if target not in allowed:
            raise ValueError(
                f"Invalid scan transition: {self.status} → {target} "
                f"(allowed: {', '.join(s.value for s in allowed) or 'none'})"
            )
        self.status = target

    def _emit(self, event_type: str, payload: dict) -> None:
        self._domain_events.append({"event_type": event_type, "payload": payload})

    def _duration_seconds(self) -> float | None:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
