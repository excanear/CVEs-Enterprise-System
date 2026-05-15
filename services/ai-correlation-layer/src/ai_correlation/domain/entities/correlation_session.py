"""CorrelationSession — aggregate root for the ACL correlation lifecycle.

A session represents one run of the full correlation pipeline for a tenant.
It transitions through states: PENDING → RUNNING → COMPLETED | FAILED.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class SessionStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass
class CorrelationSession:
    """Aggregate root: tracks a single correlation analysis run."""

    session_id: str
    tenant_id: str
    status: SessionStatus = SessionStatus.PENDING
    evidence_count: int = 0
    path_count: int = 0
    cluster_count: int = 0
    prioritized_count: int = 0
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    def start(self) -> None:
        self.status = SessionStatus.RUNNING
        self.updated_at = datetime.now(UTC)

    def complete(
        self,
        *,
        cluster_count: int,
        prioritized_count: int,
    ) -> None:
        self.status = SessionStatus.COMPLETED
        self.cluster_count = cluster_count
        self.prioritized_count = prioritized_count
        self.updated_at = datetime.now(UTC)
        self.completed_at = datetime.now(UTC)

    def fail(self, error: str) -> None:
        self.status = SessionStatus.FAILED
        self.error = error
        self.updated_at = datetime.now(UTC)
