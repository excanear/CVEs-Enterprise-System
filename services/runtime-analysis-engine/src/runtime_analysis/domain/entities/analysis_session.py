from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from cves_db.types import TenantId, uuid7


class SessionStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


_VALID_TRANSITIONS: dict[SessionStatus, frozenset[SessionStatus]] = {
    SessionStatus.PENDING: frozenset({SessionStatus.RUNNING, SessionStatus.FAILED}),
    SessionStatus.RUNNING: frozenset(
        {SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.TIMEOUT}
    ),
    SessionStatus.COMPLETED: frozenset(),
    SessionStatus.FAILED: frozenset(),
    SessionStatus.TIMEOUT: frozenset(),
}


@dataclass
class AnalysisSession:
    """Aggregate root for a single browser-based analysis session."""

    session_id: str
    tenant_id: TenantId
    target_url: str
    correlation_id: str
    options: dict
    status: SessionStatus = SessionStatus.PENDING
    result_id: str | None = None
    failure_reason: str | None = None
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
    ) -> "AnalysisSession":
        return cls(
            session_id=uuid7(),
            tenant_id=tenant_id,
            target_url=target_url,
            correlation_id=correlation_id,
            options=options or {},
        )

    # ------------------------------------------------------------------
    # State machine
    # ------------------------------------------------------------------

    def _transition(self, new_status: SessionStatus) -> None:
        allowed = _VALID_TRANSITIONS[self.status]
        if new_status not in allowed:
            raise ValueError(
                f"Invalid transition {self.status!s} → {new_status!s}"
            )
        self.status = new_status

    def start(self) -> None:
        self._transition(SessionStatus.RUNNING)
        self.started_at = datetime.now(UTC)

    def complete(self, result_id: str) -> None:
        self._transition(SessionStatus.COMPLETED)
        self.result_id = result_id
        self.finished_at = datetime.now(UTC)

    def fail(self, reason: str) -> None:
        self._transition(SessionStatus.FAILED)
        self.failure_reason = reason
        self.finished_at = datetime.now(UTC)

    def timeout(self) -> None:
        self._transition(SessionStatus.TIMEOUT)
        self.failure_reason = "Session timed out"
        self.finished_at = datetime.now(UTC)

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            SessionStatus.COMPLETED,
            SessionStatus.FAILED,
            SessionStatus.TIMEOUT,
        }

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at is None or self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()
