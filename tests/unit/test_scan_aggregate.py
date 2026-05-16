"""Unit tests — Scan aggregate state machine."""
from __future__ import annotations

import uuid

import pytest

from scan_orchestrator.domain.entities.scan import Scan, ScanPriority, ScanStatus, ScanType


@pytest.fixture
def base_scan() -> Scan:
    return Scan(
        scan_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        scan_type=ScanType.PORT_SCAN,
        priority=ScanPriority.NORMAL,
        initiated_by="test_user",
        config_snapshot={},
        targets=["10.0.0.1", "10.0.0.2"],
        correlation_id=uuid.uuid4(),
    )


class TestScanInitialState:
    def test_initial_status_is_pending(self, base_scan):
        assert base_scan.status == ScanStatus.PENDING

    def test_initial_counters_are_zero(self, base_scan):
        assert base_scan.tasks_total == 0
        assert base_scan.tasks_completed == 0
        assert base_scan.tasks_failed == 0
        assert base_scan.tasks_retrying == 0

    def test_priority_scores(self):
        assert ScanPriority.CRITICAL.as_score() == 100
        assert ScanPriority.HIGH.as_score() == 75
        assert ScanPriority.NORMAL.as_score() == 50
        assert ScanPriority.LOW.as_score() == 25


class TestScanScheduleTransition:
    def test_schedule_from_pending(self, base_scan):
        base_scan.schedule()
        assert base_scan.status == ScanStatus.SCHEDULED
        assert base_scan.scheduled_at is not None

    def test_schedule_emits_domain_event(self, base_scan):
        base_scan.schedule()
        events = base_scan._domain_events
        assert any(e.get("type") == "scan.scheduled" or "scan.scheduled" in str(e) for e in events)

    def test_cannot_schedule_twice(self, base_scan):
        base_scan.schedule()
        with pytest.raises(ValueError, match="Invalid"):
            base_scan.schedule()


class TestScanRunningTransition:
    def test_start_from_scheduled(self, base_scan):
        worker_id = uuid.uuid4()
        base_scan.schedule()
        base_scan.start(worker_id)
        assert base_scan.status == ScanStatus.RUNNING
        assert base_scan.started_at is not None
        assert worker_id in base_scan.assigned_worker_ids

    def test_cannot_start_from_pending(self, base_scan):
        with pytest.raises(ValueError, match="Invalid"):
            base_scan.start(uuid.uuid4())

    def test_multiple_workers_accumulate(self, base_scan):
        w1, w2 = uuid.uuid4(), uuid.uuid4()
        base_scan.schedule()
        base_scan.start(w1)
        base_scan.start(w2)
        assert w1 in base_scan.assigned_worker_ids
        assert w2 in base_scan.assigned_worker_ids

    def test_same_worker_not_duplicated(self, base_scan):
        worker = uuid.uuid4()
        base_scan.schedule()
        base_scan.start(worker)
        base_scan.start(worker)
        assert base_scan.assigned_worker_ids.count(worker) == 1


class TestScanCompletionTransition:
    def _running_scan(self, base_scan):
        base_scan.schedule()
        base_scan.start(uuid.uuid4())
        return base_scan

    def test_complete_with_no_failures(self, base_scan):
        scan = self._running_scan(base_scan)
        scan.tasks_total = 5
        scan.tasks_completed = 5
        scan.complete()
        assert scan.status == ScanStatus.COMPLETED
        assert scan.completed_at is not None

    def test_partial_when_some_failed(self, base_scan):
        scan = self._running_scan(base_scan)
        scan.tasks_total = 5
        scan.tasks_completed = 3
        scan.tasks_failed = 2
        scan.complete()
        assert scan.status == ScanStatus.PARTIAL

    def test_fail_transition(self, base_scan):
        scan = self._running_scan(base_scan)
        scan.fail(reason="worker crashed")
        assert scan.status == ScanStatus.FAILED
        assert scan.failure_reason == "worker crashed"

    def test_cancel_from_running(self, base_scan):
        scan = self._running_scan(base_scan)
        scan.cancel(cancelled_by="admin")
        assert scan.status == ScanStatus.CANCELLED


class TestScanIsTerminal:
    def test_completed_is_terminal(self, base_scan):
        base_scan.schedule()
        base_scan.start(uuid.uuid4())
        base_scan.complete()
        assert base_scan.is_terminal is True

    def test_pending_is_not_terminal(self, base_scan):
        assert base_scan.is_terminal is False

    def test_cancelled_is_terminal(self, base_scan):
        base_scan.cancel(cancelled_by="admin")
        assert base_scan.is_terminal is True


class TestScanProgressProperty:
    def test_progress_zero_when_no_tasks(self, base_scan):
        assert base_scan.progress_pct == 0.0

    def test_progress_computed_from_counters(self, base_scan):
        base_scan.tasks_total = 10
        base_scan.tasks_completed = 7
        assert base_scan.progress_pct == pytest.approx(70.0)

    def test_progress_capped_at_100(self, base_scan):
        base_scan.tasks_total = 5
        base_scan.tasks_completed = 5
        base_scan.tasks_failed = 0
        assert base_scan.progress_pct <= 100.0
