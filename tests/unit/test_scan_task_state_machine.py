"""Unit tests — ScanTask state machine (all valid/invalid transitions)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from scan_orchestrator.domain.entities.scan_task import ScanTask, TaskStatus, TaskType


@pytest.fixture
def base_task() -> ScanTask:
    return ScanTask(
        task_id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        target="10.0.0.1",
        task_type=TaskType.PORT_SCAN,
        priority_score=50,
        max_attempts=3,
    )


class TestScanTaskInitialState:
    def test_initial_status_is_queued(self, base_task):
        assert base_task.status == TaskStatus.QUEUED

    def test_initial_attempt_count_is_zero(self, base_task):
        assert base_task.attempt_count == 0

    def test_can_retry_initially_true(self, base_task):
        assert base_task.can_retry is True

    def test_is_not_terminal_initially(self, base_task):
        assert base_task.is_terminal is False

    def test_execution_duration_none_initially(self, base_task):
        assert base_task.execution_duration_ms is None


class TestScanTaskDispatchTransition:
    def test_dispatch_sets_worker_and_timestamp(self, base_task):
        worker = uuid.uuid4()
        base_task.dispatch(worker)
        assert base_task.status == TaskStatus.DISPATCHED
        assert base_task.assigned_worker_id == worker
        assert base_task.dispatched_at is not None

    def test_cannot_dispatch_twice(self, base_task):
        base_task.dispatch(uuid.uuid4())
        with pytest.raises(ValueError, match="Invalid task transition"):
            base_task.dispatch(uuid.uuid4())

    def test_cannot_dispatch_from_completed(self, base_task):
        base_task.dispatch(uuid.uuid4())
        base_task.start()
        base_task.complete({"result": "ok"})
        with pytest.raises(ValueError, match="Invalid task transition"):
            base_task.dispatch(uuid.uuid4())


class TestScanTaskStartTransition:
    def test_start_sets_started_at_and_increments_attempt(self, base_task):
        base_task.dispatch(uuid.uuid4())
        base_task.start()
        assert base_task.status == TaskStatus.RUNNING
        assert base_task.started_at is not None
        assert base_task.attempt_count == 1

    def test_cannot_start_from_queued_directly(self, base_task):
        with pytest.raises(ValueError, match="Invalid task transition"):
            base_task.start()


class TestScanTaskCompleteTransition:
    def _make_running(self, task):
        task.dispatch(uuid.uuid4())
        task.start()
        return task

    def test_complete_stores_result(self, base_task):
        self._make_running(base_task)
        result = {"ports": [80, 443], "os": "Linux"}
        base_task.complete(result)
        assert base_task.status == TaskStatus.COMPLETED
        assert base_task.result == result
        assert base_task.completed_at is not None

    def test_is_terminal_after_complete(self, base_task):
        self._make_running(base_task)
        base_task.complete({})
        assert base_task.is_terminal is True

    def test_execution_duration_computed(self, base_task):
        self._make_running(base_task)
        base_task.complete({})
        assert base_task.execution_duration_ms is not None
        assert base_task.execution_duration_ms >= 0

    def test_cannot_complete_from_queued(self, base_task):
        with pytest.raises(ValueError, match="Invalid task transition"):
            base_task.complete({})


class TestScanTaskFailTransition:
    def _make_running(self, task):
        task.dispatch(uuid.uuid4())
        task.start()
        return task

    def test_fail_stores_error(self, base_task):
        self._make_running(base_task)
        base_task.fail("timeout", "TIMEOUT_ERROR")
        assert base_task.status == TaskStatus.FAILED
        assert base_task.error_message == "timeout"
        assert base_task.last_error_code == "TIMEOUT_ERROR"
        assert base_task.is_terminal is True

    def test_can_fail_from_queued_directly(self, base_task):
        # Valid per state machine
        base_task.fail("pre-flight check failed")
        assert base_task.status == TaskStatus.FAILED


class TestScanTaskRetryTransition:
    def _make_failed(self, task):
        task.dispatch(uuid.uuid4())
        task.start()
        task.fail("transient error")
        return task

    def test_mark_retrying_sets_timestamp(self, base_task):
        self._make_failed(base_task)
        retry_at = datetime.now(tz=timezone.utc)
        base_task.mark_retrying(retry_at)
        assert base_task.status == TaskStatus.RETRYING
        assert base_task.next_retry_at == retry_at
        assert base_task.error_message is None

    def test_requeue_from_retrying(self, base_task):
        self._make_failed(base_task)
        base_task.mark_retrying(datetime.now(tz=timezone.utc))
        base_task.requeue()
        assert base_task.status == TaskStatus.QUEUED
        assert base_task.assigned_worker_id is None
        assert base_task.dispatched_at is None


class TestScanTaskDLQTransition:
    def test_move_to_dlq_from_failed(self, base_task):
        base_task.dispatch(uuid.uuid4())
        base_task.start()
        base_task.fail("permanent failure")
        base_task.move_to_dlq()
        assert base_task.status == TaskStatus.DLQ
        assert base_task.is_terminal is True

    def test_cannot_transition_from_dlq(self, base_task):
        base_task.fail("failed")
        base_task.move_to_dlq()
        with pytest.raises(ValueError, match="Invalid task transition"):
            base_task.dispatch(uuid.uuid4())


class TestScanTaskCanRetry:
    def test_can_retry_when_below_max_attempts(self, base_task):
        base_task.attempt_count = 2
        base_task.max_attempts = 3
        assert base_task.can_retry is True

    def test_cannot_retry_when_at_max_attempts(self, base_task):
        base_task.attempt_count = 3
        base_task.max_attempts = 3
        assert base_task.can_retry is False

    def test_cannot_retry_when_above_max_attempts(self, base_task):
        base_task.attempt_count = 5
        base_task.max_attempts = 3
        assert base_task.can_retry is False


class TestInvalidTransitions:
    @pytest.mark.parametrize("bad_target", [
        TaskStatus.RUNNING,
        TaskStatus.COMPLETED,
        TaskStatus.DLQ,
    ])
    def test_queued_cannot_go_to_invalid_states(self, base_task, bad_target):
        with pytest.raises(ValueError, match="Invalid task transition"):
            base_task._transition_to(bad_target)
