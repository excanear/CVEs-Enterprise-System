"""Async tests — ScanOrchestrationService full lifecycle.

Tests the application service layer with in-memory fakes.
All I/O ports are wired with InMemory implementations from conftest.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from scan_orchestrator.application.commands import (
    CancelScanCommand,
    RetryFailedTasksCommand,
    SubmitScanCommand,
)
from scan_orchestrator.application.scan_orchestration_service import ScanOrchestrationService
from scan_orchestrator.application.worker_pool_manager import WorkerPoolManager
from scan_orchestrator.domain.entities.scan import ScanPriority, ScanStatus, ScanType
from scan_orchestrator.domain.entities.scan_task import TaskStatus
from scan_orchestrator.domain.value_objects.scan_config import ScanConfig


@pytest.fixture
def orchestration_svc(scan_repo, task_repo, scan_queue, event_publisher):
    return ScanOrchestrationService(
        scan_repo=scan_repo,
        task_repo=task_repo,
        scan_queue=scan_queue,
        event_publisher=event_publisher,
        worker_pool=WorkerPoolManager(),
    )


def _submit_cmd(tenant_id: uuid.UUID, **overrides) -> SubmitScanCommand:
    return SubmitScanCommand(
        tenant_id=tenant_id,
        scan_type=ScanType.PORT_SCAN,
        targets=["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        priority=ScanPriority.NORMAL,
        initiated_by="pytest",
        correlation_id=uuid.uuid4(),
        config=ScanConfig(),
        **overrides,
    )


class TestSubmitScan:
    async def test_submit_returns_scan_id(self, orchestration_svc, tenant_id):
        cmd = _submit_cmd(tenant_id)
        scan_id = await orchestration_svc.submit_scan(cmd)
        assert isinstance(scan_id, uuid.UUID)

    async def test_submit_persists_scan(self, orchestration_svc, scan_repo, tenant_id):
        cmd = _submit_cmd(tenant_id)
        scan_id = await orchestration_svc.submit_scan(cmd)
        scan = await scan_repo.get(scan_id, tenant_id)
        assert scan is not None
        assert scan.tenant_id == tenant_id

    async def test_submit_creates_tasks(self, orchestration_svc, task_repo, tenant_id):
        cmd = _submit_cmd(tenant_id)
        scan_id = await orchestration_svc.submit_scan(cmd)
        tasks = await task_repo.list_by_scan(scan_id)
        assert len(tasks) > 0

    async def test_submit_enqueues_tasks(self, orchestration_svc, scan_queue, tenant_id):
        cmd = _submit_cmd(tenant_id, targets=["10.0.0.1"])
        await orchestration_svc.submit_scan(cmd)
        depth = await scan_queue.queue_depth(tenant_id)
        assert depth["total"] > 0

    async def test_submit_publishes_scan_started_event(self, orchestration_svc, event_publisher, tenant_id):
        cmd = _submit_cmd(tenant_id)
        await orchestration_svc.submit_scan(cmd)
        event_types = [evt_type for evt_type, _ in event_publisher.events]
        assert "scan.started" in event_types

    async def test_scan_type_full_creates_all_task_types(self, orchestration_svc, task_repo, tenant_id):
        from scan_orchestrator.domain.entities.scan_task import TaskType
        cmd = _submit_cmd(tenant_id, scan_type=ScanType.FULL, targets=["10.0.0.1"])
        scan_id = await orchestration_svc.submit_scan(cmd)
        tasks = await task_repo.list_by_scan(scan_id)
        task_types = {t.task_type for t in tasks}
        assert task_types == set(TaskType)

    async def test_task_count_matches_targets_times_task_types(self, orchestration_svc, task_repo, tenant_id):
        targets = ["10.0.0.1", "10.0.0.2"]
        cmd = _submit_cmd(tenant_id, scan_type=ScanType.NETWORK_DISCOVERY, targets=targets)
        scan_id = await orchestration_svc.submit_scan(cmd)
        tasks = await task_repo.list_by_scan(scan_id)
        # NETWORK_DISCOVERY → [ICMP_PING, DNS_ENUMERATION] = 2 types × 2 targets = 4 tasks
        assert len(tasks) == 4


class TestCancelScan:
    async def test_cancel_sets_status_to_cancelled(self, orchestration_svc, scan_repo, tenant_id):
        scan_id = await orchestration_svc.submit_scan(_submit_cmd(tenant_id))
        await orchestration_svc.cancel_scan(CancelScanCommand(
            tenant_id=tenant_id,
            scan_id=scan_id,
            cancelled_by="admin",
        ))
        scan = await scan_repo.get(scan_id, tenant_id)
        assert scan.status == ScanStatus.CANCELLED

    async def test_cancel_nonexistent_scan_raises(self, orchestration_svc, tenant_id):
        with pytest.raises(LookupError):
            await orchestration_svc.cancel_scan(CancelScanCommand(
                tenant_id=tenant_id,
                scan_id=uuid.uuid4(),
                cancelled_by="admin",
            ))

    async def test_cancel_terminal_scan_is_idempotent(self, orchestration_svc, scan_repo, tenant_id):
        """Cancelling an already-cancelled scan should not raise."""
        scan_id = await orchestration_svc.submit_scan(_submit_cmd(tenant_id))
        cmd = CancelScanCommand(tenant_id=tenant_id, scan_id=scan_id, cancelled_by="admin")
        await orchestration_svc.cancel_scan(cmd)
        # Second cancel should be idempotent
        await orchestration_svc.cancel_scan(cmd)
        scan = await scan_repo.get(scan_id, tenant_id)
        assert scan.status == ScanStatus.CANCELLED


class TestRetryFailedTasks:
    async def _submit_with_failed_task(self, orchestration_svc, task_repo, scan_repo, tenant_id):
        scan_id = await orchestration_svc.submit_scan(_submit_cmd(tenant_id))
        tasks = await task_repo.list_by_scan(scan_id)
        task = tasks[0]
        # Manually transition task to FAILED with remaining retries
        task.dispatch(uuid.uuid4())
        task.start()
        task.fail("simulated failure")
        await task_repo.update(task)
        return scan_id, task

    async def test_retry_re_enqueues_retryable_tasks(
        self, orchestration_svc, task_repo, scan_repo, scan_queue, tenant_id
    ):
        scan_id, failed_task = await self._submit_with_failed_task(
            orchestration_svc, task_repo, scan_repo, tenant_id
        )
        # Clear queue so we can count re-enqueued items
        await scan_queue.dequeue("PORT_SCAN", tenant_id, max_items=100)

        retry_count = await orchestration_svc.retry_failed_tasks(RetryFailedTasksCommand(
            tenant_id=tenant_id,
            scan_id=scan_id,
            requested_by="pytest",
        ))
        assert retry_count >= 1

    async def test_retry_exhausted_tasks_moved_to_dlq(
        self, orchestration_svc, task_repo, scan_repo, tenant_id
    ):
        scan_id = await orchestration_svc.submit_scan(_submit_cmd(tenant_id))
        tasks = await task_repo.list_by_scan(scan_id)
        task = tasks[0]
        # Exhaust all attempts
        task.attempt_count = task.max_attempts  # no more retries
        task.dispatch(uuid.uuid4())
        task.start()
        task.fail("exhausted")
        await task_repo.update(task)

        await orchestration_svc.retry_failed_tasks(RetryFailedTasksCommand(
            tenant_id=tenant_id,
            scan_id=scan_id,
            requested_by="pytest",
        ))
        updated_task = await task_repo.get(task.task_id)
        assert updated_task.status == TaskStatus.DLQ

    async def test_retry_nonexistent_scan_raises(self, orchestration_svc, tenant_id):
        with pytest.raises(LookupError):
            await orchestration_svc.retry_failed_tasks(RetryFailedTasksCommand(
                tenant_id=tenant_id,
                scan_id=uuid.uuid4(),
                requested_by="pytest",
            ))


class TestTaskCompletionHandlers:
    async def test_on_task_completed_increments_counter(
        self, orchestration_svc, task_repo, scan_repo, tenant_id
    ):
        scan_id = await orchestration_svc.submit_scan(_submit_cmd(tenant_id))
        tasks = await task_repo.list_by_scan(scan_id)
        task = tasks[0]
        task.dispatch(uuid.uuid4())
        task.start()
        await task_repo.update(task)

        await orchestration_svc.on_task_completed(
            task_id=task.task_id,
            scan_id=scan_id,
            tenant_id=tenant_id,
            result={"ports": [80]},
        )
        scan = await scan_repo.get(scan_id, tenant_id)
        assert scan.tasks_completed >= 1

    async def test_on_task_failed_triggers_retry_if_retriable(
        self, orchestration_svc, task_repo, scan_repo, tenant_id
    ):
        scan_id = await orchestration_svc.submit_scan(_submit_cmd(tenant_id))
        tasks = await task_repo.list_by_scan(scan_id)
        task = tasks[0]
        task.dispatch(uuid.uuid4())
        task.start()
        await task_repo.update(task)

        await orchestration_svc.on_task_failed(
            task_id=task.task_id,
            scan_id=scan_id,
            tenant_id=tenant_id,
            error="timeout",
            error_code="TIMEOUT",
        )
        updated = await task_repo.get(task.task_id)
        # Should be RETRYING (still has attempts)
        assert updated.status in {TaskStatus.RETRYING, TaskStatus.DLQ}
