"""Unit tests — SubmitScanCommand validators (Pydantic v2)."""
from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from scan_orchestrator.application.commands import (
    CancelScanCommand,
    RetryFailedTasksCommand,
    SubmitScanCommand,
)
from scan_orchestrator.domain.entities.scan import ScanPriority, ScanType
from scan_orchestrator.domain.value_objects.scan_config import ScanConfig


def _base_cmd(**overrides) -> dict:
    return {
        "tenant_id": uuid.uuid4(),
        "scan_type": ScanType.PORT_SCAN,
        "targets": ["10.0.0.1", "10.0.0.2"],
        "priority": ScanPriority.NORMAL,
        "initiated_by": "pytest",
        "correlation_id": uuid.uuid4(),
        "config": ScanConfig(),
        **overrides,
    }


class TestSubmitScanCommandTargetDeduplication:
    def test_deduplicates_identical_targets(self):
        cmd = SubmitScanCommand(**_base_cmd(targets=["10.0.0.1", "10.0.0.1", "10.0.0.2"]))
        assert cmd.targets == ["10.0.0.1", "10.0.0.2"]

    def test_deduplicates_with_whitespace(self):
        cmd = SubmitScanCommand(**_base_cmd(targets=["10.0.0.1 ", " 10.0.0.1", "10.0.0.2"]))
        assert cmd.targets == ["10.0.0.1", "10.0.0.2"]

    def test_preserves_insertion_order(self):
        cmd = SubmitScanCommand(**_base_cmd(targets=["b.com", "a.com", "c.com", "b.com"]))
        assert cmd.targets == ["b.com", "a.com", "c.com"]

    def test_strips_empty_strings(self):
        cmd = SubmitScanCommand(**_base_cmd(targets=["10.0.0.1", "", "   ", "10.0.0.2"]))
        assert "" not in cmd.targets
        assert "   " not in cmd.targets

    def test_single_target_accepted(self):
        cmd = SubmitScanCommand(**_base_cmd(targets=["192.168.1.1"]))
        assert len(cmd.targets) == 1

    def test_empty_targets_raises(self):
        with pytest.raises(ValidationError):
            SubmitScanCommand(**_base_cmd(targets=[]))

    def test_too_many_targets_raises(self):
        with pytest.raises(ValidationError):
            SubmitScanCommand(**_base_cmd(targets=[f"10.0.{i//256}.{i%256}" for i in range(5001)]))


class TestSubmitScanCommandFields:
    def test_default_priority_is_normal(self):
        cmd = SubmitScanCommand(**_base_cmd())
        assert cmd.priority == ScanPriority.NORMAL

    def test_schedule_cron_defaults_to_none(self):
        cmd = SubmitScanCommand(**_base_cmd())
        assert cmd.schedule_cron is None

    def test_schedule_cron_can_be_set(self):
        cmd = SubmitScanCommand(**_base_cmd(schedule_cron="0 2 * * *"))
        assert cmd.schedule_cron == "0 2 * * *"

    def test_initiated_by_max_length(self):
        with pytest.raises(ValidationError):
            SubmitScanCommand(**_base_cmd(initiated_by="x" * 257))

    def test_all_scan_types_accepted(self):
        for st in ScanType:
            cmd = SubmitScanCommand(**_base_cmd(scan_type=st))
            assert cmd.scan_type == st

    def test_all_priorities_accepted(self):
        for p in ScanPriority:
            cmd = SubmitScanCommand(**_base_cmd(priority=p))
            assert cmd.priority == p


class TestCancelScanCommand:
    def test_valid_cancel_command(self):
        cmd = CancelScanCommand(
            tenant_id=uuid.uuid4(),
            scan_id=uuid.uuid4(),
            cancelled_by="admin",
        )
        assert cmd.cancelled_by == "admin"

    def test_missing_tenant_id_raises(self):
        with pytest.raises(ValidationError):
            CancelScanCommand(scan_id=uuid.uuid4(), cancelled_by="admin")  # type: ignore[call-arg]


class TestRetryFailedTasksCommand:
    def test_valid_retry_command(self):
        cmd = RetryFailedTasksCommand(
            tenant_id=uuid.uuid4(),
            scan_id=uuid.uuid4(),
            requested_by="api",
        )
        assert cmd.requested_by == "api"
