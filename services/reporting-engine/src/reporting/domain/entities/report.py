"""Report — aggregate root for the reporting lifecycle."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class ReportType(str, Enum):
    EXECUTIVE = "EXECUTIVE"
    TECHNICAL = "TECHNICAL"
    EVIDENCE_EXPORT = "EVIDENCE_EXPORT"
    REMEDIATION = "REMEDIATION"
    COMPLIANCE = "COMPLIANCE"


class ReportFormat(str, Enum):
    JSON = "JSON"
    HTML = "HTML"
    PDF = "PDF"
    CSV = "CSV"


class ReportStatus(str, Enum):
    PENDING = "PENDING"
    GENERATING = "GENERATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass
class Report:
    """Aggregate root: one generated report artifact."""

    report_id: str
    tenant_id: str
    report_type: ReportType
    report_format: ReportFormat
    status: ReportStatus = ReportStatus.PENDING
    finding_count: int = 0
    content: str | None = None        # JSON / HTML / CSV text
    content_bytes: bytes | None = None  # PDF binary
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    generated_at: datetime | None = None

    def mark_generating(self) -> None:
        self.status = ReportStatus.GENERATING

    def complete(self, content: str | None, content_bytes: bytes | None, finding_count: int) -> None:
        self.status = ReportStatus.COMPLETED
        self.content = content
        self.content_bytes = content_bytes
        self.finding_count = finding_count
        self.generated_at = datetime.now(UTC)

    def fail(self, error: str) -> None:
        self.status = ReportStatus.FAILED
        self.error = error
        self.generated_at = datetime.now(UTC)
