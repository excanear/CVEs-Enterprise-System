"""Reporting Engine — domain event schemas.

Topic: re.report.events
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

RE_REPORT_TOPIC = "re.report.events"

RE_EVENT_TYPES: dict[str, str] = {
    "report_generated": "re.report.generated",
}


class _REBase(BaseModel):
    model_config = ConfigDict(frozen=True)


class ReportGeneratedPayload(_REBase):
    """Emitted when a report is successfully generated."""

    report_id: str
    tenant_id: str
    report_type: str   # EXECUTIVE | TECHNICAL | EVIDENCE_EXPORT | REMEDIATION | COMPLIANCE
    report_format: str  # JSON | HTML | PDF | CSV
    finding_count: int
    generated_at: str  # ISO 8601
