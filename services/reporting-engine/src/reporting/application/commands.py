"""Typed commands for the Reporting Engine application layer."""
from __future__ import annotations

from dataclasses import dataclass, field

from reporting.domain.entities.report import ReportFormat, ReportType


@dataclass(frozen=True)
class GenerateReportCommand:
    tenant_id: str
    report_type: ReportType
    report_format: ReportFormat
    requested_by: str = "api"


@dataclass(frozen=True)
class GetReportCommand:
    tenant_id: str
    report_id: str


@dataclass(frozen=True)
class DownloadReportCommand:
    tenant_id: str
    report_id: str


@dataclass(frozen=True)
class ListReportsCommand:
    tenant_id: str
    limit: int = 50
    offset: int = 0


@dataclass(frozen=True)
class ExecutiveSummaryCommand:
    tenant_id: str


@dataclass(frozen=True)
class ComplianceMappingCommand:
    tenant_id: str


@dataclass(frozen=True)
class EvidenceExportCommand:
    tenant_id: str


@dataclass(frozen=True)
class RemediationGuidanceCommand:
    tenant_id: str
