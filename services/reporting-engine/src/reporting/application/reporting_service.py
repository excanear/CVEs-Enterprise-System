"""Reporting Service — application facade.

Orchestrates report generation, evidence buffering (via Kafka event handler),
and synchronous query commands.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import asdict
from datetime import UTC, datetime

import structlog

from cves_event_schemas.envelope import DomainEventEnvelope
from cves_event_schemas.acl.acl_events import ACL_EVENT_TYPES

from reporting.application.commands import (
    ComplianceMappingCommand,
    DownloadReportCommand,
    EvidenceExportCommand,
    ExecutiveSummaryCommand,
    GenerateReportCommand,
    GetReportCommand,
    ListReportsCommand,
    RemediationGuidanceCommand,
)
from reporting.application.compliance.framework_mapper import map_exposures
from reporting.domain.entities.report import Report, ReportFormat, ReportStatus, ReportType
from reporting.domain.ports import EvidenceStore, ReportEventPublisher, ReportRepository
from reporting.infrastructure.rendering import html_renderer, csv_renderer, pdf_renderer

log = structlog.get_logger(__name__)

_TIER_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class ReportingService:
    def __init__(
        self,
        repo: ReportRepository,
        evidence: EvidenceStore,
        publisher: ReportEventPublisher,
    ) -> None:
        self._repo = repo
        self._evidence = evidence
        self._publisher = publisher

    # ── Kafka event ingestion ─────────────────────────────────────────────────

    async def handle_acl_event(self, envelope: DomainEventEnvelope) -> None:
        etype = envelope.event_type
        payload = envelope.payload or {}
        tenant_id = str(envelope.tenant_id)
        session_id = str(envelope.correlation_id)

        try:
            if etype == ACL_EVENT_TYPES["exposure_prioritized"]:
                await self._evidence.upsert_exposure(
                    {
                        "exposure_id": payload.get("exposure_id", str(uuid.uuid4())),
                        "tenant_id": tenant_id,
                        "session_id": session_id,
                        "target_url": payload.get("target_url", ""),
                        "exposure_type": payload.get("exposure_type", ""),
                        "tier": payload.get("tier", "LOW"),
                        "composite_score": float(payload.get("composite_score", 0)),
                        "rationale": payload.get("rationale", ""),
                    }
                )

            elif etype == ACL_EVENT_TYPES["cluster_created"]:
                await self._evidence.upsert_cluster(
                    {
                        "cluster_id": payload.get("cluster_id", str(uuid.uuid4())),
                        "tenant_id": tenant_id,
                        "session_id": session_id,
                        "size": int(payload.get("size", 0)),
                        "tier": payload.get("tier", "LOW"),
                        "host": payload.get("host"),
                        "avg_confidence": float(payload.get("avg_confidence", 0)),
                        "poc_triggered_count": int(payload.get("poc_triggered_count", 0)),
                        "exposure_types": payload.get("exposure_types", []),
                    }
                )

            elif etype == ACL_EVENT_TYPES["remediation_generated"]:
                await self._evidence.upsert_remediation(
                    {
                        "cluster_id": payload.get("cluster_id", str(uuid.uuid4())),
                        "tenant_id": tenant_id,
                        "session_id": session_id,
                        "exposure_type": payload.get("exposure_type", ""),
                        "steps": payload.get("steps", []),
                        "llm_enriched": bool(payload.get("llm_enriched", False)),
                        "llm_narrative": payload.get("llm_narrative"),
                    }
                )

            elif etype == ACL_EVENT_TYPES["path_ranked"]:
                ranked = payload.get("ranked_paths", [])
                await self._evidence.upsert_path(
                    {
                        "path_id": str(uuid.uuid4()),
                        "tenant_id": tenant_id,
                        "session_id": session_id,
                        "paths_json": ranked,
                    }
                )

        except Exception as exc:
            log.warning("re.service.ingest_error", event_type=etype, error=str(exc))

    # ── Report generation ─────────────────────────────────────────────────────

    async def generate_report(self, cmd: GenerateReportCommand) -> Report:
        report = Report(
            report_id=str(uuid.uuid4()),
            tenant_id=cmd.tenant_id,
            report_type=cmd.report_type,
            report_format=cmd.report_format,
        )
        await self._repo.save(report)
        report.mark_generating()
        await self._repo.update(report)

        try:
            content_text, content_bytes, finding_count = await self._build_content(report)
            report.complete(content_text, content_bytes, finding_count)
        except Exception as exc:
            log.error("re.service.generate_failed", report_id=report.report_id, error=str(exc))
            report.fail(str(exc))

        await self._repo.update(report)

        if report.status == ReportStatus.COMPLETED:
            try:
                await self._publisher.publish_report_generated(report)
            except Exception as exc:
                log.warning("re.service.publish_failed", error=str(exc))

        return report

    async def _build_content(
        self, report: Report
    ) -> tuple[str | None, bytes | None, int]:
        tenant_id = report.tenant_id
        rtype = report.report_type
        rfmt = report.report_format

        exposures = await self._evidence.list_exposures(tenant_id)
        clusters = await self._evidence.list_clusters(tenant_id)
        remediations = await self._evidence.list_remediations(tenant_id)
        paths = await self._evidence.list_paths(tenant_id, limit=50)

        finding_count = len(exposures)

        if rfmt == ReportFormat.CSV:
            if rtype == ReportType.REMEDIATION:
                text = csv_renderer.render_remediation_csv(remediations)
            else:
                text = csv_renderer.render_evidence_csv(exposures)
            return text, None, finding_count

        if rfmt == ReportFormat.JSON:
            data = self._build_json_data(rtype, exposures, clusters, remediations, paths, tenant_id)
            return json.dumps(data, indent=2, default=str), None, finding_count

        # HTML / PDF
        html = self._render_html(rtype, tenant_id, exposures, clusters, remediations, paths)

        if rfmt == ReportFormat.PDF:
            pdf_bytes = pdf_renderer.render_pdf(html)
            return None, pdf_bytes, finding_count

        return html, None, finding_count

    def _render_html(
        self,
        rtype: ReportType,
        tenant_id: str,
        exposures: list[dict],
        clusters: list[dict],
        remediations: list[dict],
        paths: list[dict],
    ) -> str:
        data: dict = {
            "exposures": exposures,
            "clusters": clusters,
            "remediations": remediations,
            "paths": paths,
        }
        if rtype == ReportType.EXECUTIVE:
            return html_renderer.render_executive(tenant_id, data)
        if rtype == ReportType.TECHNICAL:
            return html_renderer.render_technical(tenant_id, data)
        if rtype == ReportType.REMEDIATION:
            return html_renderer.render_remediation(tenant_id, data)
        if rtype == ReportType.COMPLIANCE:
            findings = map_exposures(exposures)
            data["compliance_findings"] = [asdict(f) for f in findings]
            return html_renderer.render_compliance(tenant_id, data)
        # EVIDENCE_EXPORT → technical view
        return html_renderer.render_technical(tenant_id, data)

    def _build_json_data(
        self,
        rtype: ReportType,
        exposures: list[dict],
        clusters: list[dict],
        remediations: list[dict],
        paths: list[dict],
        tenant_id: str,
    ) -> dict:
        base = {
            "report_type": rtype.value,
            "tenant_id": tenant_id,
            "generated_at": datetime.now(UTC).isoformat(),
        }
        if rtype == ReportType.EXECUTIVE:
            tier_counts: dict[str, int] = {}
            for e in exposures:
                t = e.get("tier", "LOW")
                tier_counts[t] = tier_counts.get(t, 0) + 1
            top5 = sorted(exposures, key=lambda x: x.get("composite_score", 0), reverse=True)[:5]
            base.update(
                {
                    "total_findings": len(exposures),
                    "total_clusters": len(clusters),
                    "tier_breakdown": tier_counts,
                    "top_findings": top5,
                }
            )
        elif rtype == ReportType.TECHNICAL:
            base.update({"findings": exposures, "attack_paths": paths})
        elif rtype == ReportType.REMEDIATION:
            base.update({"remediations": remediations})
        elif rtype == ReportType.COMPLIANCE:
            findings = map_exposures(exposures)
            base.update({"compliance_findings": [asdict(f) for f in findings]})
        else:
            base.update({"exposures": exposures, "clusters": clusters})
        return base

    # ── Query commands ────────────────────────────────────────────────────────

    async def get_report(self, cmd: GetReportCommand) -> Report | None:
        return await self._repo.get(cmd.report_id)

    async def list_reports(self, cmd: ListReportsCommand) -> list[Report]:
        return await self._repo.list_by_tenant(cmd.tenant_id, cmd.limit, cmd.offset)

    async def get_executive_summary(self, cmd: ExecutiveSummaryCommand) -> dict:
        exposures = await self._evidence.list_exposures(cmd.tenant_id)
        clusters = await self._evidence.list_clusters(cmd.tenant_id)
        tier_counts: dict[str, int] = {}
        for e in exposures:
            t = e.get("tier", "LOW")
            tier_counts[t] = tier_counts.get(t, 0) + 1
        top5 = sorted(exposures, key=lambda x: x.get("composite_score", 0), reverse=True)[:5]
        return {
            "tenant_id": cmd.tenant_id,
            "total_findings": len(exposures),
            "total_clusters": len(clusters),
            "tier_breakdown": tier_counts,
            "top_findings": top5,
            "generated_at": datetime.now(UTC).isoformat(),
        }

    async def get_compliance_mapping(self, cmd: ComplianceMappingCommand) -> list[dict]:
        exposures = await self._evidence.list_exposures(cmd.tenant_id)
        findings = map_exposures(exposures)
        return [asdict(f) for f in findings]

    async def get_evidence_export(self, cmd: EvidenceExportCommand) -> str:
        exposures = await self._evidence.list_exposures(cmd.tenant_id)
        return csv_renderer.render_evidence_csv(exposures)

    async def get_remediation_guidance(self, cmd: RemediationGuidanceCommand) -> list[dict]:
        remediations = await self._evidence.list_remediations(cmd.tenant_id)
        exposures = await self._evidence.list_exposures(cmd.tenant_id)

        tier_map: dict[str, str] = {e.get("exposure_type", ""): e.get("tier", "LOW") for e in exposures}
        result: list[dict] = []
        for r in sorted(
            remediations,
            key=lambda x: _TIER_ORDER.get(tier_map.get(x.get("exposure_type", ""), "LOW"), 99),
        ):
            result.append(
                {
                    "cluster_id": r.get("cluster_id"),
                    "exposure_type": r.get("exposure_type"),
                    "tier": tier_map.get(r.get("exposure_type", ""), "LOW"),
                    "steps": r.get("steps", []),
                    "llm_enriched": r.get("llm_enriched", False),
                    "llm_narrative": r.get("llm_narrative"),
                }
            )
        return result
