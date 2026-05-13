"""ValidationResult entity — immutable output of the 5-stage validation pipeline."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from cves_db.types import uuid7

from cves_event_schemas.eve.eve_events import ValidationVerdict
from exposure_validation.domain.value_objects.middleware_findings import MiddlewareFindings
from exposure_validation.domain.value_objects.parser_findings import ParserFindings
from exposure_validation.domain.value_objects.poc_result import PoCResult
from exposure_validation.domain.value_objects.reachability_probe import ReachabilityProbeResult


@dataclass(frozen=True)
class ValidationResult:
    result_id: str
    job_id: str
    verdict: ValidationVerdict
    final_confidence: float
    reachability_probe: ReachabilityProbeResult
    middleware_findings: MiddlewareFindings
    parser_findings: ParserFindings
    poc_result: PoCResult
    signal_count: int
    correlation_count: int
    stages_passed: tuple[str, ...]
    created_at: datetime

    @classmethod
    def create(
        cls,
        *,
        job_id: str,
        verdict: ValidationVerdict,
        final_confidence: float,
        reachability_probe: ReachabilityProbeResult,
        middleware_findings: MiddlewareFindings,
        parser_findings: ParserFindings,
        poc_result: PoCResult,
        signal_count: int,
        correlation_count: int,
        stages_passed: tuple[str, ...],
    ) -> "ValidationResult":
        return cls(
            result_id=str(uuid7()),
            job_id=job_id,
            verdict=verdict,
            final_confidence=final_confidence,
            reachability_probe=reachability_probe,
            middleware_findings=middleware_findings,
            parser_findings=parser_findings,
            poc_result=poc_result,
            signal_count=signal_count,
            correlation_count=correlation_count,
            stages_passed=stages_passed,
            created_at=datetime.now(UTC),
        )

    @property
    def evidence_count(self) -> int:
        count = 0
        if self.reachability_probe.is_reachable:
            count += 1
        if self.middleware_findings.score < 0.5:
            count += 1
        if self.parser_findings.has_reflected_input:
            count += 1
        if self.parser_findings.has_stack_trace:
            count += 1
        if self.parser_findings.has_json_error_leak:
            count += 1
        if self.poc_result.triggered:
            count += 1
        if self.correlation_count >= 2:
            count += 1
        return count
