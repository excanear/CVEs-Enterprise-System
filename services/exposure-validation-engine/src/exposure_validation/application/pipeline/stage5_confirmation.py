"""Stage 5 — Confirmation: computes the final verdict from all stage outputs.

Scoring formula (additive deltas over inference_score, clamped to [0, 1]):
  +0.20  if reachable (HTTP 2xx/3xx/4xx but not 404/timeout)
  +0.15  if correlation_count >= 2 engines
  +0.10  if middleware.score < 0.5 (many missing security headers)
  +0.20  if parser.has_reflected_input OR has_stack_trace OR has_debug_info
  +0.35  if poc.triggered
  -0.30  if not reachable (hard penalty)

Verdict thresholds:
  >= 0.75  → TRUE_POSITIVE
  <= 0.25  → FALSE_POSITIVE
  else     → REQUIRES_REVIEW
  not_reachable + score < 0.30 → INSUFFICIENT_DATA
"""
from __future__ import annotations

import structlog

from cves_event_schemas.eve.eve_events import ValidationVerdict

from exposure_validation.domain.value_objects.middleware_findings import MiddlewareFindings
from exposure_validation.domain.value_objects.parser_findings import ParserFindings
from exposure_validation.domain.value_objects.poc_result import PoCResult
from exposure_validation.domain.value_objects.reachability_probe import ReachabilityProbeResult

log = structlog.get_logger(__name__)

_TRUE_POSITIVE_THRESHOLD = 0.75
_FALSE_POSITIVE_THRESHOLD = 0.25
_INSUFFICIENT_DATA_THRESHOLD = 0.30


class ConfirmationStage:
    @staticmethod
    def confirm(
        *,
        reachability: ReachabilityProbeResult,
        middleware: MiddlewareFindings,
        parser: ParserFindings,
        poc: PoCResult,
        inference_score: float,
        correlation_count: int,
    ) -> tuple[ValidationVerdict, float, list[str]]:
        """Return (verdict, final_confidence, stages_passed)."""
        score = inference_score
        stages_passed: list[str] = ["detection", "inference"]

        # Correlation bonus
        if correlation_count >= 2:
            score += 0.15
            stages_passed.append("correlation")

        # Reachability
        if reachability.is_reachable:
            score += 0.20
            stages_passed.append("reachability")
        else:
            score -= 0.30

        # Middleware (bad headers = higher risk)
        if middleware.score < 0.5:
            score += 0.10
            stages_passed.append("middleware")

        # Parser risk
        if parser.has_reflected_input or parser.has_stack_trace or parser.has_debug_info:
            score += 0.20
            stages_passed.append("parser")

        # PoC probe
        if poc.triggered:
            score += 0.35
            stages_passed.append("poc")

        final = round(max(0.0, min(score, 1.0)), 4)

        # Verdict
        if not reachability.is_reachable and final < _INSUFFICIENT_DATA_THRESHOLD:
            verdict = ValidationVerdict.INSUFFICIENT_DATA
        elif final >= _TRUE_POSITIVE_THRESHOLD:
            verdict = ValidationVerdict.TRUE_POSITIVE
        elif final <= _FALSE_POSITIVE_THRESHOLD:
            verdict = ValidationVerdict.FALSE_POSITIVE
        else:
            verdict = ValidationVerdict.REQUIRES_REVIEW

        log.info(
            "eve.stage5.verdict",
            verdict=verdict.value,
            final_confidence=final,
            poc_triggered=poc.triggered,
            reachable=reachability.is_reachable,
        )

        return verdict, final, stages_passed
