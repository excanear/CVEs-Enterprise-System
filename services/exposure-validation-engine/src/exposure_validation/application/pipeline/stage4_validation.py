"""Stage 4 — Validation: runs all 4 validators in parallel.

Dispatches to:
  - ReachabilityValidator (httpx + optional Playwright)
  - MiddlewareValidator (header analysis)
  - ParserValidator (body risk analysis + reflection)
  - PoCValidator (safe probes: timing, reflection, CORS, header injection)
"""
from __future__ import annotations

import asyncio

import structlog

from exposure_validation.domain.value_objects.exposure_candidate import ExposureCandidate
from exposure_validation.domain.value_objects.middleware_findings import MiddlewareFindings
from exposure_validation.domain.value_objects.parser_findings import ParserFindings
from exposure_validation.domain.value_objects.poc_result import PoCResult
from exposure_validation.domain.value_objects.reachability_probe import ReachabilityProbeResult
from exposure_validation.infrastructure.fetcher.http_prober import HTTPProber

from exposure_validation.application.validators.middleware_validator import MiddlewareValidator
from exposure_validation.application.validators.parser_validator import ParserValidator
from exposure_validation.application.validators.poc_validator import PoCValidator
from exposure_validation.application.validators.reachability_validator import ReachabilityValidator

log = structlog.get_logger(__name__)


class ValidationStage:
    @staticmethod
    async def validate(
        candidate: ExposureCandidate,
        prober: HTTPProber,
    ) -> tuple[ReachabilityProbeResult, MiddlewareFindings, ParserFindings, PoCResult]:
        """Run all 4 validators in parallel and return their results."""
        url = candidate.full_url

        reach_task = ReachabilityValidator.check(candidate, prober)
        middleware_task = MiddlewareValidator.analyze(url, prober)
        parser_task = ParserValidator.analyze(candidate, prober)
        poc_task = PoCValidator.probe(candidate, prober)

        reachability, middleware, parser, poc = await asyncio.gather(
            reach_task,
            middleware_task,
            parser_task,
            poc_task,
            return_exceptions=False,
        )

        log.debug(
            "eve.stage4.complete",
            url=url,
            reachable=reachability.is_reachable,
            middleware_score=middleware.score,
            parser_risk=parser.risk_score,
            poc_triggered=poc.triggered,
        )

        return reachability, middleware, parser, poc
