"""ExposureValidationService — orchestrates the 5-stage pipeline.

Entry points:
  validate(cmd)             — runs the full pipeline for one command, returns job_id
  handle_kafka_signal(env)  — processes an upstream Kafka event, dispatches validate()
"""
from __future__ import annotations

import asyncio
from typing import Any

import redis.asyncio as aioredis
import structlog

from cves_db.types import uuid7
from cves_event_schemas.envelope import DomainEventEnvelope

from exposure_validation.application.commands import ValidateExposureCommand
from exposure_validation.application.pipeline.stage1_detection import DetectionStage
from exposure_validation.application.pipeline.stage2_inference import InferenceStage
from exposure_validation.application.pipeline.stage3_correlation import CorrelationStage
from exposure_validation.application.pipeline.stage4_validation import ValidationStage
from exposure_validation.application.pipeline.stage5_confirmation import ConfirmationStage
from exposure_validation.domain.entities.validation_job import ValidationJob
from exposure_validation.domain.entities.validation_result import ValidationResult
from exposure_validation.domain.ports import (
    ExposureEventPublisher,
    ValidationJobRepository,
    ValidationResultRepository,
)
from exposure_validation.infrastructure.fetcher.http_prober import HTTPProber

log = structlog.get_logger(__name__)


class ExposureValidationService:
    def __init__(
        self,
        job_repo: ValidationJobRepository,
        result_repo: ValidationResultRepository,
        event_publisher: ExposureEventPublisher,
        redis_client: aioredis.Redis,
    ) -> None:
        self._job_repo = job_repo
        self._result_repo = result_repo
        self._publisher = event_publisher
        self._redis = redis_client

    async def validate(self, cmd: ValidateExposureCommand) -> str:
        """Run the full 5-stage pipeline. Returns job_id."""
        from cves_event_schemas.eve.eve_events import ExposureType

        # ── Create job in PENDING state ──────────────────────────────────
        job = ValidationJob.create(
            tenant_id=cmd.tenant_id,
            target_url=cmd.target_url,
            correlation_id=cmd.correlation_id or str(uuid7()),
            exposure_type=cmd.exposure_type,
            options={
                "signal_source": cmd.signal_source,
                "endpoint_path": cmd.endpoint_path,
                "method": cmd.method,
                "param_names": list(cmd.param_names),
                "timeout_seconds": cmd.timeout_seconds,
            },
        )
        await self._job_repo.save(job)

        try:
            async with asyncio.timeout(cmd.timeout_seconds):
                await self._run_pipeline(job, cmd)
        except TimeoutError:
            job.fail("Validation timed out")
            await self._job_repo.save(job)
            log.warning("eve.service.timeout", job_id=job.job_id)
        except Exception as exc:
            job.fail(str(exc))
            await self._job_repo.save(job)
            log.error("eve.service.failed", job_id=job.job_id, error=str(exc))

        return job.job_id

    async def _run_pipeline(
        self, job: ValidationJob, cmd: ValidateExposureCommand
    ) -> None:
        job.start()
        await self._job_repo.save(job)

        # ── Stage 2: Inference ───────────────────────────────────────────
        from exposure_validation.domain.value_objects.exposure_candidate import ExposureCandidate

        candidate = ExposureCandidate(
            tenant_id=cmd.tenant_id,
            target_url=cmd.target_url,
            exposure_type=cmd.exposure_type,
            signal_source=cmd.signal_source,
            endpoint_path=cmd.endpoint_path,
            method=cmd.method,
            param_names=cmd.param_names,
            confidence_hint=cmd.confidence_hint,
            raw_signals=cmd.raw_signals,
        )

        inference_score = InferenceStage.score(candidate)
        if inference_score < 0:
            # Below noise floor — fail fast as FALSE_POSITIVE
            from cves_event_schemas.eve.eve_events import ValidationVerdict
            from exposure_validation.domain.value_objects.middleware_findings import MiddlewareFindings
            from exposure_validation.domain.value_objects.parser_findings import ParserFindings
            from exposure_validation.domain.value_objects.poc_result import PoCResult
            from exposure_validation.domain.value_objects.reachability_probe import ReachabilityProbeResult

            result = ValidationResult.create(
                job_id=job.job_id,
                verdict=ValidationVerdict.FALSE_POSITIVE,
                final_confidence=0.0,
                reachability_probe=ReachabilityProbeResult.unreachable(candidate.full_url, "filtered_by_inference"),
                middleware_findings=MiddlewareFindings(),
                parser_findings=ParserFindings(),
                poc_result=PoCResult.no_probe(),
                signal_count=len(cmd.raw_signals),
                correlation_count=0,
                stages_passed=("detection", "inference"),
            )
            await self._result_repo.save(result)
            job.complete(result.result_id, {"verdict": "FALSE_POSITIVE", "fast_path": True})
            await self._job_repo.save(job)
            await self._publisher.publish_result(job, result)
            return

        # ── Stage 3: Correlation ─────────────────────────────────────────
        correlation_count = await CorrelationStage.correlate(candidate, self._redis)
        inference_score = CorrelationStage.apply_bonus(inference_score, correlation_count)

        # ── Stage 4: Validation (parallel probes) ────────────────────────
        async with HTTPProber() as prober:
            reachability, middleware, parser, poc = await ValidationStage.validate(
                candidate, prober
            )

        # ── Stage 5: Confirmation ────────────────────────────────────────
        verdict, final_confidence, stages_passed = ConfirmationStage.confirm(
            reachability=reachability,
            middleware=middleware,
            parser=parser,
            poc=poc,
            inference_score=inference_score,
            correlation_count=correlation_count,
        )

        result = ValidationResult.create(
            job_id=job.job_id,
            verdict=verdict,
            final_confidence=final_confidence,
            reachability_probe=reachability,
            middleware_findings=middleware,
            parser_findings=parser,
            poc_result=poc,
            signal_count=len(cmd.raw_signals),
            correlation_count=correlation_count,
            stages_passed=tuple(stages_passed),
        )

        await self._result_repo.save(result)
        job.complete(
            result.result_id,
            {
                "verdict": verdict.value,
                "final_confidence": final_confidence,
                "stages_passed": stages_passed,
                "poc_triggered": poc.triggered,
            },
        )
        await self._job_repo.save(job)
        await self._publisher.publish_result(job, result)

    async def handle_kafka_signal(
        self, envelope: DomainEventEnvelope
    ) -> None:
        """Entry point for the Kafka consumer callback.

        Routes the upstream event through Stage 1 (Detection), and if it
        produces a candidate, submits a validation job asynchronously.
        """
        candidate = DetectionStage.process(envelope)
        if candidate is None:
            return

        log.info(
            "eve.signal.received",
            event_type=envelope.event_type,
            exposure_type=candidate.exposure_type.value,
            endpoint=candidate.full_url,
        )

        cmd = ValidateExposureCommand(
            tenant_id=candidate.tenant_id,
            target_url=candidate.target_url,
            exposure_type=candidate.exposure_type,
            signal_source=candidate.signal_source,
            endpoint_path=candidate.endpoint_path,
            method=candidate.method,
            param_names=candidate.param_names,
            confidence_hint=candidate.confidence_hint,
            raw_signals=candidate.raw_signals,
            correlation_id=str(envelope.correlation_id),
        )

        # Fire-and-forget; pipeline runs in background
        asyncio.create_task(self.validate(cmd))
