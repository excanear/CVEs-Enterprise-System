"""Application entrypoint for scan-orchestrator.

Wires together all infrastructure components and starts FastAPI + background workers.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os

import redis.asyncio as aioredis
from fastapi import FastAPI

from cves_db.rls import install_rls_hook
from cves_db.session import AsyncSessionFactory
from cves_observability.health import HealthRouter
from cves_observability.logging import setup_logging
from cves_observability.tracing import setup_tracing

from scan_orchestrator.application.adaptive_rate_limiter import AdaptiveRateLimiter
from scan_orchestrator.application.scan_orchestration_service import ScanOrchestrationService
from scan_orchestrator.application.worker_pool_manager import WorkerPoolManager
from scan_orchestrator.infrastructure.circuit_breaker import CircuitBreaker
from scan_orchestrator.infrastructure.persistence.scan_repository import (
    PostgresScanRepository,
    PostgresScanTaskRepository,
)
from scan_orchestrator.infrastructure.queue.redis_scan_queue import RedisScanQueue
from scan_orchestrator.infrastructure.scheduler.distributed_scheduler import DistributedScheduler
from scan_orchestrator.infrastructure.workers.watchdog import WorkerWatchdog
from scan_orchestrator.interface.api.router import router

SERVICE_NAME = "scan-orchestrator"
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "0.1.0")

setup_logging(log_level=os.getenv("LOG_LEVEL", "INFO"), service_name=SERVICE_NAME)
setup_tracing(
    service_name=SERVICE_NAME,
    service_version=SERVICE_VERSION,
    otlp_endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317"),
    environment=os.getenv("ENV", "production"),
)

logger = logging.getLogger(SERVICE_NAME)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Infrastructure wiring ──
    db_url = os.environ["DATABASE_URL"]
    redis_url = os.environ["REDIS_URL"]

    session_factory = AsyncSessionFactory.from_url(db_url)
    install_rls_hook(session_factory._engine)  # type: ignore[attr-defined]

    redis_client = aioredis.from_url(redis_url, decode_responses=True)

    async with session_factory.session() as session:
        scan_repo = PostgresScanRepository(session)
        task_repo = PostgresScanTaskRepository(session)

        worker_pool = WorkerPoolManager()
        rate_limiter = AdaptiveRateLimiter(redis=redis_client)
        circuit_breaker = CircuitBreaker(redis=redis_client)
        scan_queue = RedisScanQueue(redis=redis_client)

        orchestration_svc = ScanOrchestrationService(
            scan_repo=scan_repo,
            task_repo=task_repo,
            scan_queue=scan_queue,
            event_publisher=None,   # wire real publisher post-Kafka setup
            worker_pool=worker_pool,
        )

        async def _scheduler_fire(job_id: str, payload: dict) -> None:
            from cves_db.types import uuid7
            from scan_orchestrator.application.commands import SubmitScanCommand
            from scan_orchestrator.domain.entities.scan import ScanPriority, ScanType
            from scan_orchestrator.domain.value_objects.scan_config import ScanConfig

            cmd = SubmitScanCommand(
                tenant_id=payload["tenant_id"],
                scan_type=ScanType(payload["scan_type"]),
                targets=payload["targets"],
                priority=ScanPriority(payload.get("priority", "NORMAL")),
                initiated_by=f"scheduler:{job_id}",
                correlation_id=uuid7(),
                config=ScanConfig.from_dict(payload.get("config", {})),
            )
            await orchestration_svc.submit_scan(cmd)

        scheduler = DistributedScheduler(redis=redis_client, fire_callback=_scheduler_fire)
        watchdog = WorkerWatchdog(redis=redis_client, queue=scan_queue)

        # Attach to app state so router deps can resolve
        app.state.orchestration_svc = orchestration_svc
        app.state.worker_pool = worker_pool
        app.state.scan_queue = scan_queue
        app.state.scheduler = scheduler

        await scan_queue.start_delayed_mover()
        await scheduler.start()
        await watchdog.start()

        logger.info("scan-orchestrator.started")
        yield

        # ── Shutdown ──
        await scheduler.stop()
        await watchdog.stop()
        await redis_client.aclose()
        await session_factory.close()
        logger.info("scan-orchestrator.stopped")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Scan Orchestrator",
        version=SERVICE_VERSION,
        docs_url="/docs",
        lifespan=lifespan,
    )

    health = HealthRouter(service_name=SERVICE_NAME, version=SERVICE_VERSION, checks={})
    app.include_router(router)
    app.include_router(health.build())
    return app


app = create_app()
