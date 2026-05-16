"""Reporting Engine — FastAPI entrypoint.

Lifecycle:
1. PostgreSQL (AsyncSessionFactory) → PGReportingRepository
2. Kafka producer (graceful degradation) → KafkaREEventPublisher
3. ReportingService wired with repo, evidence store, publisher
4. Kafka ACL consumer background task (asyncio.to_thread)
5. FastAPI on port 8009
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
import uvicorn
from fastapi import FastAPI

from cves_db.session import AsyncSessionFactory
from cves_observability.health import HealthRouter
from cves_observability.instrumentation import instrument_app
from cves_observability.logging import setup_logging
from cves_observability.tracing import setup_tracing

from reporting.application.reporting_service import ReportingService
from reporting.infrastructure.kafka.event_publisher import KafkaREEventPublisher
from reporting.infrastructure.kafka.signal_consumer import KafkaRESignalConsumer
from reporting.infrastructure.persistence.report_repository import PGReportingRepository
from reporting.interface.api.router import router

log = structlog.get_logger(__name__)

# ── Settings ──────────────────────────────────────────────────────────────────

_DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://cves:cves_secret@localhost:5432/cves_platform",
)
_KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
_SERVICE_NAME = "reporting-engine"


# ── Noop publisher (Kafka unavailable fallback) ────────────────────────────────

class _NoopPublisher:
    async def publish_report_generated(self, report) -> None:  # type: ignore[no-untyped-def]
        pass


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    setup_logging(service_name=_SERVICE_NAME)
    setup_tracing(service_name=_SERVICE_NAME)
    log.info("re.starting")

    # PostgreSQL
    db_factory = AsyncSessionFactory.from_url(_DATABASE_URL)
    app.state.db_factory = db_factory
    repo = PGReportingRepository(db_factory.session_maker)

    # Kafka producer (graceful degradation)
    kafka_producer = None
    publisher: object = _NoopPublisher()
    try:
        from cves_kafka_client.producer import BaseKafkaProducer

        kafka_producer = BaseKafkaProducer(bootstrap_servers=_KAFKA_BOOTSTRAP)
        publisher = KafkaREEventPublisher(kafka_producer)  # type: ignore[assignment]
        log.info("re.kafka.producer.ready")
    except Exception as exc:
        log.warning("re.kafka.producer.unavailable", error=str(exc), fallback="noop publisher")

    # Wire service (repo serves as both ReportRepository and EvidenceStore)
    reporting_service = ReportingService(
        repo=repo,  # type: ignore[arg-type]
        evidence=repo,  # type: ignore[arg-type]
        publisher=publisher,  # type: ignore[arg-type]
    )
    app.state.reporting_service = reporting_service

    # Kafka ACL consumer (background)
    consumer = KafkaRESignalConsumer(_KAFKA_BOOTSTRAP)
    consumer_task: asyncio.Task | None = None
    try:
        consumer_task = asyncio.create_task(
            consumer.start(reporting_service.handle_acl_event)
        )
        log.info("re.kafka.consumer.started")
    except Exception as exc:
        log.warning("re.kafka.consumer.unavailable", error=str(exc))

    log.info("re.ready", port=8009)
    yield

    # Shutdown
    consumer.stop()
    if consumer_task and not consumer_task.done():
        consumer_task.cancel()
        try:
            await consumer_task
        except asyncio.CancelledError:
            pass
    if kafka_producer is not None:
        try:
            kafka_producer.flush()
        except Exception:
            pass
    await db_factory.close()
    log.info("re.shutdown")


# ── Application ────────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="Reporting Engine",
        version="0.1.0",
        description="Executive, technical, compliance and evidence reports for CVEs Enterprise System.",
        lifespan=lifespan,
    )
    health_router = HealthRouter(service_name=_SERVICE_NAME, version="0.1.0")
    app.include_router(health_router.router)
    app.include_router(router)
    instrument_app(app, service_name=_SERVICE_NAME)
    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "reporting.main:app",
        host="0.0.0.0",
        port=8009,
        reload=False,
        log_config=None,
    )
