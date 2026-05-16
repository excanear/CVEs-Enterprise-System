"""Exposure Validation Engine — FastAPI application entrypoint.

Lifecycle:
1. AsyncSessionFactory → PostgreSQL
2. Repositories wired
3. Redis client (required for correlation stage)
4. HTTPProber (shared across validators)
5. Kafka producer (graceful degradation)
6. Kafka consumer (background asyncio.to_thread loop)
7. ExposureValidationService wired
8. FastAPI started on port 8006
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

import redis.asyncio as aioredis
import structlog
import uvicorn
from fastapi import FastAPI

from cves_db.session import AsyncSessionFactory
from cves_observability.health import HealthRouter
from cves_observability.instrumentation import instrument_app
from cves_observability.logging import setup_logging
from cves_observability.tracing import setup_tracing

from exposure_validation.application.exposure_validation_service import (
    ExposureValidationService,
)
from exposure_validation.infrastructure.kafka.event_publisher import (
    KafkaEVEEventPublisher,
)
from exposure_validation.infrastructure.kafka.signal_consumer import KafkaSignalConsumer
from exposure_validation.infrastructure.persistence.validation_repository import (
    PostgresValidationJobRepository,
    PostgresValidationResultRepository,
)
from exposure_validation.interface.api.router import router

log = structlog.get_logger(__name__)

# ── Settings ──────────────────────────────────────────────────────────────────

_DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://cves:cves_secret@localhost:5432/cves_platform",
)
_KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
_SERVICE_NAME = "exposure-validation-engine"


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    setup_logging(service_name=_SERVICE_NAME)
    setup_tracing(service_name=_SERVICE_NAME)
    log.info("eve.starting")

    # Database
    db_factory = AsyncSessionFactory.from_url(_DATABASE_URL)
    app.state.db_factory = db_factory

    # Repositories
    job_repo = PostgresValidationJobRepository(db_factory.session_maker)
    result_repo = PostgresValidationResultRepository(db_factory.session_maker)
    app.state.job_repo = job_repo
    app.state.result_repo = result_repo

    # Redis (required for correlation stage)
    redis_client = aioredis.from_url(_REDIS_URL, decode_responses=False)
    app.state.redis = redis_client

    # Kafka producer (optional — graceful degradation)
    kafka_producer = None
    try:
        from cves_kafka_client.producer import BaseKafkaProducer

        kafka_producer = BaseKafkaProducer.from_config(
            bootstrap_servers=_KAFKA_BOOTSTRAP,
            transactional_id=f"{_SERVICE_NAME}-producer",
        )
        await kafka_producer.start()
        log.info("eve.kafka.producer_connected")
    except Exception as exc:
        log.warning("eve.kafka.producer_unavailable", error=str(exc))

    event_publisher = (
        KafkaEVEEventPublisher(kafka_producer) if kafka_producer else _NoopPublisher()
    )
    app.state.event_publisher = event_publisher

    # Application service
    eve_service = ExposureValidationService(
        job_repo=job_repo,
        result_repo=result_repo,
        event_publisher=event_publisher,
        redis_client=redis_client,
    )
    app.state.eve_service = eve_service

    # Kafka consumer (optional — background thread polling upstream topics)
    consumer_task: asyncio.Task | None = None
    if kafka_producer:
        try:
            consumer = KafkaSignalConsumer(bootstrap_servers=_KAFKA_BOOTSTRAP)
            app.state.consumer = consumer

            async def _consumer_wrapper() -> None:
                await consumer.start_consuming(eve_service.handle_kafka_signal)

            consumer_task = asyncio.create_task(_consumer_wrapper())
            log.info("eve.kafka.consumer_started")
        except Exception as exc:
            log.warning("eve.kafka.consumer_unavailable", error=str(exc))

    log.info("eve.started")
    yield

    # ── Shutdown ───────────────────────────────────────────────────────────
    log.info("eve.stopping")
    if consumer_task:
        consumer = getattr(app.state, "consumer", None)
        if consumer:
            await consumer.stop()
        consumer_task.cancel()
    if kafka_producer:
        await kafka_producer.stop()
    await redis_client.aclose()
    await db_factory.dispose()
    log.info("eve.stopped")


# ── App ───────────────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="Exposure Validation Engine",
        description=(
            "Reduces false positives from upstream engines via a 5-stage pipeline: "
            "Detection → Inference → Correlation → Validation → Confirmation. "
            "Emits validated TRUE_POSITIVE exposures as domain events."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(router)
    app.include_router(HealthRouter(service_name=_SERVICE_NAME).router)
    instrument_app(app, service_name=_SERVICE_NAME)
    return app


app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "exposure_validation.main:app",
        host="0.0.0.0",
        port=8006,
        reload=False,
    )


# ── Noop publisher (fallback when Kafka is unavailable) ───────────────────────

class _NoopPublisher:
    async def publish_result(self, job: object, result: object) -> None:
        log.debug("eve.noop_publisher.skipped", job_id=getattr(job, "job_id", "?"))
