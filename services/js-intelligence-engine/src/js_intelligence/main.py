"""JS Intelligence Engine — FastAPI application entry point.

Lifecycle:
1. Initialize TreeSitterJSParser (loads grammar once)
2. Wire PostgreSQL session factory
3. Wire repositories + Kafka producer (graceful degradation)
4. Expose FastAPI app with lifespan context manager
"""
from __future__ import annotations

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

from js_intelligence.application.js_intelligence_service import JSIntelligenceService
from js_intelligence.infrastructure.ast.tree_sitter_parser import TreeSitterJSParser
from js_intelligence.infrastructure.kafka.event_publisher import (
    KafkaJSIntelligenceEventPublisher,
)
from js_intelligence.infrastructure.persistence.job_repository import (
    PostgresJSAnalysisJobRepository,
    PostgresJSIntelligenceResultRepository,
)
from js_intelligence.interface.api.router import router

log = structlog.get_logger(__name__)

# ── Settings ──────────────────────────────────────────────────────────────────

_DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://cves:cves_secret@localhost:5432/cves_platform",
)
_KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
_SERVICE_NAME = "js-intelligence-engine"


# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    setup_logging(service_name=_SERVICE_NAME)
    setup_tracing(service_name=_SERVICE_NAME)
    log.info("js_intelligence.starting")

    # Initialize tree-sitter grammar (CPU-bound — done once at startup)
    TreeSitterJSParser.initialize()
    log.info("js_intelligence.tree_sitter_ready")

    # Database
    db_factory = AsyncSessionFactory.from_url(_DATABASE_URL)
    app.state.db_factory = db_factory

    # Repositories
    job_repo = PostgresJSAnalysisJobRepository(db_factory.session_maker)
    result_repo = PostgresJSIntelligenceResultRepository(db_factory.session_maker)
    app.state.job_repo = job_repo
    app.state.result_repo = result_repo

    # Kafka producer (optional — graceful degradation)
    kafka_producer = None
    try:
        from cves_kafka_client.producer import BaseKafkaProducer

        kafka_producer = BaseKafkaProducer.from_config(
            bootstrap_servers=_KAFKA_BOOTSTRAP,
            transactional_id=f"{_SERVICE_NAME}-producer",
        )
        await kafka_producer.start()
        log.info("js_intelligence.kafka.connected")
    except Exception as exc:
        log.warning("js_intelligence.kafka.unavailable", error=str(exc))

    event_publisher = (
        KafkaJSIntelligenceEventPublisher(kafka_producer)
        if kafka_producer
        else _NoopPublisher()
    )
    app.state.event_publisher = event_publisher

    # Application service
    app.state.js_intelligence_service = JSIntelligenceService(
        job_repo=job_repo,
        result_repo=result_repo,
        event_publisher=event_publisher,
    )

    log.info("js_intelligence.started")
    yield

    # Shutdown
    log.info("js_intelligence.stopping")
    if kafka_producer:
        await kafka_producer.stop()
    await db_factory.dispose()
    log.info("js_intelligence.stopped")


# ── App ───────────────────────────────────────────────────────────────────────


def create_app() -> FastAPI:
    app = FastAPI(
        title="JS Intelligence Engine",
        description=(
            "Static JavaScript bundle analysis: AST traversal, source map reconstruction, "
            "route inference, webpack/vite analysis, and dependency graphing."
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
        "js_intelligence.main:app",
        host="0.0.0.0",
        port=8005,
        reload=False,
    )


# ── Noop publisher (fallback when Kafka is unavailable) ───────────────────────


class _NoopPublisher:
    async def publish_result(self, job: object, result: object) -> None:  # type: ignore[override]
        log.debug("js_intelligence.noop_publisher")
