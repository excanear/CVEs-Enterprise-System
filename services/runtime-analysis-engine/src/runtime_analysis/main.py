"""Runtime Analysis Engine — FastAPI application entry point.

Lifecycle:
1. Start async_playwright → create BrowserPool
2. Wire PostgreSQL session factory
3. Wire repositories + Kafka producer (optional — graceful degradation)
4. Expose FastAPI app with lifespan context manager
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
import uvicorn
from fastapi import FastAPI
from playwright.async_api import async_playwright

from cves_db.session import AsyncSessionFactory
from cves_observability.health import HealthRouter
from cves_observability.instrumentation import instrument_app
from cves_observability.logging import setup_logging
from cves_observability.tracing import setup_tracing

from runtime_analysis.infrastructure.browser.browser_pool import BrowserPool
from runtime_analysis.infrastructure.kafka.event_publisher import (
    KafkaRuntimeEventPublisher,
)
from runtime_analysis.infrastructure.persistence.analysis_repository import (
    PostgresAnalysisResultRepository,
    PostgresAnalysisSessionRepository,
)
from runtime_analysis.interface.api.router import router

log = structlog.get_logger(__name__)

# ── Settings ──────────────────────────────────────────────────────────────────

_DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://cves:cves@localhost:5432/cves",
)
_KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
_BROWSER_POOL_SIZE = int(os.environ.get("BROWSER_POOL_SIZE", "3"))
_SERVICE_NAME = "runtime-analysis-engine"


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    setup_logging(service_name=_SERVICE_NAME)
    setup_tracing(service_name=_SERVICE_NAME)
    log.info("runtime_analysis.starting")

    # Database
    db_factory = AsyncSessionFactory.from_url(_DATABASE_URL)
    app.state.db_factory = db_factory

    # Repositories
    app.state.session_repo = PostgresAnalysisSessionRepository(db_factory.session_maker)
    app.state.result_repo = PostgresAnalysisResultRepository(db_factory.session_maker)

    # Browser pool
    pw = await async_playwright().start()
    pool = BrowserPool(size=_BROWSER_POOL_SIZE)
    await pool.start(pw)
    app.state.browser_pool = pool

    # Kafka producer (optional — graceful degradation if broker unavailable)
    kafka_producer = None
    try:
        from cves_kafka_client.producer import BaseKafkaProducer

        kafka_producer = BaseKafkaProducer.from_config(
            bootstrap_servers=_KAFKA_BOOTSTRAP,
            transactional_id=f"{_SERVICE_NAME}-producer",
        )
        await kafka_producer.start()
        log.info("runtime_analysis.kafka.connected")
    except Exception as exc:
        log.warning("runtime_analysis.kafka.unavailable", error=str(exc))

    event_publisher = KafkaRuntimeEventPublisher(kafka_producer) if kafka_producer else _NoopPublisher()
    app.state.event_publisher = event_publisher

    # Application service
    from runtime_analysis.application.runtime_analysis_service import (
        RuntimeAnalysisService,
    )

    app.state.analysis_service = RuntimeAnalysisService(
        browser_pool=pool,
        session_repo=app.state.session_repo,
        result_repo=app.state.result_repo,
        event_publisher=event_publisher,
    )

    log.info("runtime_analysis.started", pool_size=_BROWSER_POOL_SIZE)
    yield

    # Shutdown
    log.info("runtime_analysis.stopping")
    await pool.stop()
    await pw.stop()
    if kafka_producer:
        await kafka_producer.stop()
    await db_factory.dispose()
    log.info("runtime_analysis.stopped")


# ── App ───────────────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="Runtime Analysis Engine",
        description="Dynamic web application analysis via headless browser instrumentation",
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
        "runtime_analysis.main:app",
        host="0.0.0.0",
        port=8004,
        reload=False,
    )


# ── Noop publisher (fallback when Kafka is unavailable) ───────────────────────

class _NoopPublisher:
    async def publish_result(self, session, result) -> None:  # type: ignore[override]
        log.debug(
            "runtime_analysis.noop_publisher",
            session_id=session.session_id,
        )
