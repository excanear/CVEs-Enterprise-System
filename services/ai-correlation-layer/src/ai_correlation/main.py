"""AI Correlation Layer — FastAPI application entrypoint.

Lifecycle:
1. PostgreSQL (AsyncSessionFactory) → CorrelationRepository
2. Redis client → CorrelationCache
3. Kafka producer (graceful degradation)
4. KafkaACLEventPublisher (or _NoopPublisher)
5. LLM client (optional, graceful degradation if disabled)
6. CorrelationService wired with all algorithms
7. Kafka consumer background task (asyncio.to_thread)
8. FastAPI on port 8008
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

from ai_correlation.application.algorithms.attack_path_ranker import AttackPathRanker
from ai_correlation.application.algorithms.evidence_clusterer import EvidenceClusterer
from ai_correlation.application.algorithms.exposure_prioritizer import ExposurePrioritizer
from ai_correlation.application.algorithms.remediation_generator import RemediationGenerator
from ai_correlation.application.correlation_service import CorrelationService
from ai_correlation.infrastructure.ai.llm_client import AsyncLLMClient
from ai_correlation.infrastructure.kafka.event_publisher import KafkaACLEventPublisher
from ai_correlation.infrastructure.kafka.signal_consumer import KafkaACLSignalConsumer
from ai_correlation.infrastructure.persistence.correlation_repository import (
    PostgresCorrelationRepository,
)
from ai_correlation.infrastructure.redis.correlation_cache import RedisCorrelationCache
from ai_correlation.interface.api.router import router

log = structlog.get_logger(__name__)

# ── Settings ──────────────────────────────────────────────────────────────────

_DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://cves:cves_secret@localhost:5432/cves_platform",
)
_KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
_LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
_LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "")          # empty = OpenAI default
_LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini")
_LLM_ENABLED = os.environ.get("LLM_ENABLED", "false").lower() == "true"
_SERVICE_NAME = "ai-correlation-layer"


# ── Noop publisher (fallback when Kafka is down) ───────────────────────────────

class _NoopPublisher:
    async def publish_cluster_created(self, cluster):  # type: ignore[no-untyped-def]
        pass

    async def publish_paths_ranked(self, tenant_id, session_id, paths):  # type: ignore[no-untyped-def]
        pass

    async def publish_exposure_prioritized(self, exposure, session_id):  # type: ignore[no-untyped-def]
        pass

    async def publish_remediation_generated(self, plan, tenant_id, session_id):  # type: ignore[no-untyped-def]
        pass


# ── Noop cache (fallback when Redis is down) ──────────────────────────────────

class _NoopCache:
    async def get_clusters(self, tenant_id): return None  # type: ignore[no-untyped-def]
    async def set_clusters(self, tenant_id, clusters): pass  # type: ignore[no-untyped-def]
    async def get_ranked_paths(self, tenant_id): return None  # type: ignore[no-untyped-def]
    async def set_ranked_paths(self, tenant_id, paths): pass  # type: ignore[no-untyped-def]
    async def get_prioritized(self, tenant_id): return None  # type: ignore[no-untyped-def]
    async def set_prioritized(self, tenant_id, items): pass  # type: ignore[no-untyped-def]
    async def get_remediation(self, cluster_id): return None  # type: ignore[no-untyped-def]
    async def set_remediation(self, cluster_id, plan): pass  # type: ignore[no-untyped-def]


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    setup_logging(service_name=_SERVICE_NAME)
    setup_tracing(service_name=_SERVICE_NAME)
    log.info("acl.starting")

    # PostgreSQL
    db_factory = AsyncSessionFactory.from_url(_DATABASE_URL)
    app.state.db_factory = db_factory
    correlation_repo = PostgresCorrelationRepository(db_factory.session_maker)

    # Redis (graceful degradation)
    cache = _NoopCache()
    redis_client = None
    try:
        import redis.asyncio as aioredis  # type: ignore[import-untyped]

        redis_client = aioredis.from_url(_REDIS_URL, decode_responses=True)
        await redis_client.ping()
        cache = RedisCorrelationCache(redis_client)  # type: ignore[assignment]
        log.info("acl.redis.connected")
    except Exception as exc:
        log.warning("acl.redis.unavailable", error=str(exc), fallback="noop cache")

    # Kafka producer (graceful degradation)
    kafka_producer = None
    publisher = _NoopPublisher()
    try:
        from cves_kafka_client.producer import BaseKafkaProducer

        kafka_producer = BaseKafkaProducer(bootstrap_servers=_KAFKA_BOOTSTRAP)
        publisher = KafkaACLEventPublisher(kafka_producer)  # type: ignore[assignment]
        log.info("acl.kafka.producer.ready")
    except Exception as exc:
        log.warning("acl.kafka.producer.unavailable", error=str(exc), fallback="noop publisher")

    # LLM client (optional)
    llm_client: AsyncLLMClient | None = None
    if _LLM_ENABLED and _LLM_API_KEY:
        llm_client = AsyncLLMClient(
            api_key=_LLM_API_KEY,
            base_url=_LLM_BASE_URL or None,
            model=_LLM_MODEL,
        )
        log.info("acl.llm.enabled", model=_LLM_MODEL)
    else:
        log.info("acl.llm.disabled", reason="LLM_ENABLED=false or LLM_API_KEY not set")

    # Wire algorithms
    clusterer = EvidenceClusterer()
    ranker = AttackPathRanker()
    prioritizer = ExposurePrioritizer()
    remediation = RemediationGenerator(llm_client=llm_client)

    # Wire service
    correlation_service = CorrelationService(
        repository=correlation_repo,
        cache=cache,  # type: ignore[arg-type]
        publisher=publisher,  # type: ignore[arg-type]
        clusterer=clusterer,
        ranker=ranker,
        prioritizer=prioritizer,
        remediation=remediation,
    )
    app.state.correlation_service = correlation_service

    # Kafka consumer (background)
    consumer = KafkaACLSignalConsumer(_KAFKA_BOOTSTRAP)
    consumer_task: asyncio.Task | None = None
    try:
        consumer_task = asyncio.create_task(
            consumer.start(correlation_service.handle_kafka_signal)
        )
        log.info("acl.kafka.consumer.started")
    except Exception as exc:
        log.warning("acl.kafka.consumer.unavailable", error=str(exc))

    log.info("acl.ready", port=8008)
    yield

    # Shutdown
    log.info("acl.shutting_down")
    consumer.stop()
    if consumer_task and not consumer_task.done():
        consumer_task.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(consumer_task), timeout=5.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    if redis_client:
        await redis_client.aclose()
    await db_factory.dispose()
    log.info("acl.stopped")


# ── Application factory ────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="AI Correlation Layer",
        description=(
            "Correlates, prioritizes, and groups validated security findings. "
            "Runs DBSCAN clustering, deterministic attack path ranking, "
            "and template-based remediation generation."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    health = HealthRouter(service_name=_SERVICE_NAME)
    app.include_router(health.router)
    app.include_router(router)
    instrument_app(app, service_name=_SERVICE_NAME)
    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "ai_correlation.main:app",
        host="0.0.0.0",
        port=8008,
        workers=1,
        loop="uvloop",
    )
