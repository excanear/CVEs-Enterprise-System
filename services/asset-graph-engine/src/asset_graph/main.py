"""Asset Graph Engine — FastAPI application entrypoint.

Lifecycle:
1. PostgreSQL (AsyncSessionFactory) → IngestionJobRepository
2. Neo4j async driver → bootstrap_constraints()
3. Neo4jGraphRepository wired
4. Kafka producer (graceful degradation)
5. KafkaAGEEventPublisher (or _NoopPublisher)
6. AssetGraphService wired
7. Kafka consumer background task (asyncio.to_thread)
8. FastAPI on port 8007
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
from cves_observability.logging import setup_logging
from cves_observability.tracing import setup_tracing

from asset_graph.application.asset_graph_service import AssetGraphService
from asset_graph.infrastructure.kafka.signal_consumer import KafkaGraphSignalConsumer
from asset_graph.infrastructure.neo4j.driver import AsyncNeo4jDriver
from asset_graph.infrastructure.neo4j.graph_repository import Neo4jGraphRepository
from asset_graph.infrastructure.persistence.ingestion_repository import (
    PostgresIngestionJobRepository,
)
from asset_graph.interface.api.router import router

log = structlog.get_logger(__name__)

# ── Settings ──────────────────────────────────────────────────────────────────

_DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://cves:cves_secret@localhost:5432/cves_platform",
)
_KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
_NEO4J_URL = os.environ.get("NEO4J_URL", "bolt://localhost:7687")
_NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
_NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "neo4j_secret")
_SERVICE_NAME = "asset-graph-engine"


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    setup_logging(service_name=_SERVICE_NAME)
    setup_tracing(service_name=_SERVICE_NAME)
    log.info("age.starting")

    # PostgreSQL (job tracking)
    db_factory = AsyncSessionFactory.from_url(_DATABASE_URL)
    app.state.db_factory = db_factory
    job_repo = PostgresIngestionJobRepository(db_factory.session_maker)
    app.state.job_repo = job_repo

    # Neo4j driver + constraints bootstrap
    neo4j_driver = AsyncNeo4jDriver(
        uri=_NEO4J_URL,
        user=_NEO4J_USER,
        password=_NEO4J_PASSWORD,
    )
    await neo4j_driver.bootstrap_constraints()
    app.state.neo4j_driver = neo4j_driver

    graph_repo = Neo4jGraphRepository(neo4j_driver)
    app.state.graph_repo = graph_repo

    # Kafka producer (optional — graceful degradation)
    kafka_producer = None
    try:
        from cves_kafka_client.producer import BaseKafkaProducer

        kafka_producer = BaseKafkaProducer.from_config(
            bootstrap_servers=_KAFKA_BOOTSTRAP,
            transactional_id=f"{_SERVICE_NAME}-producer",
        )
        await kafka_producer.start()
        log.info("age.kafka.producer_connected")
    except Exception as exc:
        log.warning("age.kafka.producer_unavailable", error=str(exc))

    if kafka_producer:
        from asset_graph.infrastructure.kafka.event_publisher import KafkaAGEEventPublisher
        event_publisher = KafkaAGEEventPublisher(kafka_producer)
    else:
        event_publisher = _NoopPublisher()

    app.state.event_publisher = event_publisher

    # Application service (facade)
    age_service = AssetGraphService(
        graph_repo=graph_repo,
        job_repo=job_repo,
        event_publisher=event_publisher,
    )
    app.state.age_service = age_service

    # Kafka consumer (optional — background asyncio.to_thread poll loop)
    consumer_task: asyncio.Task | None = None
    if kafka_producer:
        try:
            consumer = KafkaGraphSignalConsumer(bootstrap_servers=_KAFKA_BOOTSTRAP)
            app.state.consumer = consumer

            async def _consumer_wrapper() -> None:
                await consumer.start_consuming(age_service.handle_kafka_signal)

            consumer_task = asyncio.create_task(_consumer_wrapper())
            log.info("age.kafka.consumer_started")
        except Exception as exc:
            log.warning("age.kafka.consumer_unavailable", error=str(exc))

    log.info("age.started")
    yield

    # ── Shutdown ───────────────────────────────────────────────────────────
    log.info("age.stopping")
    if consumer_task:
        consumer = getattr(app.state, "consumer", None)
        if consumer:
            await consumer.stop()
        consumer_task.cancel()
    if kafka_producer:
        await kafka_producer.stop()
    await neo4j_driver.close()
    await db_factory.dispose()
    log.info("age.stopped")


# ── App ───────────────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="Asset Graph Engine",
        description=(
            "Builds and queries a directed asset relationship graph in Neo4j. "
            "Provides attack path analysis, trust chain traversal, exposure propagation "
            "(via APOC), runtime dependency risk, and infrastructure topology mapping."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(router)
    app.include_router(
        HealthRouter(
            service_name=_SERVICE_NAME,
            version="0.1.0",
            checks={
                "neo4j": lambda: app.state.neo4j_driver.ping(),
            },
        ).router
    )
    return app


app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "asset_graph.main:app",
        host="0.0.0.0",
        port=8007,
        reload=False,
    )


# ── Noop publisher ────────────────────────────────────────────────────────────

class _NoopPublisher:
    async def publish_node_upserted(self, node: object) -> None:
        log.debug("age.noop_publisher.node_upserted")

    async def publish_attack_path(self, path: object, tenant_id: str) -> None:
        log.debug("age.noop_publisher.attack_path")

    async def publish_propagation(self, propagation: object) -> None:
        log.debug("age.noop_publisher.propagation")
