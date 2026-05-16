"""Discovery Engine application entrypoint.

Wires all infrastructure components and starts FastAPI with the discovery
service bound to app.state.
"""
from __future__ import annotations

import contextlib
import logging
import os

from fastapi import FastAPI

from cves_db.rls import install_rls_hook
from cves_db.session import AsyncSessionFactory
from cves_observability.health import HealthRouter
from cves_observability.instrumentation import instrument_app
from cves_observability.logging import setup_logging
from cves_observability.tracing import setup_tracing

from discovery_engine.application.asset_correlator import AssetCorrelator
from discovery_engine.application.discovery_service import DiscoveryService
from discovery_engine.infrastructure.persistence.asset_repository import (
    PostgresDiscoveredAssetRepository,
    PostgresDiscoveryJobRepository,
)
from discovery_engine.infrastructure.sources.crawler import WebCrawler
from discovery_engine.infrastructure.sources.ct_logs import CTLogsSource
from discovery_engine.infrastructure.sources.endpoint_extractor import EndpointExtractor
from discovery_engine.infrastructure.sources.passive_dns import PassiveDNSSource
from discovery_engine.infrastructure.sources.robots_sitemap import RobotsSitemapSource
from discovery_engine.interface.api.router import router

SERVICE_NAME = "discovery-engine"
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
    db_url = os.environ["DATABASE_URL"]

    session_factory = AsyncSessionFactory.from_url(db_url)
    install_rls_hook(session_factory._engine)  # type: ignore[attr-defined]

    async with session_factory.session() as session:
        job_repo = PostgresDiscoveryJobRepository(session)
        asset_repo = PostgresDiscoveredAssetRepository(session)

        passive_dns = PassiveDNSSource(
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
            securitytrails_api_key=os.getenv("SECURITYTRAILS_API_KEY"),
        )
        ct_logs = CTLogsSource()
        robots_sitemap = RobotsSitemapSource()
        crawler = WebCrawler(
            max_rps=float(os.getenv("CRAWLER_MAX_RPS", "5.0")),
            allow_internal=os.getenv("CRAWLER_ALLOW_INTERNAL", "false").lower() == "true",
        )
        extractor = EndpointExtractor()
        correlator = AssetCorrelator()

        # Kafka publisher is optional — gracefully degrades when broker is unreachable
        event_publisher = None
        kafka_brokers = os.getenv("KAFKA_BOOTSTRAP_SERVERS")
        if kafka_brokers:
            try:
                from cves_kafka.producer import BaseKafkaProducer
                from discovery_engine.infrastructure.kafka.event_publisher import (
                    KafkaDiscoveryEventPublisher,
                )
                producer = BaseKafkaProducer.from_config(
                    {"bootstrap.servers": kafka_brokers},
                    transactional_id=f"discovery-engine-{SERVICE_VERSION}",
                )
                event_publisher = KafkaDiscoveryEventPublisher(producer)
                logger.info("kafka.publisher_enabled")
            except Exception as exc:
                logger.warning("kafka.publisher_disabled", extra={"reason": str(exc)})

        svc = DiscoveryService(
            job_repo=job_repo,
            asset_repo=asset_repo,
            event_publisher=event_publisher,
            passive_dns=passive_dns,
            ct_logs=ct_logs,
            robots_sitemap=robots_sitemap,
            crawler=crawler,
            endpoint_extractor=extractor,
            correlator=correlator,
        )

        app.state.discovery_svc = svc
        logger.info("discovery-engine.started")
        yield

    await session_factory.close()
    logger.info("discovery-engine.stopped")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Discovery Engine",
        version=SERVICE_VERSION,
        docs_url="/docs",
        lifespan=lifespan,
    )
    health = HealthRouter(service_name=SERVICE_NAME, version=SERVICE_VERSION, checks={})
    app.include_router(router)
    app.include_router(health.router)
    instrument_app(app, service_name=SERVICE_NAME)
    return app


app = create_app()
