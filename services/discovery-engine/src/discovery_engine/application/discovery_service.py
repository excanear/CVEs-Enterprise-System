"""Discovery orchestration service.

Pipeline:
  Phase 1 — Passive recon (parallel): passive DNS + CT logs.
  Phase 2 — Active recon (per-FQDN): robots.txt + sitemap.xml.
  Phase 3 — Crawling: BFS HTTP crawl of in-scope hosts.
  Phase 4 — Endpoint extraction: APIs/paths from crawled pages.
  Phase 5 — Correlation: shared IPs, certificates, CNAMEs, parent domains.
  Phase 6 — Persist + publish domain events.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..domain.entities.discovered_asset import (
    AssetType,
    DiscoveredAsset,
    DiscoverySource,
)
from ..domain.entities.discovery_job import DiscoveryJob, DiscoverySourceConfig
from ..domain.ports import (
    DiscoveredAssetRepository,
    DiscoveryEventPublisher,
    DiscoveryJobRepository,
)
from ..domain.value_objects.certificate import Certificate
from ..domain.value_objects.dns_record import DNSRecord
from .asset_correlator import AssetCorrelator
from .commands import RunDiscoveryCommand

if TYPE_CHECKING:
    from ..infrastructure.sources.crawler import CrawledPage
    from ..infrastructure.sources.endpoint_extractor import EndpointExtractor
    from ..infrastructure.sources.passive_dns import PassiveDNSSource
    from ..infrastructure.sources.ct_logs import CTLogsSource
    from ..infrastructure.sources.robots_sitemap import RobotsSitemapSource
    from ..infrastructure.sources.crawler import WebCrawler

logger = logging.getLogger(__name__)

# Safety cap: never crawl more than this many hosts in one job
_MAX_ACTIVE_HOSTS = 20
# Safety cap: passive recon FQDNs forwarded to active phase
_MAX_PASSIVE_FQDNS = 200


@dataclass
class DiscoveryResult:
    job_id: uuid.UUID
    assets_found: int
    endpoints_found: int
    correlations_found: int


class DiscoveryService:
    def __init__(
        self,
        *,
        job_repo: DiscoveryJobRepository,
        asset_repo: DiscoveredAssetRepository,
        event_publisher: DiscoveryEventPublisher | None,
        passive_dns: "PassiveDNSSource",
        ct_logs: "CTLogsSource",
        robots_sitemap: "RobotsSitemapSource",
        crawler: "WebCrawler",
        endpoint_extractor: "EndpointExtractor",
        correlator: AssetCorrelator,
    ) -> None:
        self._job_repo = job_repo
        self._asset_repo = asset_repo
        self._publisher = event_publisher
        self._passive_dns = passive_dns
        self._ct_logs = ct_logs
        self._robots_sitemap = robots_sitemap
        self._crawler = crawler
        self._extractor = endpoint_extractor
        self._correlator = correlator

    # ── Public API ────────────────────────────────────────────────────────

    async def run_discovery(self, cmd: RunDiscoveryCommand) -> DiscoveryResult:
        job = DiscoveryJob.create(
            tenant_id=cmd.tenant_id,
            target_domain=cmd.target_domain,
            scope_domains=cmd.scope_domains or [cmd.target_domain],
            sources=list(cmd.sources) if cmd.sources else None,
            initiated_by=cmd.initiated_by,
            correlation_id=cmd.correlation_id,
        )
        job.start()
        await self._job_repo.save(job)
        logger.info("discovery.started", extra={"job_id": str(job.job_id), "domain": job.target_domain})

        try:
            result = await self._pipeline(job, cmd)
            job.complete(assets_found=result.assets_found, endpoints_found=result.endpoints_found)
            await self._job_repo.save(job)
            await self._emit("publish_job_completed", job)
            logger.info(
                "discovery.completed",
                extra={
                    "job_id": str(job.job_id),
                    "assets": result.assets_found,
                    "endpoints": result.endpoints_found,
                    "correlations": result.correlations_found,
                },
            )
            return result
        except Exception as exc:
            logger.error("discovery.failed", extra={"job_id": str(job.job_id), "error": str(exc)}, exc_info=True)
            job.fail(str(exc))
            await self._job_repo.save(job)
            await self._emit("publish_job_failed", job)
            raise

    # ── Pipeline phases ───────────────────────────────────────────────────

    async def _pipeline(self, job: DiscoveryJob, cmd: RunDiscoveryCommand) -> DiscoveryResult:
        domain = job.target_domain
        dns_records: list[DNSRecord] = []
        certificates: list[Certificate] = []
        discovered_fqdns: set[str] = {domain}
        all_assets: list[DiscoveredAsset] = []
        all_endpoints_count: int = 0

        # ── Phase 1: Passive recon (parallel) ─────────────────────────────
        passive_tasks: list[Any] = []
        passive_labels: list[str] = []

        if DiscoverySourceConfig.PASSIVE_DNS in job.sources:
            passive_tasks.append(self._passive_dns.query(domain))
            passive_labels.append("PASSIVE_DNS")
        if DiscoverySourceConfig.CT_LOGS in job.sources:
            passive_tasks.append(self._ct_logs.query(domain))
            passive_labels.append("CT_LOGS")

        if passive_tasks:
            results = await asyncio.gather(*passive_tasks, return_exceptions=True)
            for label, result in zip(passive_labels, results):
                if isinstance(result, Exception):
                    logger.warning("discovery.source_failed", extra={"source": label, "error": str(result)})
                    continue
                records, fqdns = result
                if label == "PASSIVE_DNS":
                    dns_records.extend(records)
                else:
                    certificates.extend(records)   # ct_logs returns (certs, fqdns)
                discovered_fqdns.update(fqdns)

        # Build domain/host assets from passive recon
        for fqdn in list(discovered_fqdns)[:_MAX_PASSIVE_FQDNS]:
            asset = DiscoveredAsset.create(
                tenant_id=job.tenant_id,
                job_id=job.job_id,
                asset_type=AssetType.DOMAIN,
                value=fqdn,
                source=DiscoverySource.PASSIVE_DNS if fqdn == domain else DiscoverySource.CT_LOGS,
                confidence=0.85 if fqdn == domain else 0.75,
                correlation_id=job.correlation_id,
            )
            all_assets.append(asset)

        # Also add IPs discovered via DNS A records as HOST assets
        seen_ips: set[str] = set()
        for record in dns_records:
            from ..domain.value_objects.dns_record import RecordType
            if record.record_type in (RecordType.A, RecordType.AAAA) and record.value not in seen_ips:
                seen_ips.add(record.value)
                all_assets.append(DiscoveredAsset.create(
                    tenant_id=job.tenant_id,
                    job_id=job.job_id,
                    asset_type=AssetType.HOST,
                    value=record.value,
                    source=DiscoverySource.PASSIVE_DNS,
                    confidence=0.9,
                    correlation_id=job.correlation_id,
                    metadata={"resolved_from": record.name},
                ))

        # ── Phase 2: robots.txt + sitemap (parallel per host) ─────────────
        seed_urls: list[str] = []
        if DiscoverySourceConfig.ROBOTS_SITEMAP in job.sources:
            active_hosts = [f for f in discovered_fqdns if f][:_MAX_ACTIVE_HOSTS]
            rs_tasks = [self._robots_sitemap.discover(h) for h in active_hosts]
            rs_results = await asyncio.gather(*rs_tasks, return_exceptions=True)
            for result in rs_results:
                if not isinstance(result, Exception):
                    seed_urls.extend(result)

        # ── Phase 3: Crawling ──────────────────────────────────────────────
        crawled_pages: list["CrawledPage"] = []
        if DiscoverySourceConfig.CRAWLER in job.sources:
            crawl_hosts = list(discovered_fqdns)[:_MAX_ACTIVE_HOSTS]
            pages_per_host = max(10, cmd.max_pages // max(len(crawl_hosts), 1))

            for hostname in crawl_hosts:
                try:
                    pages = await self._crawler.crawl(
                        hostname,
                        scope_domains=job.scope_domains,
                        max_depth=cmd.max_depth,
                        max_pages=pages_per_host,
                        seed_urls=[u for u in seed_urls if hostname in u],
                        allow_internal=cmd.allow_internal,
                    )
                    crawled_pages.extend(pages)

                    # Add discovered URLs as URL assets
                    for page in pages:
                        all_assets.append(DiscoveredAsset.create(
                            tenant_id=job.tenant_id,
                            job_id=job.job_id,
                            asset_type=AssetType.URL,
                            value=page.url,
                            source=DiscoverySource.CRAWLER,
                            confidence=0.95,
                            correlation_id=job.correlation_id,
                            metadata={"status_code": page.status_code, "content_type": page.content_type},
                        ))
                except Exception as exc:
                    logger.warning("discovery.crawl_failed", extra={"host": hostname, "error": str(exc)})

        # ── Phase 4: Endpoint extraction ───────────────────────────────────
        if DiscoverySourceConfig.ENDPOINT_EXTRACTION in job.sources:
            for page in crawled_pages:
                endpoints = self._extractor.extract(page)
                all_endpoints_count += len(endpoints)
                for ep in endpoints:
                    all_assets.append(DiscoveredAsset.create(
                        tenant_id=job.tenant_id,
                        job_id=job.job_id,
                        asset_type=AssetType.ENDPOINT,
                        value=ep.url,
                        source=DiscoverySource.ENDPOINT_EXTRACTION,
                        confidence=0.8 if ep.is_api_endpoint else 0.6,
                        correlation_id=job.correlation_id,
                        metadata={
                            "method": ep.method,
                            "is_api": ep.is_api_endpoint,
                            "discovered_from": ep.discovered_from,
                        },
                    ))

        # ── Phase 5: Correlation ───────────────────────────────────────────
        correlations = self._correlator.correlate(all_assets, dns_records, certificates)
        for asset_a_id, asset_b_id, reason in correlations:
            for asset in all_assets:
                if asset.asset_id == asset_a_id:
                    asset.mark_correlated(asset_b_id, reason)

        # ── Phase 6: Persist + publish ─────────────────────────────────────
        await self._asset_repo.save_batch(all_assets)
        for asset in all_assets:
            await self._emit("publish_asset_discovered", asset, job)

        return DiscoveryResult(
            job_id=job.job_id,
            assets_found=len(all_assets),
            endpoints_found=all_endpoints_count,
            correlations_found=len(correlations),
        )

    async def _emit(self, method: str, *args) -> None:
        """Safe event emission — never fails the pipeline."""
        if not self._publisher:
            return
        try:
            await getattr(self._publisher, method)(*args)
        except Exception as exc:
            logger.warning("discovery.event_publish_failed", extra={"method": method, "error": str(exc)})
