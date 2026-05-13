"""DiscoveredAsset aggregate — root of the Discovery Engine domain."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from cves_db.types import uuid7


class AssetType(StrEnum):
    HOST = "HOST"
    DOMAIN = "DOMAIN"
    URL = "URL"
    ENDPOINT = "ENDPOINT"
    CERTIFICATE = "CERTIFICATE"


class DiscoverySource(StrEnum):
    PASSIVE_DNS = "PASSIVE_DNS"
    CT_LOGS = "CT_LOGS"
    ROBOTS_TXT = "ROBOTS_TXT"
    SITEMAP = "SITEMAP"
    CRAWLER = "CRAWLER"
    ENDPOINT_EXTRACTION = "ENDPOINT_EXTRACTION"
    MANUAL = "MANUAL"


class AssetStatus(StrEnum):
    NEW = "NEW"
    CONFIRMED = "CONFIRMED"
    STALE = "STALE"
    CORRELATED = "CORRELATED"


@dataclass
class DiscoveredAsset:
    """Asset aggregate root — represents any surface element found during discovery."""

    asset_id: uuid.UUID
    tenant_id: uuid.UUID
    job_id: uuid.UUID
    asset_type: AssetType
    value: str                          # FQDN, IP, full URL, or path
    source: DiscoverySource
    status: AssetStatus = AssetStatus.NEW
    confidence: float = 0.5             # 0.0 – 1.0
    parent_asset_id: uuid.UUID | None = None
    correlation_id: uuid.UUID | None = None
    first_seen_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    _domain_events: list = field(default_factory=list, repr=False)

    @classmethod
    def create(
        cls,
        tenant_id: uuid.UUID,
        job_id: uuid.UUID,
        asset_type: AssetType,
        value: str,
        source: DiscoverySource,
        *,
        confidence: float = 0.5,
        parent_asset_id: uuid.UUID | None = None,
        correlation_id: uuid.UUID | None = None,
        metadata: dict | None = None,
    ) -> "DiscoveredAsset":
        return cls(
            asset_id=uuid7(),
            tenant_id=tenant_id,
            job_id=job_id,
            asset_type=asset_type,
            value=value.lower().strip(),
            source=source,
            confidence=max(0.0, min(1.0, confidence)),
            parent_asset_id=parent_asset_id,
            correlation_id=correlation_id,
            metadata=metadata or {},
        )

    # ── State transitions ─────────────────────────────────────────────────

    def confirm(self, confidence: float = 1.0) -> None:
        self.status = AssetStatus.CONFIRMED
        self.confidence = max(self.confidence, min(1.0, confidence))
        self.last_seen_at = datetime.now(timezone.utc)

    def mark_stale(self) -> None:
        self.status = AssetStatus.STALE

    def mark_correlated(self, correlated_with: uuid.UUID, reason: str = "") -> None:
        self.status = AssetStatus.CORRELATED
        self.metadata.setdefault("correlations", []).append(
            {"with": str(correlated_with), "reason": reason}
        )

    def touch(self) -> None:
        self.last_seen_at = datetime.now(timezone.utc)

    def add_tag(self, tag: str) -> None:
        if tag not in self.tags:
            self.tags.append(tag)

    def collect_events(self) -> list:
        evts = list(self._domain_events)
        self._domain_events.clear()
        return evts

    # ── Derived properties ────────────────────────────────────────────────

    @property
    def is_domain_like(self) -> bool:
        return self.asset_type in (AssetType.DOMAIN, AssetType.HOST)

    @property
    def asi_asset_type(self) -> str:
        """Map to ASI event schema asset_type literals."""
        mapping = {
            AssetType.HOST: "HOST",
            AssetType.DOMAIN: "DOMAIN",
            AssetType.URL: "URL",
            AssetType.ENDPOINT: "URL",
            AssetType.CERTIFICATE: "DOMAIN",
        }
        return mapping.get(self.asset_type, "DOMAIN")

    @property
    def asi_discovery_source(self) -> str:
        """Map to ASI event schema discovery_source literals."""
        mapping = {
            DiscoverySource.PASSIVE_DNS: "PASSIVE_DNS",
            DiscoverySource.CT_LOGS: "PASSIVE_DNS",
            DiscoverySource.MANUAL: "MANUAL",
            DiscoverySource.ROBOTS_TXT: "ACTIVE_SCAN",
            DiscoverySource.SITEMAP: "ACTIVE_SCAN",
            DiscoverySource.CRAWLER: "ACTIVE_SCAN",
            DiscoverySource.ENDPOINT_EXTRACTION: "ACTIVE_SCAN",
        }
        return mapping.get(self.source, "ACTIVE_SCAN")
