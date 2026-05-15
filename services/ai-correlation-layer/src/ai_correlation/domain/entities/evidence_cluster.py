"""EvidenceCluster — group of correlated exposure findings.

A cluster is formed by DBSCAN over feature vectors derived from real
validated findings. It never invents new findings — only groups existing ones.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from cves_event_schemas.acl.acl_events import RiskTier


@dataclass
class EvidenceItem:
    """One atomic piece of validated evidence (from EVE or AGE)."""

    evidence_id: str          # job_id from EVE or path key from AGE
    tenant_id: str
    exposure_type: str        # ExposureType enum value
    target_url: str
    confidence: float         # 0–1, from EVE final_confidence
    poc_triggered: bool
    propagation_depth: int    # from AGE, 0 if not enriched yet
    hop_count: int            # from AGE attack path, 0 if none
    host: str | None = None
    evidence_summary: str | None = None


@dataclass
class EvidenceCluster:
    """A cluster of related evidence items grouped by DBSCAN."""

    cluster_id: str
    tenant_id: str
    session_id: str
    items: list[EvidenceItem] = field(default_factory=list)
    tier: RiskTier = RiskTier.LOW
    host: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def size(self) -> int:
        return len(self.items)

    @property
    def avg_confidence(self) -> float:
        if not self.items:
            return 0.0
        return sum(i.confidence for i in self.items) / len(self.items)

    @property
    def poc_triggered_count(self) -> int:
        return sum(1 for i in self.items if i.poc_triggered)

    @property
    def exposure_types(self) -> list[str]:
        return list({i.exposure_type for i in self.items})

    @property
    def max_propagation_depth(self) -> int:
        if not self.items:
            return 0
        return max(i.propagation_depth for i in self.items)
