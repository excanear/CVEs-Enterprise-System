"""Unit tests — EvidenceClusterer (DBSCAN-based grouping)."""
from __future__ import annotations

import uuid

import pytest

from ai_correlation.application.algorithms.evidence_clusterer import (
    EvidenceClusterer,
    _cluster_tier,
    _cluster_host,
)
from ai_correlation.domain.entities.evidence_cluster import EvidenceCluster, EvidenceItem
from cves_event_schemas.acl.acl_events import RiskTier


def _make_item(
    *,
    confidence: float = 0.5,
    poc_triggered: bool = False,
    propagation_depth: int = 0,
    hop_count: int = 0,
    exposure_type: str = "SQLI",
    host: str | None = "example.com",
    target_url: str = "https://example.com/api",
    tenant_id: str | None = None,
) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=str(uuid.uuid4()),
        tenant_id=tenant_id or str(uuid.uuid4()),
        exposure_type=exposure_type,
        target_url=target_url,
        confidence=confidence,
        poc_triggered=poc_triggered,
        propagation_depth=propagation_depth,
        hop_count=hop_count,
        host=host,
    )


class TestClusterTierHelper:
    def test_critical_high_confidence_with_poc(self):
        items = [_make_item(confidence=0.90, poc_triggered=True)]
        assert _cluster_tier(items) == RiskTier.CRITICAL

    def test_critical_high_confidence_deep_propagation(self):
        items = [_make_item(confidence=0.90, propagation_depth=3)]
        assert _cluster_tier(items) == RiskTier.CRITICAL

    def test_high_when_poc_without_critical_confidence(self):
        items = [_make_item(confidence=0.70, poc_triggered=True)]
        assert _cluster_tier(items) == RiskTier.HIGH

    def test_high_confidence_without_poc_or_depth(self):
        items = [_make_item(confidence=0.72)]
        assert _cluster_tier(items) == RiskTier.HIGH

    def test_medium_moderate_confidence(self):
        items = [_make_item(confidence=0.55)]
        assert _cluster_tier(items) == RiskTier.MEDIUM

    def test_low_confidence(self):
        items = [_make_item(confidence=0.30)]
        assert _cluster_tier(items) == RiskTier.LOW

    def test_mixed_confidence_averages(self):
        items = [_make_item(confidence=0.90), _make_item(confidence=0.10)]
        tier = _cluster_tier(items)
        # avg = 0.50 → MEDIUM
        assert tier == RiskTier.MEDIUM


class TestClusterHostHelper:
    def test_single_host_returned(self):
        items = [_make_item(host="api.example.com"), _make_item(host="api.example.com")]
        assert _cluster_host(items) == "api.example.com"

    def test_multiple_hosts_returns_none(self):
        items = [_make_item(host="a.com"), _make_item(host="b.com")]
        assert _cluster_host(items) is None

    def test_all_none_hosts_returns_none(self):
        items = [_make_item(host=None), _make_item(host=None)]
        assert _cluster_host(items) is None


class TestEvidenceClustererEmpty:
    async def test_empty_items_returns_empty_list(self):
        clusterer = EvidenceClusterer()
        result = await clusterer.cluster([], tenant_id="t1", session_id="s1")
        assert result == []


class TestEvidenceClustererSingleItem:
    async def test_single_item_creates_one_cluster(self):
        clusterer = EvidenceClusterer()
        item = _make_item(confidence=0.75)
        clusters = await clusterer.cluster([item], tenant_id="t1", session_id="s1")
        assert len(clusters) == 1
        assert clusters[0].size == 1
        assert clusters[0].items[0] is item


class TestEvidenceClustererGrouping:
    async def test_similar_items_grouped_together(self):
        """Items with identical feature vectors should form one cluster."""
        clusterer = EvidenceClusterer()
        tid = str(uuid.uuid4())
        items = [
            _make_item(confidence=0.8, poc_triggered=True, host="api.com", tenant_id=tid),
            _make_item(confidence=0.82, poc_triggered=True, host="api.com", tenant_id=tid),
            _make_item(confidence=0.79, poc_triggered=True, host="api.com", tenant_id=tid),
        ]
        clusters = await clusterer.cluster(items, tenant_id=tid, session_id="sess")
        # DBSCAN should group these together (small eps difference)
        total_items = sum(c.size for c in clusters)
        assert total_items == 3

    async def test_noise_items_become_singleton_clusters(self):
        """DBSCAN label=-1 (noise) items should each become a singleton cluster."""
        clusterer = EvidenceClusterer()
        # Maximally different items: one high, one zero confidence
        items = [
            _make_item(confidence=0.99, poc_triggered=True, host="a.com"),
            _make_item(confidence=0.01, poc_triggered=False, host="z.com"),
        ]
        clusters = await clusterer.cluster(items, tenant_id="t1", session_id="s1")
        total_items = sum(c.size for c in clusters)
        assert total_items == len(items)

    async def test_all_clusters_belong_to_correct_tenant(self):
        clusterer = EvidenceClusterer()
        tid = "tenant-xyz"
        items = [_make_item(tenant_id=tid) for _ in range(3)]
        clusters = await clusterer.cluster(items, tenant_id=tid, session_id="s1")
        for c in clusters:
            assert c.tenant_id == tid


class TestEvidenceClusterProperties:
    def test_size_property(self):
        items = [_make_item(), _make_item()]
        cluster = EvidenceCluster(
            cluster_id="c1", tenant_id="t1", session_id="s1", items=items, tier=RiskTier.LOW
        )
        assert cluster.size == 2

    def test_avg_confidence(self):
        items = [_make_item(confidence=0.6), _make_item(confidence=0.8)]
        cluster = EvidenceCluster(
            cluster_id="c1", tenant_id="t1", session_id="s1", items=items, tier=RiskTier.MEDIUM
        )
        assert cluster.avg_confidence == pytest.approx(0.7)

    def test_poc_triggered_count(self):
        items = [
            _make_item(poc_triggered=True),
            _make_item(poc_triggered=False),
            _make_item(poc_triggered=True),
        ]
        cluster = EvidenceCluster(
            cluster_id="c1", tenant_id="t1", session_id="s1", items=items, tier=RiskTier.HIGH
        )
        assert cluster.poc_triggered_count == 2

    def test_exposure_types_unique(self):
        items = [
            _make_item(exposure_type="SQLI"),
            _make_item(exposure_type="XSS"),
            _make_item(exposure_type="SQLI"),
        ]
        cluster = EvidenceCluster(
            cluster_id="c1", tenant_id="t1", session_id="s1", items=items, tier=RiskTier.HIGH
        )
        assert sorted(cluster.exposure_types) == ["SQLI", "XSS"]

    def test_max_propagation_depth(self):
        items = [
            _make_item(propagation_depth=1),
            _make_item(propagation_depth=5),
            _make_item(propagation_depth=3),
        ]
        cluster = EvidenceCluster(
            cluster_id="c1", tenant_id="t1", session_id="s1", items=items, tier=RiskTier.HIGH
        )
        assert cluster.max_propagation_depth == 5
