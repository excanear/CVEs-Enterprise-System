"""Contract tests — Kafka event schema compatibility.

Validates that:
1. All DomainEventEnvelope payloads from producers match declared schemas.
2. Producer ↔ consumer schema contracts hold (producer can emit what consumer expects).
3. Schema evolution: required fields are always present.
"""
from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from cves_event_schemas.envelope import DomainEventEnvelope
from cves_event_schemas.asi.asset_events import (
    ASI_ASSET_TOPIC,
    AssetDiscoveredPayload,
    AssetScopedPayload,
    AssetActivatedPayload,
    AssetDecommissionedPayload,
)
from cves_event_schemas.acl.acl_events import (
    ACL_CORRELATION_TOPIC,
    ACL_EVENT_TYPES,
    ClusterCreatedPayload,
    PathRankedPayload,
    RankedPathEntry,
    RiskTier,
)


def _envelope(event_type: str, payload: dict) -> DomainEventEnvelope:
    return DomainEventEnvelope(
        event_type=event_type,
        aggregate_id=uuid.uuid4(),
        aggregate_type="Test",
        tenant_id=uuid.uuid4(),
        correlation_id=uuid.uuid4(),
        producer_svc="contract-test",
        payload=payload,
    )


# ── ASI Event Contracts ───────────────────────────────────────────────────────

class TestASIAssetDiscoveredContract:
    def test_valid_asset_discovered_payload(self):
        payload = AssetDiscoveredPayload(
            asset_id=uuid.uuid4(),
            asset_type="URL",
            discovery_source="ACTIVE_SCAN",
            fqdn="api.example.com",
            ip_address=None,
            scan_id=uuid.uuid4(),
        )
        envelope = _envelope("asi.asset.discovered", payload.model_dump())
        assert envelope.event_type == "asi.asset.discovered"

    def test_all_asset_types_accepted(self):
        for asset_type in ["HOST", "DOMAIN", "CLOUD_RESOURCE", "URL", "SERVICE"]:
            payload = AssetDiscoveredPayload(
                asset_id=uuid.uuid4(),
                asset_type=asset_type,
                discovery_source="MANUAL",
            )
            assert payload.asset_type == asset_type

    def test_all_discovery_sources_accepted(self):
        for source in ["MANUAL", "PASSIVE_DNS", "ACTIVE_SCAN", "CLOUD_API", "CIDR_SWEEP"]:
            payload = AssetDiscoveredPayload(
                asset_id=uuid.uuid4(),
                asset_type="HOST",
                discovery_source=source,
            )
            assert payload.discovery_source == source

    def test_invalid_asset_type_rejected(self):
        with pytest.raises(ValidationError):
            AssetDiscoveredPayload(
                asset_id=uuid.uuid4(),
                asset_type="UNKNOWN_TYPE",
                discovery_source="MANUAL",
            )

    def test_payload_is_frozen(self):
        payload = AssetDiscoveredPayload(
            asset_id=uuid.uuid4(),
            asset_type="URL",
            discovery_source="ACTIVE_SCAN",
        )
        with pytest.raises(Exception):
            payload.asset_type = "HOST"  # type: ignore[misc]

    def test_cloud_resource_fields(self):
        payload = AssetDiscoveredPayload(
            asset_id=uuid.uuid4(),
            asset_type="CLOUD_RESOURCE",
            discovery_source="CLOUD_API",
            cloud_resource_id="i-0abc123",
            cloud_provider="AWS",
        )
        assert payload.cloud_provider == "AWS"


class TestASIAssetScopedContract:
    def test_valid_scoped_payload(self):
        payload = AssetScopedPayload(
            asset_id=uuid.uuid4(),
            in_scope=True,
            scope_group="production",
            rationale="Matches CIDR 10.0.0.0/8",
        )
        envelope = _envelope("asi.asset.scoped", payload.model_dump())
        assert envelope.event_type == "asi.asset.scoped"


class TestASIAssetActivatedContract:
    def test_all_environments_accepted(self):
        for env in ["PRODUCTION", "STAGING", "DEVELOPMENT", "TESTING", "UNKNOWN"]:
            payload = AssetActivatedPayload(
                asset_id=uuid.uuid4(),
                environment=env,
                criticality="HIGH",
            )
            assert payload.environment == env

    def test_all_criticalities_accepted(self):
        for crit in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            payload = AssetActivatedPayload(
                asset_id=uuid.uuid4(),
                environment="PRODUCTION",
                criticality=crit,
            )
            assert payload.criticality == crit


# ── ACL Event Contracts ───────────────────────────────────────────────────────

class TestACLClusterCreatedContract:
    def test_valid_cluster_created_payload(self):
        payload = ClusterCreatedPayload(
            cluster_id=str(uuid.uuid4()),
            tenant_id=str(uuid.uuid4()),
            session_id=str(uuid.uuid4()),
            size=3,
            exposure_types=["SQLI", "XSS"],
            host="api.example.com",
            avg_confidence=0.85,
            poc_triggered_count=2,
            tier=RiskTier.CRITICAL.value,
        )
        envelope = _envelope(ACL_EVENT_TYPES["cluster_created"], payload.model_dump())
        assert envelope.event_type == "acl.cluster.created"

    def test_avg_confidence_bounds_enforced(self):
        with pytest.raises(ValidationError):
            ClusterCreatedPayload(
                cluster_id="c1",
                tenant_id="t1",
                session_id="s1",
                size=1,
                exposure_types=["SQLI"],
                avg_confidence=1.5,  # > 1.0
                tier="LOW",
            )

    def test_all_risk_tiers_valid(self):
        for tier in RiskTier:
            payload = ClusterCreatedPayload(
                cluster_id="c1",
                tenant_id="t1",
                session_id="s1",
                size=1,
                exposure_types=["SQLI"],
                avg_confidence=0.5,
                tier=tier.value,
            )
            assert payload.tier == tier.value


class TestACLPathRankedContract:
    def test_valid_path_ranked_payload(self):
        payload = PathRankedPayload(
            tenant_id=str(uuid.uuid4()),
            session_id=str(uuid.uuid4()),
            ranked_paths=[
                RankedPathEntry(
                    source_endpoint_id="ep-001",
                    target_asset_id="asset-001",
                    hops=2,
                    composite_score=0.75,
                    rank=1,
                )
            ],
        )
        envelope = _envelope(ACL_EVENT_TYPES["path_ranked"], payload.model_dump())
        assert envelope.event_type == "acl.path.ranked"

    def test_composite_score_bounds_enforced(self):
        with pytest.raises(ValidationError):
            RankedPathEntry(
                source_endpoint_id="ep",
                target_asset_id="ast",
                hops=1,
                composite_score=1.5,
                rank=1,
            )


# ── Envelope ↔ Producer Round-Trip Contracts ──────────────────────────────────

class TestProducerConsumerSchemaCompatibility:
    def test_rae_produces_valid_asi_asset_envelope(self):
        """Simulates what KafkaRuntimeEventPublisher emits for WebSocket discovery."""
        from cves_event_schemas.asi.asset_events import AssetDiscoveredPayload

        ws_asset_id = uuid.uuid4()
        payload = AssetDiscoveredPayload(
            asset_id=ws_asset_id,
            asset_type="URL",
            discovery_source="ACTIVE_SCAN",
            fqdn=None,
            ip_address=None,
            scan_id=None,
        )
        envelope = DomainEventEnvelope(
            event_type="asi.asset.discovered",
            aggregate_id=ws_asset_id,
            aggregate_type="DiscoveredAsset",
            tenant_id=uuid.uuid4(),
            correlation_id=uuid.uuid4(),
            producer_svc="runtime-analysis-engine",
            payload=payload.model_dump(),
        )
        # Consumer can reconstruct payload from envelope
        reconstructed = AssetDiscoveredPayload.model_validate(envelope.payload)
        assert reconstructed.asset_id == ws_asset_id
        assert reconstructed.asset_type == "URL"

    def test_acl_producer_re_consumer_compatibility(self):
        """ACL produces cluster_created → RE consumer must be able to decode it."""
        payload = ClusterCreatedPayload(
            cluster_id=str(uuid.uuid4()),
            tenant_id=str(uuid.uuid4()),
            session_id=str(uuid.uuid4()),
            size=5,
            exposure_types=["SQLI"],
            avg_confidence=0.9,
            poc_triggered_count=3,
            tier="CRITICAL",
        )
        envelope = DomainEventEnvelope(
            event_type="acl.cluster.created",
            aggregate_id=uuid.uuid4(),
            aggregate_type="EvidenceCluster",
            tenant_id=uuid.uuid4(),
            correlation_id=uuid.uuid4(),
            producer_svc="ai-correlation-layer",
            payload=payload.model_dump(),
        )
        # Simulate RE consumer decoding the envelope
        raw_json = envelope.model_dump_json()
        decoded_envelope = DomainEventEnvelope.model_validate_json(raw_json)
        decoded_payload = ClusterCreatedPayload.model_validate(decoded_envelope.payload)
        assert decoded_payload.tier == "CRITICAL"
        assert decoded_payload.size == 5

    def test_envelope_event_type_matches_topic_routing(self):
        """All ACL_EVENT_TYPES must match the acl.*.* pattern."""
        import re
        for key, event_type in ACL_EVENT_TYPES.items():
            assert re.match(r"^acl\.[a-z0-9_]+\.[a-z0-9_]+$", event_type), (
                f"ACL_EVENT_TYPES['{key}'] = '{event_type}' violates naming convention"
            )

    def test_correlation_id_propagated_across_envelope_chain(self):
        """Producer's correlation_id must be preserved through the event chain."""
        shared_correlation_id = uuid.uuid4()

        # RAE produces event 1
        evt1 = DomainEventEnvelope(
            event_type="rf.fingerprint.analyzed",
            aggregate_id=uuid.uuid4(),
            aggregate_type="AnalysisResult",
            tenant_id=uuid.uuid4(),
            correlation_id=shared_correlation_id,  # propagated from request
            producer_svc="runtime-analysis-engine",
            payload={"key": "value"},
        )

        # AGE consumes evt1 and produces evt2 with same correlation_id
        evt2 = DomainEventEnvelope(
            event_type="age.graph.node_upserted",
            aggregate_id=uuid.uuid4(),
            aggregate_type="GraphNode",
            tenant_id=uuid.uuid4(),
            correlation_id=shared_correlation_id,  # propagated
            causation_id=evt1.event_id,
            producer_svc="asset-graph-engine",
            payload={"node_id": "n1"},
        )

        assert evt2.correlation_id == shared_correlation_id
        assert evt2.causation_id == evt1.event_id
