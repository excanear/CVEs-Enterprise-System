"""Serialisation micro-benchmark using pytest-benchmark.

Benchmarks:
1. DomainEventEnvelope.model_dump_json()  — serialisation throughput
2. DomainEventEnvelope.model_validate_json() — deserialisation throughput
3. BaseKafkaProducer.produce_envelope() — end-to-end enqueue throughput
4. EvidenceClusterer.cluster()           — DBSCAN throughput under load

Run:
  pytest tests/performance/test_serialization_benchmark.py -v --benchmark-only \
    --benchmark-sort=mean --benchmark-min-rounds=1000
"""
from __future__ import annotations

import json
import uuid
from unittest.mock import MagicMock

import pytest

from cves_event_schemas.envelope import DomainEventEnvelope


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def sample_envelope() -> DomainEventEnvelope:
    return DomainEventEnvelope(
        event_type="asi.asset.discovered",
        aggregate_id=uuid.uuid4(),
        aggregate_type="AssetAggregate",
        tenant_id=uuid.uuid4(),
        correlation_id=uuid.uuid4(),
        producer_svc="benchmarks",
        payload={
            "asset_id": str(uuid.uuid4()),
            "asset_type": "HOST",
            "fqdn": "benchmark-host.internal",
            "ip_addresses": ["10.0.0.1", "10.0.0.2"],
            "os_fingerprint": "Ubuntu 22.04",
            "open_ports": [22, 80, 443, 8080],
        },
    )


@pytest.fixture(scope="module")
def envelope_json(sample_envelope) -> str:
    return sample_envelope.model_dump_json()


@pytest.fixture(scope="module")
def kafka_headers(sample_envelope) -> list[tuple[str, bytes]]:
    return sample_envelope.to_kafka_headers()


# ── Serialisation benchmarks ──────────────────────────────────────────────────

@pytest.mark.performance
def test_benchmark_envelope_serialisation(benchmark, sample_envelope):
    """Benchmark: Pydantic model → JSON bytes."""
    result = benchmark(sample_envelope.model_dump_json)
    assert '"event_type"' in result


@pytest.mark.performance
def test_benchmark_envelope_deserialisation(benchmark, envelope_json):
    """Benchmark: JSON bytes → validated Pydantic model."""
    result = benchmark(DomainEventEnvelope.model_validate_json, envelope_json)
    assert result.event_type == "asi.asset.discovered"


@pytest.mark.performance
def test_benchmark_to_kafka_headers(benchmark, sample_envelope):
    """Benchmark: envelope → Kafka header list."""
    headers = benchmark(sample_envelope.to_kafka_headers)
    assert any(k == "event_type" for k, _ in headers)


@pytest.mark.performance
def test_benchmark_envelope_creation(benchmark):
    """Benchmark: constructing DomainEventEnvelope from scratch."""
    def _make():
        return DomainEventEnvelope(
            event_type="asi.asset.discovered",
            aggregate_id=uuid.uuid4(),
            aggregate_type="AssetAggregate",
            tenant_id=uuid.uuid4(),
            correlation_id=uuid.uuid4(),
            producer_svc="benchmarks",
            payload={"key": "value"},
        )

    result = benchmark(_make)
    assert result.producer_svc == "benchmarks"


# ── Producer throughput benchmark ─────────────────────────────────────────────

@pytest.mark.performance
def test_benchmark_kafka_produce_envelope(benchmark, sample_envelope):
    """Benchmark: BaseKafkaProducer.produce_envelope() end-to-end."""
    from cves_kafka.producer import BaseKafkaProducer

    mock_confluent = MagicMock()
    mock_confluent.produce = MagicMock()
    producer = BaseKafkaProducer(mock_confluent)

    benchmark(producer.produce_envelope, "test.topic", sample_envelope)
    assert mock_confluent.produce.called


# ── EvidenceClusterer throughput benchmark ────────────────────────────────────

@pytest.mark.performance
def test_benchmark_evidence_clusterer_small(benchmark):
    """Benchmark: DBSCAN on 10 evidence items (typical incident)."""
    pytest.importorskip("ai_correlation.application.algorithms.evidence_clusterer")
    from ai_correlation.application.algorithms.evidence_clusterer import (
        EvidenceClusterer,
        EvidenceItem,
    )

    items = [
        EvidenceItem(
            id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            cve_id="CVE-2024-0001",
            host="10.0.0.1",
            port=443,
            confidence=0.85 - (i * 0.01),
            cvss_score=7.5,
            severity="HIGH",
            poc_triggered=i % 3 == 0,
            exposure_type="REMOTE_CODE_EXECUTION",
            propagation_depth=i % 4,
        )
        for i in range(10)
    ]

    clusterer = EvidenceClusterer()
    benchmark(clusterer.cluster, items)


@pytest.mark.performance
def test_benchmark_evidence_clusterer_large(benchmark):
    """Benchmark: DBSCAN on 200 evidence items (large-scale scan)."""
    pytest.importorskip("ai_correlation.application.algorithms.evidence_clusterer")
    from ai_correlation.application.algorithms.evidence_clusterer import (
        EvidenceClusterer,
        EvidenceItem,
    )

    import random
    rng = random.Random(42)

    items = [
        EvidenceItem(
            id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            cve_id=f"CVE-2024-{i:04d}",
            host=f"10.0.{i // 254}.{i % 254 + 1}",
            port=rng.choice([22, 80, 443, 8080, 3306]),
            confidence=rng.uniform(0.3, 0.99),
            cvss_score=rng.uniform(1.0, 10.0),
            severity=rng.choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
            poc_triggered=rng.random() > 0.7,
            exposure_type=rng.choice(["RCE", "SQLi", "XSS", "SSRF", "LFI"]),
            propagation_depth=rng.randint(0, 5),
        )
        for i in range(200)
    ]

    clusterer = EvidenceClusterer()
    benchmark(clusterer.cluster, items)
