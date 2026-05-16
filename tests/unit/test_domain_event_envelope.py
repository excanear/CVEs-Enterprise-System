"""Unit tests — DomainEventEnvelope schema and invariants."""
from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from cves_event_schemas.envelope import DomainEventEnvelope


def _valid_envelope(**overrides) -> dict:
    base = {
        "event_type": "asi.asset.discovered",
        "aggregate_id": uuid.uuid4(),
        "aggregate_type": "Asset",
        "tenant_id": uuid.uuid4(),
        "correlation_id": uuid.uuid4(),
        "producer_svc": "test-service",
        "payload": {"asset_id": str(uuid.uuid4()), "asset_type": "URL"},
    }
    base.update(overrides)
    return base


class TestDomainEventEnvelopeCreation:
    def test_valid_envelope_creates_successfully(self):
        env = DomainEventEnvelope(**_valid_envelope())
        assert env.event_type == "asi.asset.discovered"

    def test_event_id_auto_generated(self):
        env = DomainEventEnvelope(**_valid_envelope())
        assert isinstance(env.event_id, uuid.UUID)

    def test_timestamp_auto_generated_as_ms(self):
        env = DomainEventEnvelope(**_valid_envelope())
        # Should be a reasonable Unix ms timestamp (after year 2020)
        assert env.timestamp > 1_577_836_800_000

    def test_schema_version_defaults_to_1_0_0(self):
        env = DomainEventEnvelope(**_valid_envelope())
        assert env.schema_version == "1.0.0"

    def test_causation_id_defaults_to_none(self):
        env = DomainEventEnvelope(**_valid_envelope())
        assert env.causation_id is None

    def test_causation_id_can_be_set(self):
        cause_id = uuid.uuid4()
        env = DomainEventEnvelope(**_valid_envelope(causation_id=cause_id))
        assert env.causation_id == cause_id


class TestDomainEventEnvelopeImmutability:
    def test_envelope_is_frozen(self):
        env = DomainEventEnvelope(**_valid_envelope())
        with pytest.raises(Exception):
            env.event_type = "modified.type"  # type: ignore[misc]


class TestDomainEventEnvelopeEventTypeValidation:
    @pytest.mark.parametrize("valid_type", [
        "asi.asset.discovered",
        "rf.fingerprint.analyzed",
        "eve.exposure.confirmed",
        "jsi.js.bundle_analyzed",
        "age.graph.node_upserted",
        "acl.correlation.cluster_created",
        "re.report.generated",
        "scan.orchestrator.scan_started",
    ])
    def test_valid_event_types_accepted(self, valid_type):
        env = DomainEventEnvelope(**_valid_envelope(event_type=valid_type))
        assert env.event_type == valid_type

    @pytest.mark.parametrize("invalid_type", [
        "UPPERCASE.EVENT",
        "no-dots",
        ".leading.dot",
        "trailing.dot.",
        "double..dot",
        "",
        "1starts.with.number",
    ])
    def test_invalid_event_types_rejected(self, invalid_type):
        with pytest.raises(ValidationError):
            DomainEventEnvelope(**_valid_envelope(event_type=invalid_type))


class TestDomainEventEnvelopeSchemaVersionValidation:
    @pytest.mark.parametrize("valid_version", ["1.0.0", "2.3.1", "10.0.0"])
    def test_valid_semver_accepted(self, valid_version):
        env = DomainEventEnvelope(**_valid_envelope(schema_version=valid_version))
        assert env.schema_version == valid_version

    @pytest.mark.parametrize("invalid_version", ["1.0", "v1.0.0", "1.0.0-beta", "latest"])
    def test_invalid_semver_rejected(self, invalid_version):
        with pytest.raises(ValidationError):
            DomainEventEnvelope(**_valid_envelope(schema_version=invalid_version))


class TestDomainEventEnvelopeKafkaHeaders:
    def test_to_kafka_headers_includes_event_type(self):
        env = DomainEventEnvelope(**_valid_envelope())
        headers = env.to_kafka_headers()
        assert any(k == "event_type" for k, _ in headers) or "event_type" in dict(headers)

    def test_to_kafka_headers_includes_tenant_id(self):
        env = DomainEventEnvelope(**_valid_envelope())
        headers = env.to_kafka_headers()
        header_dict = {k: v for k, v in headers} if isinstance(headers, list) else headers
        assert "tenant_id" in header_dict

    def test_to_kafka_headers_includes_correlation_id(self):
        env = DomainEventEnvelope(**_valid_envelope())
        headers = env.to_kafka_headers()
        header_dict = {k: v for k, v in headers} if isinstance(headers, list) else headers
        assert "correlation_id" in header_dict


class TestDomainEventEnvelopeRoundTrip:
    def test_json_round_trip(self):
        original = DomainEventEnvelope(**_valid_envelope())
        json_str = original.model_dump_json()
        restored = DomainEventEnvelope.model_validate_json(json_str)
        assert restored.event_id == original.event_id
        assert restored.event_type == original.event_type
        assert restored.tenant_id == original.tenant_id
        assert restored.payload == original.payload

    def test_dict_round_trip(self):
        original = DomainEventEnvelope(**_valid_envelope())
        as_dict = original.model_dump()
        restored = DomainEventEnvelope.model_validate(as_dict)
        assert restored.event_id == original.event_id
        assert restored.correlation_id == original.correlation_id
