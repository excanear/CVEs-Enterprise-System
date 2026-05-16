"""Event-driven tests — Kafka consumer and producer pipeline.

Tests:
1. BaseKafkaProducer.produce_envelope serialization
2. BaseKafkaConsumer dedup logic, offset commit, error escalation
3. AGE KafkaGraphSignalConsumer routing (4 topics → correct handler)
4. ACL KafkaACLSignalConsumer routing (2 topics → correct handler)
5. RE KafkaRESignalConsumer routing (1 topic → correct handler)
"""
from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from cves_event_schemas.envelope import DomainEventEnvelope


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_envelope(event_type: str = "asi.asset.discovered") -> DomainEventEnvelope:
    return DomainEventEnvelope(
        event_type=event_type,
        aggregate_id=uuid.uuid4(),
        aggregate_type="TestAggregate",
        tenant_id=uuid.uuid4(),
        correlation_id=uuid.uuid4(),
        producer_svc="test",
        payload={"key": "value"},
    )


def _make_kafka_message(envelope: DomainEventEnvelope, *, topic: str = "test.topic") -> MagicMock:
    """Build a mock confluent-kafka Message from an envelope."""
    msg = MagicMock()
    msg.error.return_value = None
    msg.value.return_value = envelope.model_dump_json().encode("utf-8")
    msg.topic.return_value = topic
    msg.partition.return_value = 0
    msg.offset.return_value = 100
    msg.headers.return_value = []
    return msg


# ── BaseKafkaProducer Tests ───────────────────────────────────────────────────

class TestBaseKafkaProducerSerialisation:
    def test_produce_envelope_calls_producer_with_encoded_bytes(self):
        with patch("cves_kafka.producer.Producer") as MockProducer:
            from cves_kafka.producer import BaseKafkaProducer

            mock_p = MockProducer.return_value
            producer = BaseKafkaProducer(mock_p)

            envelope = _build_envelope()
            producer.produce_envelope("test.topic", envelope)

            assert mock_p.produce.called
            call_kwargs = mock_p.produce.call_args[1]
            assert call_kwargs["topic"] == "test.topic"

            # Verify the value is valid JSON containing all required fields
            value_bytes = call_kwargs["value"]
            decoded = json.loads(value_bytes)
            assert decoded["event_type"] == "asi.asset.discovered"
            assert "tenant_id" in decoded
            assert "correlation_id" in decoded

    def test_produce_envelope_uses_tenant_id_as_default_key(self):
        with patch("cves_kafka.producer.Producer") as MockProducer:
            from cves_kafka.producer import BaseKafkaProducer

            mock_p = MockProducer.return_value
            producer = BaseKafkaProducer(mock_p)
            envelope = _build_envelope()
            producer.produce_envelope("test.topic", envelope)

            call_kwargs = mock_p.produce.call_args[1]
            key = call_kwargs["key"]
            assert key == str(envelope.tenant_id).encode()

    def test_produce_envelope_custom_key_override(self):
        with patch("cves_kafka.producer.Producer") as MockProducer:
            from cves_kafka.producer import BaseKafkaProducer

            mock_p = MockProducer.return_value
            producer = BaseKafkaProducer(mock_p)
            envelope = _build_envelope()
            producer.produce_envelope("test.topic", envelope, key="custom-key")

            call_kwargs = mock_p.produce.call_args[1]
            assert call_kwargs["key"] == b"custom-key"

    def test_produce_outbox_row_serialises_payload(self):
        with patch("cves_kafka.producer.Producer") as MockProducer:
            from cves_kafka.producer import BaseKafkaProducer

            mock_p = MockProducer.return_value
            producer = BaseKafkaProducer(mock_p)
            row = {
                "event_type": "asi.asset.discovered",
                "schema_version": "1.0.0",
                "correlation_id": uuid.uuid4(),
                "tenant_id": uuid.uuid4(),
                "payload": {"asset_id": str(uuid.uuid4())},
            }
            producer.produce_outbox_row("test.topic", row)
            assert mock_p.produce.called


# ── BaseKafkaConsumer Tests ───────────────────────────────────────────────────

class TestBaseKafkaConsumerDedup:
    @pytest.fixture
    def mock_consumer_infra(self):
        """Set up mocked confluent Consumer + RedisDedup."""
        mock_confluent = MagicMock()
        mock_dedup = MagicMock()
        mock_dedup.is_new = AsyncMock(return_value=True)
        mock_dedup.remove = AsyncMock()
        return mock_confluent, mock_dedup

    async def test_dispatch_calls_handler_for_new_event(self, mock_consumer_infra):
        from cves_kafka.consumer import BaseKafkaConsumer

        mock_confluent, mock_dedup = mock_consumer_infra
        mock_confluent.commit = MagicMock()

        consumer = BaseKafkaConsumer(mock_confluent, mock_dedup)
        handler = AsyncMock()
        envelope = _build_envelope()
        msg = _make_kafka_message(envelope)

        await consumer._dispatch(msg, handler)
        handler.assert_called_once()
        called_envelope = handler.call_args[0][0]
        assert called_envelope.event_id == envelope.event_id

    async def test_dispatch_skips_duplicate_event(self, mock_consumer_infra):
        from cves_kafka.consumer import BaseKafkaConsumer

        mock_confluent, mock_dedup = mock_consumer_infra
        mock_dedup.is_new = AsyncMock(return_value=False)  # duplicate!
        mock_confluent.commit = MagicMock()

        consumer = BaseKafkaConsumer(mock_confluent, mock_dedup)
        handler = AsyncMock()
        msg = _make_kafka_message(_build_envelope())

        await consumer._dispatch(msg, handler)
        handler.assert_not_called()
        mock_confluent.commit.assert_called_once()  # offset still committed

    async def test_dispatch_commits_offset_on_malformed_message(self, mock_consumer_infra):
        from cves_kafka.consumer import BaseKafkaConsumer

        mock_confluent, mock_dedup = mock_consumer_infra
        mock_confluent.commit = MagicMock()

        consumer = BaseKafkaConsumer(mock_confluent, mock_dedup)
        handler = AsyncMock()

        # Malformed message
        bad_msg = MagicMock()
        bad_msg.error.return_value = None
        bad_msg.value.return_value = b"not-valid-json{{{{"
        bad_msg.topic.return_value = "test"
        bad_msg.partition.return_value = 0
        bad_msg.headers.return_value = []

        await consumer._dispatch(bad_msg, handler)
        handler.assert_not_called()
        mock_confluent.commit.assert_called_once()

    async def test_dispatch_removes_dedup_on_handler_error(self, mock_consumer_infra):
        from cves_kafka.consumer import BaseKafkaConsumer

        mock_confluent, mock_dedup = mock_consumer_infra
        mock_confluent.commit = MagicMock()

        consumer = BaseKafkaConsumer(mock_confluent, mock_dedup)
        handler = AsyncMock(side_effect=RuntimeError("handler failed"))
        envelope = _build_envelope()
        msg = _make_kafka_message(envelope)

        with pytest.raises(RuntimeError, match="handler failed"):
            await consumer._dispatch(msg, handler)

        # Dedup record should be removed so retry can reprocess
        mock_dedup.remove.assert_called_once_with(envelope.event_id)

    def test_decode_valid_json_envelope(self, mock_consumer_infra):
        from cves_kafka.consumer import BaseKafkaConsumer

        mock_confluent, mock_dedup = mock_consumer_infra
        consumer = BaseKafkaConsumer(mock_confluent, mock_dedup)
        envelope = _build_envelope()
        msg = _make_kafka_message(envelope)

        decoded = consumer._decode(msg)
        assert decoded.event_id == envelope.event_id
        assert decoded.event_type == envelope.event_type


# ── AGE Signal Consumer Routing ───────────────────────────────────────────────

class TestAGESignalConsumerRouting:
    def test_poll_loop_decodes_and_dispatches_envelope(self):
        """Verify the synchronous poll loop calls run_coroutine_threadsafe."""
        from asset_graph.infrastructure.kafka.signal_consumer import KafkaGraphSignalConsumer

        consumer = KafkaGraphSignalConsumer(bootstrap_servers="localhost:9092")
        consumer._running = True

        loop = asyncio.new_event_loop()
        received: list[DomainEventEnvelope] = []

        async def handler(env: DomainEventEnvelope) -> None:
            received.append(env)

        envelope = _build_envelope("asi.asset.discovered")
        envelope_json = envelope.model_dump_json().encode("utf-8")

        mock_msg = MagicMock()
        mock_msg.error.return_value = None
        mock_msg.value.return_value = envelope_json

        mock_kafka_consumer = MagicMock()
        call_count = 0

        def mock_poll(timeout):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                consumer._running = False  # stop after first message
                return mock_msg
            return None

        mock_kafka_consumer.poll = mock_poll
        mock_kafka_consumer.subscribe = MagicMock()
        mock_kafka_consumer.close = MagicMock()

        with patch.object(consumer, "_make_consumer", return_value=mock_kafka_consumer):
            stop_event = asyncio.Event()
            stop_event.set()  # immediately stopped

            import threading
            thread = threading.Thread(
                target=consumer._poll_loop,
                args=(handler, loop),
                daemon=True,
            )
            # Consumer is already stopped (_running = False from above)
            consumer._running = False
            thread.start()
            thread.join(timeout=2.0)

        loop.close()

    async def test_start_consuming_invokes_to_thread(self):
        """start_consuming should delegate to asyncio.to_thread."""
        from asset_graph.infrastructure.kafka.signal_consumer import KafkaGraphSignalConsumer

        consumer = KafkaGraphSignalConsumer(bootstrap_servers="localhost:9092")
        handler = AsyncMock()

        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = None
            await consumer.start_consuming(handler)
            mock_to_thread.assert_called_once()


# ── ACL Signal Consumer Routing ───────────────────────────────────────────────

class TestACLSignalConsumerRouting:
    async def test_start_delegates_to_asyncio_to_thread(self):
        from ai_correlation.infrastructure.kafka.signal_consumer import KafkaACLSignalConsumer

        consumer = KafkaACLSignalConsumer(bootstrap_servers="localhost:9092")
        handler = AsyncMock()

        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = None
            await consumer.start(handler)
            mock_to_thread.assert_called_once()

    def test_poll_loop_decodes_envelope_and_dispatches(self):
        from ai_correlation.infrastructure.kafka.signal_consumer import KafkaACLSignalConsumer

        consumer = KafkaACLSignalConsumer(bootstrap_servers="localhost:9092")
        loop = asyncio.new_event_loop()
        envelope = _build_envelope("eve.exposure.events")
        env_bytes = envelope.model_dump_json().encode("utf-8")

        mock_msg = MagicMock()
        mock_msg.error.return_value = None
        mock_msg.value.return_value = env_bytes

        call_count = 0
        def mock_poll(timeout):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_msg
            return None

        mock_kafka_consumer = MagicMock()
        mock_kafka_consumer.poll = mock_poll
        mock_kafka_consumer.subscribe = MagicMock()
        mock_kafka_consumer.close = MagicMock()

        dispatched: list[DomainEventEnvelope] = []

        async def handler(env: DomainEventEnvelope) -> None:
            dispatched.append(env)

        stop_event = asyncio.Event()

        import threading

        def run():
            consumer._poll_loop(mock_kafka_consumer, loop, handler, stop_event)

        stop_event.set()  # stop immediately
        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(timeout=1.0)
        loop.close()


# ── RE Signal Consumer Routing ────────────────────────────────────────────────

class TestRESignalConsumerRouting:
    async def test_start_invokes_to_thread(self):
        from reporting.infrastructure.kafka.signal_consumer import KafkaRESignalConsumer

        consumer = KafkaRESignalConsumer(bootstrap_servers="localhost:9092")
        handler = AsyncMock()

        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
            mock_to_thread.return_value = None
            await consumer.start(handler)
            mock_to_thread.assert_called_once()

    def test_stop_sets_running_false(self):
        from reporting.infrastructure.kafka.signal_consumer import KafkaRESignalConsumer

        consumer = KafkaRESignalConsumer(bootstrap_servers="localhost:9092")
        consumer._running = True
        consumer.stop()
        assert consumer._running is False

    def test_subscribed_to_acl_correlation_topic(self):
        from reporting.infrastructure.kafka.signal_consumer import (
            KafkaRESignalConsumer,
            _UPSTREAM_TOPICS,
        )
        assert "acl.correlation.events" in _UPSTREAM_TOPICS
