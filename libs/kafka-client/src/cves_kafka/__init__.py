"""cves_kafka — Kafka producer/consumer infrastructure with transactional guarantees."""

from .producer import BaseKafkaProducer
from .consumer import BaseKafkaConsumer
from .dedup import RedisDedup

__all__ = ["BaseKafkaProducer", "BaseKafkaConsumer", "RedisDedup"]
