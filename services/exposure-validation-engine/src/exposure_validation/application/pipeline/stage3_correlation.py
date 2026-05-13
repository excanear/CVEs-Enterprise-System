"""Stage 3 — Correlation: groups signals from the same endpoint across engines.

Uses Redis sorted sets to accumulate signal counts per endpoint per tenant.
A +0.15 bonus is applied to the inference score when 2+ different engines
have reported the same endpoint.

Key format: eve:correlation:{tenant_id}:{sha256_hex(endpoint_url)}
TTL: 300 s (signals expire after 5 minutes to avoid stale data).
"""
from __future__ import annotations

import hashlib

import redis.asyncio as aioredis
import structlog

from exposure_validation.domain.value_objects.exposure_candidate import ExposureCandidate

log = structlog.get_logger(__name__)

_TTL_SECONDS = 300
_MULTI_ENGINE_THRESHOLD = 2
_MULTI_ENGINE_BONUS = 0.15


def _endpoint_key(tenant_id: str, endpoint_url: str) -> str:
    h = hashlib.sha256(endpoint_url.encode()).hexdigest()
    return f"eve:correlation:{tenant_id}:{h}"


class CorrelationStage:
    @staticmethod
    async def correlate(
        candidate: ExposureCandidate,
        redis_client: aioredis.Redis,
    ) -> int:
        """Record this signal and return the cumulative cross-engine signal count."""
        endpoint_url = candidate.full_url
        key = _endpoint_key(candidate.tenant_id, endpoint_url)

        try:
            count = await redis_client.incr(key)
            await redis_client.expire(key, _TTL_SECONDS)
            log.debug("eve.stage3.signal_recorded", endpoint=endpoint_url, count=count)
            return int(count)
        except Exception as exc:
            log.warning("eve.stage3.redis_error", error=str(exc))
            return 1  # assume single signal on Redis failure

    @staticmethod
    def apply_bonus(inference_score: float, correlation_count: int) -> float:
        """Return score with optional cross-engine bonus applied."""
        if correlation_count >= _MULTI_ENGINE_THRESHOLD:
            return min(inference_score + _MULTI_ENGINE_BONUS, 0.95)
        return inference_score
