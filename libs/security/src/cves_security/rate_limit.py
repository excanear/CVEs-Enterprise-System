"""Redis sliding-window rate limiter.

Algorithm: INCR + EXPIRE per key per window.
  Key: "ratelimit:{api_key_id}:{tenant_id}:{window_start_seconds}"
  Window: configurable (default 60 s).
  Limit: configurable requests per window.

This is a fixed-window approximation. Use a sliding window Lua script
for strict enforcement if needed at higher QPS.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from typing import Final

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

_DEFAULT_WINDOW_SECONDS: Final[int] = 60
_DEFAULT_MAX_REQUESTS: Final[int] = 500

_LUA_SLIDING_WINDOW = """
local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local window_start = now - window

redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
local count = redis.call('ZCARD', key)

if count >= limit then
    return {0, count}
end

redis.call('ZADD', key, now, now .. '-' .. math.random())
redis.call('EXPIRE', key, window)
return {1, count + 1}
"""


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    current_count: int
    limit: int
    window_seconds: int


class RateLimiter:
    """Async Redis sliding-window rate limiter (sorted-set algorithm).

    Usage::

        limiter = RateLimiter(redis_client, max_requests=200, window_seconds=60)
        result = await limiter.check(api_key_id=uuid, tenant_id=uuid)
        if not result.allowed:
            raise HTTPException(429)
    """

    def __init__(
        self,
        redis: aioredis.Redis,
        *,
        max_requests: int = _DEFAULT_MAX_REQUESTS,
        window_seconds: int = _DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self._redis = redis
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._script = redis.register_script(_LUA_SLIDING_WINDOW)

    def _key(self, api_key_id: uuid.UUID, tenant_id: uuid.UUID) -> str:
        return f"ratelimit:{api_key_id}:{tenant_id}"

    async def check(
        self,
        *,
        api_key_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> RateLimitResult:
        """Check and increment the rate limit counter.

        Returns a RateLimitResult — always check .allowed before proceeding.
        """
        key = self._key(api_key_id, tenant_id)
        now_ms = int(time.time() * 1000)

        allowed_raw, count_raw = await self._script(
            keys=[key],
            args=[self._window_seconds * 1000, self._max_requests, now_ms],
        )
        return RateLimitResult(
            allowed=bool(allowed_raw),
            current_count=int(count_raw),
            limit=self._max_requests,
            window_seconds=self._window_seconds,
        )
