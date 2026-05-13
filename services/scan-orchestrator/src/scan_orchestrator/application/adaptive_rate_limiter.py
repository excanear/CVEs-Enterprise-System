"""Adaptive token-bucket rate limiter per scan target.

Algorithm:
  - Each target key (IP/FQDN) gets its own token bucket.
  - Bucket refills at `current_rps` tokens per second.
  - On HTTP 429 or rate-limit signals → current_rps *= (1 - backoff_factor)
  - On timeout → current_rps *= (1 - backoff_factor * 0.5)
  - On success → current_rps = min(current_rps * recovery_factor, max_rps)
  - Rates are clamped to [min_rps, max_rps].

State is stored in Redis so multiple workers servicing the same target
share the same rate budget.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Final

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

_BUCKET_TTL: Final[int] = 3600          # expire unused buckets after 1 h
_TOKEN_PRECISION: Final[int] = 1000     # store as integer × 1000 for atomicity

# Lua script: atomic token acquire from the bucket.
# Returns 1 if acquired, 0 if throttled.
_ACQUIRE_LUA = """
local key        = KEYS[1]
local now        = tonumber(ARGV[1])
local max_rps    = tonumber(ARGV[2])
local min_rps    = tonumber(ARGV[3])
local precision  = tonumber(ARGV[4])
local ttl        = tonumber(ARGV[5])

local data = redis.call('HMGET', key, 'tokens', 'last_refill', 'current_rps')
local tokens      = tonumber(data[1]) or (max_rps * precision)
local last_refill = tonumber(data[2]) or now
local current_rps = tonumber(data[3]) or (max_rps * precision)

-- Refill tokens based on elapsed time
local elapsed = math.max(0, now - last_refill)
local new_tokens = tokens + elapsed * current_rps / 1000
local bucket_max = current_rps  -- bucket capacity = 1 second worth of tokens

if new_tokens > bucket_max then new_tokens = bucket_max end

local allowed = 0
if new_tokens >= precision then
    new_tokens = new_tokens - precision
    allowed = 1
end

redis.call('HMSET', key,
    'tokens', math.floor(new_tokens),
    'last_refill', now,
    'current_rps', current_rps
)
redis.call('EXPIRE', key, ttl)
return allowed
"""

# Adjust rate — returns new current_rps * precision
_ADJUST_LUA = """
local key         = KEYS[1]
local factor      = tonumber(ARGV[1])   -- multiply factor (< 1 to slow, > 1 to speed up)
local min_val     = tonumber(ARGV[2])
local max_val     = tonumber(ARGV[3])
local ttl         = tonumber(ARGV[4])

local current_rps = tonumber(redis.call('HGET', key, 'current_rps')) or max_val
local new_rps = current_rps * factor

if new_rps < min_val then new_rps = min_val end
if new_rps > max_val then new_rps = max_val end

redis.call('HSET', key, 'current_rps', math.floor(new_rps))
redis.call('EXPIRE', key, ttl)
return math.floor(new_rps)
"""


@dataclass
class AdaptiveRateLimiter:
    """Per-target adaptive token-bucket rate limiter backed by Redis."""

    redis: aioredis.Redis
    initial_rps: float = 10.0
    min_rps: float = 0.5
    max_rps: float = 100.0
    backoff_factor: float = 0.5          # rate reduction on throttle signal
    timeout_factor: float = 0.25         # rate reduction on timeout (gentler)
    recovery_factor: float = 1.1         # rate increase on success
    namespace: str = "ratelimit:scan"

    _acquire_script: object = field(init=False, repr=False)
    _adjust_script: object = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._acquire_script = self.redis.register_script(_ACQUIRE_LUA)
        self._adjust_script = self.redis.register_script(_ADJUST_LUA)

    def _key(self, target: str) -> str:
        return f"{self.namespace}:{target}"

    async def acquire(self, target: str, *, wait: bool = True) -> bool:
        """Acquire a rate-limit token for the target.

        If wait=True, blocks until a token is available.
        If wait=False, returns False immediately if throttled.
        """
        key = self._key(target)
        while True:
            allowed = await self._acquire_script(
                keys=[key],
                args=[
                    int(time.monotonic() * 1000),
                    int(self.max_rps * _TOKEN_PRECISION),
                    int(self.min_rps * _TOKEN_PRECISION),
                    _TOKEN_PRECISION,
                    _BUCKET_TTL,
                ],
            )
            if allowed:
                return True
            if not wait:
                return False
            # Wait roughly one token worth of time before retrying
            current_rps = await self._get_current_rps(target)
            wait_s = 1.0 / max(current_rps, self.min_rps)
            await asyncio.sleep(wait_s)

    async def record_success(self, target: str) -> None:
        """Signal a successful request — nudge rate upward."""
        await self._adjust_rate(target, self.recovery_factor)

    async def record_throttle(self, target: str) -> None:
        """Signal HTTP 429 or explicit rate-limit — aggressively reduce rate."""
        factor = 1.0 - self.backoff_factor
        await self._adjust_rate(target, factor)
        logger.info("adaptive_rate.throttle", extra={"target": target, "factor": factor})

    async def record_timeout(self, target: str) -> None:
        """Signal connection timeout — gently reduce rate."""
        factor = 1.0 - self.timeout_factor
        await self._adjust_rate(target, factor)
        logger.info("adaptive_rate.timeout", extra={"target": target, "factor": factor})

    async def get_stats(self, target: str) -> dict:
        key = self._key(target)
        data = await self.redis.hgetall(key)
        current_rps = float(data.get(b"current_rps", b"0")) / _TOKEN_PRECISION
        tokens = float(data.get(b"tokens", b"0")) / _TOKEN_PRECISION
        return {
            "target": target,
            "current_rps": round(current_rps, 3),
            "available_tokens": round(tokens, 3),
            "min_rps": self.min_rps,
            "max_rps": self.max_rps,
        }

    async def _adjust_rate(self, target: str, factor: float) -> None:
        await self._adjust_script(
            keys=[self._key(target)],
            args=[
                factor,
                int(self.min_rps * _TOKEN_PRECISION),
                int(self.max_rps * _TOKEN_PRECISION),
                _BUCKET_TTL,
            ],
        )

    async def _get_current_rps(self, target: str) -> float:
        raw = await self.redis.hget(self._key(target), "current_rps")
        if not raw:
            return self.initial_rps
        return float(raw) / _TOKEN_PRECISION
