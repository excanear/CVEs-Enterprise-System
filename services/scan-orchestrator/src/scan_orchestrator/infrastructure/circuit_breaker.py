"""Per-target circuit breaker — prevents hammering unresponsive hosts.

States:
  CLOSED     — normal operation, requests pass through.
  OPEN       — target is failing; all requests rejected immediately.
  HALF_OPEN  — probe mode; one request passes through to test recovery.

Transitions:
  CLOSED  → OPEN       after consecutive_failures >= threshold
  OPEN    → HALF_OPEN  after reset_timeout_seconds elapses
  HALF_OPEN→ CLOSED    on success
  HALF_OPEN→ OPEN      on failure (reset the timeout)

State is stored in Redis so all workers share the same circuit state.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

_CB_TTL: Final[int] = 86400     # auto-expire unused circuit entries after 1 day

_CHECK_AND_TRIP_LUA = """
local key                = KEYS[1]
local threshold          = tonumber(ARGV[1])
local half_open_timeout  = tonumber(ARGV[2])
local now                = tonumber(ARGV[3])
local ttl                = tonumber(ARGV[4])

local state = redis.call('HGET', key, 'state') or 'CLOSED'
local failures = tonumber(redis.call('HGET', key, 'failures') or '0')
local opened_at = tonumber(redis.call('HGET', key, 'opened_at') or '0')

if state == 'OPEN' then
    if now - opened_at >= half_open_timeout then
        redis.call('HSET', key, 'state', 'HALF_OPEN')
        redis.call('EXPIRE', key, ttl)
        return 'HALF_OPEN'
    end
    return 'OPEN'
end

return state
"""

_RECORD_FAILURE_LUA = """
local key                = KEYS[1]
local threshold          = tonumber(ARGV[1])
local now                = tonumber(ARGV[2])
local ttl                = tonumber(ARGV[3])

local failures = tonumber(redis.call('HINCRBY', key, 'failures', 1))
local state = redis.call('HGET', key, 'state') or 'CLOSED'

if failures >= threshold and state ~= 'OPEN' then
    redis.call('HMSET', key, 'state', 'OPEN', 'opened_at', now, 'failures', failures)
    redis.call('EXPIRE', key, ttl)
    return 'OPEN'
end

redis.call('EXPIRE', key, ttl)
return state
"""

_RECORD_SUCCESS_LUA = """
local key = KEYS[1]
local ttl = tonumber(ARGV[1])

redis.call('HMSET', key, 'state', 'CLOSED', 'failures', '0', 'opened_at', '0')
redis.call('EXPIRE', key, ttl)
return 'CLOSED'
"""


class CircuitState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    reset_timeout_seconds: float = 60.0
    namespace: str = "cb:scan"


class CircuitBreaker:
    """Redis-backed distributed circuit breaker for scan targets."""

    def __init__(self, redis: aioredis.Redis, config: CircuitBreakerConfig | None = None) -> None:
        self._redis = redis
        self._cfg = config or CircuitBreakerConfig()
        self._check_script = redis.register_script(_CHECK_AND_TRIP_LUA)
        self._fail_script = redis.register_script(_RECORD_FAILURE_LUA)
        self._ok_script = redis.register_script(_RECORD_SUCCESS_LUA)

    def _key(self, target: str) -> str:
        return f"{self._cfg.namespace}:{target}"

    async def check(self, target: str) -> CircuitState:
        """Returns the current circuit state for the target.

        Callers MUST check before executing — if OPEN, skip the operation.
        """
        state_raw = await self._check_script(
            keys=[self._key(target)],
            args=[
                self._cfg.failure_threshold,
                self._cfg.reset_timeout_seconds,
                time.time(),
                _CB_TTL,
            ],
        )
        state = CircuitState(state_raw or "CLOSED")
        if state == CircuitState.OPEN:
            logger.debug("circuit_breaker.open", extra={"target": target})
        return state

    async def record_failure(self, target: str) -> CircuitState:
        """Increment failure counter; trip to OPEN if threshold reached."""
        state_raw = await self._fail_script(
            keys=[self._key(target)],
            args=[self._cfg.failure_threshold, time.time(), _CB_TTL],
        )
        state = CircuitState(state_raw or "CLOSED")
        if state == CircuitState.OPEN:
            logger.warning("circuit_breaker.tripped", extra={"target": target})
        return state

    async def record_success(self, target: str) -> None:
        """Reset the circuit to CLOSED on a successful probe (HALF_OPEN → CLOSED)."""
        await self._ok_script(keys=[self._key(target)], args=[_CB_TTL])
        logger.debug("circuit_breaker.recovered", extra={"target": target})

    async def get_status(self, target: str) -> dict:
        key = self._key(target)
        data = await self._redis.hgetall(key)
        return {
            "target": target,
            "state": (data.get(b"state", b"CLOSED")).decode(),
            "failures": int(data.get(b"failures", b"0")),
            "opened_at": float(data.get(b"opened_at", b"0")),
            "threshold": self._cfg.failure_threshold,
        }
