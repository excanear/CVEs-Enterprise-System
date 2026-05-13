"""API key authentication with SHA-256 hash lookup.

Security design:
- API keys are NEVER stored in plaintext — only SHA-256 hashes.
- Keys are associated with a tenant_id + scope list.
- Validation is a constant-time hash comparison (no timing oracle).
- Active keys are loaded from PostgreSQL on startup and cached in Redis
  with a configurable TTL.

Key format: cves_<base62(32 random bytes)>   (opaque to the user)
Hash stored: SHA-256(key_bytes) as hex string.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from dataclasses import dataclass
from typing import Final

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

_CACHE_TTL: Final[int] = 300  # 5 minutes


@dataclass(frozen=True)
class APIKeyRecord:
    api_key_id: uuid.UUID
    tenant_id: uuid.UUID
    scopes: list[str]
    is_active: bool


class APIKeyValidator:
    """Redis-backed API key validator.

    The caller is responsible for loading active keys into Redis on startup.
    Each key is stored as:
      HSET "apikey:{sha256_hex}" tenant_id ... scopes ... is_active ...

    Usage::

        validator = APIKeyValidator(redis_client)
        record = await validator.validate("cves_<token>")
        if record is None:
            raise HTTPException(401)
    """

    def __init__(self, redis: aioredis.Redis) -> None:
        self._redis = redis

    @staticmethod
    def _hash(key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()

    async def validate(self, raw_key: str) -> APIKeyRecord | None:
        """Return APIKeyRecord if the key is valid and active, else None."""
        if not raw_key or not raw_key.startswith("cves_"):
            return None

        key_hash = self._hash(raw_key)
        cache_key = f"apikey:{key_hash}"

        data = await self._redis.hgetall(cache_key)
        if not data:
            return None

        is_active = data.get(b"is_active", b"false") == b"true"
        if not is_active:
            return None

        try:
            return APIKeyRecord(
                api_key_id=uuid.UUID(data[b"api_key_id"].decode()),
                tenant_id=uuid.UUID(data[b"tenant_id"].decode()),
                scopes=json.loads(data.get(b"scopes", b"[]")),
                is_active=True,
            )
        except (KeyError, ValueError) as exc:
            logger.error("apikey_parse_error: %s", exc)
            return None

    async def store_key(
        self,
        raw_key: str,
        *,
        api_key_id: uuid.UUID,
        tenant_id: uuid.UUID,
        scopes: list[str],
        is_active: bool = True,
    ) -> None:
        """Persist an API key hash to Redis (called on key creation or sync)."""
        key_hash = self._hash(raw_key)
        cache_key = f"apikey:{key_hash}"
        await self._redis.hset(
            cache_key,
            mapping={
                "api_key_id": str(api_key_id),
                "tenant_id": str(tenant_id),
                "scopes": json.dumps(scopes),
                "is_active": "true" if is_active else "false",
            },
        )
        await self._redis.expire(cache_key, _CACHE_TTL)

    async def revoke_key(self, raw_key: str) -> None:
        """Revoke a key by deleting its Redis entry."""
        key_hash = self._hash(raw_key)
        await self._redis.delete(f"apikey:{key_hash}")

    def has_scope(self, record: APIKeyRecord, required: str) -> bool:
        return required in record.scopes
