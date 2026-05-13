"""Async Confluent Schema Registry client.

Used by producers (register) and consumers (fetch) to resolve Avro schemas
by subject + version.

Authentication: HTTP Basic (registry_url already contains credentials, or
pass api_key/api_secret for Confluent Cloud).
"""
from __future__ import annotations

import base64
import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class SchemaRegistryClient:
    """Minimal async Schema Registry client (Confluent REST API v1).

    Thread-safe: uses a single shared httpx.AsyncClient with connection pooling.
    """

    def __init__(
        self,
        *,
        registry_url: str,
        api_key: str | None = None,
        api_secret: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        headers = {"Accept": "application/vnd.schemaregistry.v1+json"}
        auth = None
        if api_key and api_secret:
            credentials = base64.b64encode(f"{api_key}:{api_secret}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"
        self._client = httpx.AsyncClient(
            base_url=registry_url.rstrip("/"),
            headers=headers,
            timeout=timeout,
        )

    # ── Register ──────────────────────────────────────────────────────────

    async def register_schema(self, subject: str, schema_str: str) -> int:
        """Register a schema and return its schema ID.

        Idempotent — returns existing schema ID if schema is unchanged.
        """
        payload = {"schema": schema_str}
        resp = await self._client.post(
            f"/subjects/{subject}/versions",
            content=json.dumps(payload),
            headers={"Content-Type": "application/vnd.schemaregistry.v1+json"},
        )
        resp.raise_for_status()
        return resp.json()["id"]

    # ── Fetch by ID ───────────────────────────────────────────────────────

    async def get_schema_by_id(self, schema_id: int) -> str:
        """Return the Avro schema string for a given schema ID."""
        resp = await self._client.get(f"/schemas/ids/{schema_id}")
        resp.raise_for_status()
        return resp.json()["schema"]

    # ── Fetch by subject ──────────────────────────────────────────────────

    async def get_latest_schema(self, subject: str) -> dict[str, Any]:
        """Return the latest registered version metadata for a subject."""
        resp = await self._client.get(f"/subjects/{subject}/versions/latest")
        resp.raise_for_status()
        return resp.json()

    async def get_schema_version(self, subject: str, version: int) -> dict[str, Any]:
        resp = await self._client.get(f"/subjects/{subject}/versions/{version}")
        resp.raise_for_status()
        return resp.json()

    # ── Compatibility ─────────────────────────────────────────────────────

    async def check_compatibility(self, subject: str, schema_str: str) -> bool:
        """Return True if schema_str is compatible with the latest version."""
        payload = {"schema": schema_str}
        resp = await self._client.post(
            f"/compatibility/subjects/{subject}/versions/latest",
            content=json.dumps(payload),
            headers={"Content-Type": "application/vnd.schemaregistry.v1+json"},
        )
        resp.raise_for_status()
        return resp.json().get("is_compatible", False)

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "SchemaRegistryClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()
