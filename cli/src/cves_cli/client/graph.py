"""Asset Graph Engine API client — /graph/*"""
from __future__ import annotations

from cves_cli.client.base import CVEsHTTPClient


class GraphClient:
    def __init__(self, http: CVEsHTTPClient) -> None:
        self._h = http

    async def list_assets(self, *, tenant_id: str, limit: int = 100, offset: int = 0) -> list:
        return await self._h.get(  # type: ignore[return-value]
            "/graph/assets", params={"tenant_id": tenant_id, "limit": limit, "offset": offset}
        )

    async def attack_paths(self, *, tenant_id: str, max_paths: int = 20) -> list:
        return await self._h.get(  # type: ignore[return-value]
            "/graph/attack-paths", params={"tenant_id": tenant_id, "max_paths": max_paths}
        )

    async def trust_chains(self, *, tenant_id: str, asset_id: str, max_depth: int = 10) -> list:
        return await self._h.get(  # type: ignore[return-value]
            "/graph/trust-chains",
            params={"tenant_id": tenant_id, "asset_id": asset_id, "max_depth": max_depth},
        )

    async def propagation(self, *, tenant_id: str, endpoint_id: str) -> list:
        return await self._h.get(  # type: ignore[return-value]
            "/graph/exposure-propagation",
            params={"tenant_id": tenant_id, "endpoint_id": endpoint_id},
        )

    async def dependencies(self, *, tenant_id: str) -> list:
        return await self._h.get("/graph/dependencies", params={"tenant_id": tenant_id})  # type: ignore[return-value]

    async def stats(self, *, tenant_id: str) -> dict:
        return await self._h.get("/graph/stats", params={"tenant_id": tenant_id})  # type: ignore[return-value]

    async def ingest(self, *, tenant_id: str, event_type: str, payload: dict) -> dict:
        return await self._h.post(  # type: ignore[return-value]
            "/graph/ingest",
            json={"tenant_id": tenant_id, "event_type": event_type, "payload": payload},
        )
