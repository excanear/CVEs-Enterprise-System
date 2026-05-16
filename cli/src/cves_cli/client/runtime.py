"""Runtime Analysis Engine client — /runtime-analysis/*"""
from __future__ import annotations

from cves_cli.client.base import CVEsHTTPClient


class RuntimeClient:
    def __init__(self, http: CVEsHTTPClient) -> None:
        self._h = http

    async def analyze(
        self,
        *,
        tenant_id: str,
        target_url: str,
        max_spa_routes: int = 20,
        timeout_seconds: int = 120,
    ) -> dict:
        return await self._h.post(  # type: ignore[return-value]
            "/runtime-analysis/sessions",
            json={
                "tenant_id": tenant_id,
                "target_url": target_url,
                "max_spa_routes": max_spa_routes,
                "timeout_seconds": timeout_seconds,
            },
        )

    async def get_session(self, session_id: str) -> dict:
        return await self._h.get(f"/runtime-analysis/sessions/{session_id}")  # type: ignore[return-value]

    async def list_sessions(self, *, tenant_id: str, limit: int = 20) -> list:
        return await self._h.get(  # type: ignore[return-value]
            "/runtime-analysis/sessions", params={"tenant_id": tenant_id, "limit": limit}
        )

    async def get_result(self, session_id: str) -> dict:
        return await self._h.get(f"/runtime-analysis/sessions/{session_id}/result")  # type: ignore[return-value]

    async def get_apis(self, session_id: str, *, limit: int = 100) -> list:
        return await self._h.get(  # type: ignore[return-value]
            f"/runtime-analysis/sessions/{session_id}/apis", params={"limit": limit}
        )
