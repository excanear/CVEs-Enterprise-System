"""AI Correlation Layer client — /correlation/*"""
from __future__ import annotations

from cves_cli.client.base import CVEsHTTPClient


class CorrelationClient:
    def __init__(self, http: CVEsHTTPClient) -> None:
        self._h = http

    async def trigger(self, *, tenant_id: str) -> dict:
        return await self._h.post("/correlation/sessions", json={"tenant_id": tenant_id})  # type: ignore[return-value]

    async def get_session(self, session_id: str) -> dict:
        return await self._h.get(f"/correlation/sessions/{session_id}")  # type: ignore[return-value]

    async def clusters(self, *, tenant_id: str, session_id: str | None = None) -> list:
        params: dict = {"tenant_id": tenant_id}
        if session_id:
            params["session_id"] = session_id
        return await self._h.get("/correlation/clusters", params=params)  # type: ignore[return-value]

    async def ranked_paths(self, *, tenant_id: str, limit: int = 50) -> list:
        return await self._h.get(  # type: ignore[return-value]
            "/correlation/attack-paths/ranked",
            params={"tenant_id": tenant_id, "limit": limit},
        )

    async def prioritized_exposures(self, *, tenant_id: str) -> list:
        return await self._h.get(  # type: ignore[return-value]
            "/correlation/exposures/prioritized", params={"tenant_id": tenant_id}
        )

    async def remediation(self, cluster_id: str) -> dict:
        return await self._h.get(f"/correlation/remediation/{cluster_id}")  # type: ignore[return-value]

    async def risk_summary(self, *, tenant_id: str) -> dict:
        return await self._h.get("/correlation/risk-summary", params={"tenant_id": tenant_id})  # type: ignore[return-value]
