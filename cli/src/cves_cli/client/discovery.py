"""Discovery Engine API client — /api/v1/discovery/*"""
from __future__ import annotations

from cves_cli.client.base import CVEsHTTPClient


class DiscoveryClient:
    def __init__(self, http: CVEsHTTPClient) -> None:
        self._h = http

    async def start(
        self,
        *,
        target_domain: str,
        scope_domains: list[str] | None = None,
        max_depth: int = 3,
        max_pages: int = 200,
        max_rps: float = 5.0,
        allow_internal: bool = False,
    ) -> dict:
        return await self._h.post(  # type: ignore[return-value]
            "/api/v1/discovery/jobs",
            json={
                "target_domain": target_domain,
                "scope_domains": scope_domains or [target_domain],
                "max_depth": max_depth,
                "max_pages": max_pages,
                "max_rps": max_rps,
                "allow_internal": allow_internal,
            },
        )

    async def list_jobs(self, *, limit: int = 20) -> list:
        return await self._h.get("/api/v1/discovery/jobs", params={"limit": limit})  # type: ignore[return-value]

    async def get_job(self, job_id: str) -> dict:
        return await self._h.get(f"/api/v1/discovery/jobs/{job_id}")  # type: ignore[return-value]

    async def job_assets(self, job_id: str, *, asset_type: str | None = None) -> list:
        params = {}
        if asset_type:
            params["asset_type"] = asset_type
        return await self._h.get(f"/api/v1/discovery/jobs/{job_id}/assets", params=params)  # type: ignore[return-value]

    async def list_assets(self, *, asset_type: str) -> list:
        return await self._h.get("/api/v1/discovery/assets", params={"asset_type": asset_type})  # type: ignore[return-value]

    async def get_asset(self, asset_id: str) -> dict:
        return await self._h.get(f"/api/v1/discovery/assets/{asset_id}")  # type: ignore[return-value]
