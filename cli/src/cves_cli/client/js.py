"""JS Intelligence Engine client — /js-intelligence/*"""
from __future__ import annotations

from cves_cli.client.base import CVEsHTTPClient


class JSClient:
    def __init__(self, http: CVEsHTTPClient) -> None:
        self._h = http

    async def analyze(
        self,
        *,
        tenant_id: str,
        target_url: str,
        max_js_files: int = 50,
        fetch_source_maps: bool = True,
        timeout_seconds: int = 120,
    ) -> dict:
        return await self._h.post(  # type: ignore[return-value]
            "/js-intelligence/jobs",
            json={
                "tenant_id": tenant_id,
                "target_url": target_url,
                "max_js_files": max_js_files,
                "fetch_source_maps": fetch_source_maps,
                "timeout_seconds": timeout_seconds,
            },
        )

    async def analyze_sync(
        self,
        *,
        tenant_id: str,
        target_url: str,
        timeout_seconds: int = 120,
    ) -> dict:
        return await self._h.post(  # type: ignore[return-value]
            "/js-intelligence/jobs/sync",
            json={"tenant_id": tenant_id, "target_url": target_url, "timeout_seconds": timeout_seconds},
        )

    async def get_job(self, job_id: str) -> dict:
        return await self._h.get(f"/js-intelligence/jobs/{job_id}")  # type: ignore[return-value]

    async def list_jobs(self, *, tenant_id: str, limit: int = 20) -> list:
        return await self._h.get("/js-intelligence/jobs", params={"tenant_id": tenant_id, "limit": limit})  # type: ignore[return-value]
