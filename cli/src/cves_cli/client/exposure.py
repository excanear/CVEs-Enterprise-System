"""Exposure Validation Engine client — /exposure-validation/*"""
from __future__ import annotations

from cves_cli.client.base import CVEsHTTPClient


class ExposureClient:
    def __init__(self, http: CVEsHTTPClient) -> None:
        self._h = http

    async def validate(
        self,
        *,
        tenant_id: str,
        target_url: str,
        exposure_type: str,
        correlation_id: str | None = None,
    ) -> dict:
        payload: dict = {
            "tenant_id": tenant_id,
            "target_url": target_url,
            "exposure_type": exposure_type,
        }
        if correlation_id:
            payload["correlation_id"] = correlation_id
        return await self._h.post("/exposure-validation/jobs", json=payload)  # type: ignore[return-value]

    async def get_job(self, job_id: str) -> dict:
        return await self._h.get(f"/exposure-validation/jobs/{job_id}")  # type: ignore[return-value]

    async def list_jobs(self, *, tenant_id: str, limit: int = 20) -> list:
        return await self._h.get(  # type: ignore[return-value]
            "/exposure-validation/jobs", params={"tenant_id": tenant_id, "limit": limit}
        )

    async def get_result(self, job_id: str) -> dict:
        return await self._h.get(f"/exposure-validation/jobs/{job_id}/result")  # type: ignore[return-value]
