"""Reporting Engine client — /reports/*"""
from __future__ import annotations

from cves_cli.client.base import CVEsHTTPClient


class ReportingClient:
    def __init__(self, http: CVEsHTTPClient) -> None:
        self._h = http

    async def generate(
        self,
        *,
        tenant_id: str,
        report_type: str,
        report_format: str,
        requested_by: str = "cves-cli",
    ) -> dict:
        return await self._h.post(  # type: ignore[return-value]
            "/reports/generate",
            json={
                "tenant_id": tenant_id,
                "report_type": report_type,
                "report_format": report_format,
                "requested_by": requested_by,
            },
        )

    async def list(self, *, tenant_id: str, limit: int = 50, offset: int = 0) -> list:
        return await self._h.get(  # type: ignore[return-value]
            "/reports/", params={"tenant_id": tenant_id, "limit": limit, "offset": offset}
        )

    async def get(self, *, tenant_id: str, report_id: str) -> dict:
        return await self._h.get(f"/reports/{report_id}", params={"tenant_id": tenant_id})  # type: ignore[return-value]

    async def download(self, *, tenant_id: str, report_id: str) -> bytes:
        return await self._h.get_stream(f"/reports/{report_id}/download", params={"tenant_id": tenant_id})

    async def executive_summary(self, *, tenant_id: str) -> dict:
        return await self._h.get("/reports/executive/summary", params={"tenant_id": tenant_id})  # type: ignore[return-value]

    async def compliance_mapping(self, *, tenant_id: str) -> list:
        return await self._h.get("/reports/compliance/mapping", params={"tenant_id": tenant_id})  # type: ignore[return-value]

    async def evidence_export(self, *, tenant_id: str) -> bytes:
        return await self._h.get_stream("/reports/evidence/export", params={"tenant_id": tenant_id})

    async def remediation_guidance(self, *, tenant_id: str) -> list:
        return await self._h.get("/reports/remediation/guidance", params={"tenant_id": tenant_id})  # type: ignore[return-value]
