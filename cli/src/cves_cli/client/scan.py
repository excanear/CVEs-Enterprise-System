"""Scan Orchestrator API client.

Endpoints (prefix /api/v1):
  POST   /scans                      — submit scan
  GET    /scans/{id}                 — scan status
  DELETE /scans/{id}                 — cancel scan
  POST   /scans/{id}/retry           — retry failed tasks
  GET    /scans                      — list scans
  GET    /workers/pools              — worker pool stats
  GET    /queue/depth                — queue depth
  GET    /scheduler/jobs             — list scheduled jobs
  POST   /scheduler/jobs             — create scheduled job
  DELETE /scheduler/jobs/{job_id}    — delete scheduled job
"""
from __future__ import annotations

from typing import Any

from cves_cli.client.base import CVEsHTTPClient


class ScanClient:
    def __init__(self, http: CVEsHTTPClient) -> None:
        self._h = http

    async def submit(
        self,
        *,
        scan_type: str,
        targets: list[str],
        priority: str = "NORMAL",
        config: dict | None = None,
        schedule_cron: str | None = None,
    ) -> dict:
        payload: dict[str, Any] = {
            "scan_type": scan_type,
            "targets": targets,
            "priority": priority,
            "config": config or {},
        }
        if schedule_cron:
            payload["schedule_cron"] = schedule_cron
        return await self._h.post("/api/v1/scans", json=payload)  # type: ignore[return-value]

    async def get(self, scan_id: str) -> dict:
        return await self._h.get(f"/api/v1/scans/{scan_id}")  # type: ignore[return-value]

    async def list(self, *, status: str = "RUNNING", limit: int = 50) -> list:
        return await self._h.get("/api/v1/scans", params={"scan_status": status, "limit": limit})  # type: ignore[return-value]

    async def cancel(self, scan_id: str) -> None:
        await self._h.delete(f"/api/v1/scans/{scan_id}")

    async def retry(self, scan_id: str) -> dict:
        return await self._h.post(f"/api/v1/scans/{scan_id}/retry")  # type: ignore[return-value]

    async def worker_pools(self) -> dict:
        return await self._h.get("/api/v1/workers/pools")  # type: ignore[return-value]

    async def worker_heartbeats(self) -> dict:
        return await self._h.get("/api/v1/workers/heartbeats")  # type: ignore[return-value]

    async def queue_depth(self) -> dict:
        return await self._h.get("/api/v1/queue/depth")  # type: ignore[return-value]

    async def list_jobs(self) -> list:
        return await self._h.get("/api/v1/scheduler/jobs")  # type: ignore[return-value]

    async def create_job(
        self,
        *,
        name: str,
        cron_expression: str,
        scan_type: str,
        targets: list[str],
        priority: str = "NORMAL",
        config: dict | None = None,
    ) -> dict:
        return await self._h.post(  # type: ignore[return-value]
            "/api/v1/scheduler/jobs",
            json={
                "name": name,
                "cron_expression": cron_expression,
                "scan_type": scan_type,
                "targets": targets,
                "priority": priority,
                "config": config or {},
            },
        )

    async def delete_job(self, job_id: str) -> None:
        await self._h.delete(f"/api/v1/scheduler/jobs/{job_id}")
