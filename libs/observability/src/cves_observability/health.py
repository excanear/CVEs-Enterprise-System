"""Health check FastAPI router.

Endpoints:
  GET /health/live   — Always 200 (pod is alive, liveness probe).
  GET /health/ready  — 200 if all dependency checks pass (readiness probe).
  GET /health/deps   — 200 with per-dependency status detail.
  GET /metrics       — Prometheus text exposition.

Usage::

    from cves_observability.health import HealthRouter

    health = HealthRouter(
        service_name="asi-service",
        version="1.0.0",
        checks={"postgres": check_postgres, "kafka": check_kafka},
    )
    app.include_router(health.router)
"""
from __future__ import annotations

import time
from typing import Awaitable, Callable

from fastapi import APIRouter
from fastapi.responses import JSONResponse, PlainTextResponse

HealthCheck = Callable[[], Awaitable[bool]]


class HealthRouter:
    """Pluggable health router for FastAPI applications."""

    def __init__(
        self,
        *,
        service_name: str,
        version: str = "0.0.0",
        checks: dict[str, HealthCheck] | None = None,
    ) -> None:
        self._service_name = service_name
        self._version = version
        self._checks: dict[str, HealthCheck] = checks or {}
        self.router = APIRouter(tags=["health"])
        self._register_routes()

    def _register_routes(self) -> None:
        router = self.router

        @router.get("/health/live", include_in_schema=False)
        async def liveness() -> JSONResponse:
            return JSONResponse({"status": "alive", "service": self._service_name})

        @router.get("/health/ready", include_in_schema=False)
        async def readiness() -> JSONResponse:
            results = await self._run_checks()
            all_ok = all(v["ok"] for v in results.values())
            status_code = 200 if all_ok else 503
            return JSONResponse(
                {
                    "status": "ready" if all_ok else "degraded",
                    "service": self._service_name,
                    "version": self._version,
                    "checks": results,
                },
                status_code=status_code,
            )

        @router.get("/health/deps", include_in_schema=False)
        async def deps() -> JSONResponse:
            results = await self._run_checks()
            return JSONResponse(
                {
                    "service": self._service_name,
                    "version": self._version,
                    "checks": results,
                }
            )

        @router.get("/metrics", include_in_schema=False)
        async def metrics() -> PlainTextResponse:
            try:
                from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

                return PlainTextResponse(
                    generate_latest().decode(),
                    media_type=CONTENT_TYPE_LATEST,
                )
            except ImportError:
                return PlainTextResponse("# prometheus-client not installed\n")

    async def _run_checks(self) -> dict[str, dict]:
        import asyncio

        results: dict[str, dict] = {}
        for name, fn in self._checks.items():
            start = time.perf_counter()
            try:
                ok = await asyncio.wait_for(fn(), timeout=5.0)
                results[name] = {"ok": ok, "latency_ms": round((time.perf_counter() - start) * 1000, 2)}
            except asyncio.TimeoutError:
                results[name] = {"ok": False, "error": "timeout", "latency_ms": 5000}
            except Exception as exc:  # noqa: BLE001
                results[name] = {"ok": False, "error": str(exc), "latency_ms": round((time.perf_counter() - start) * 1000, 2)}
        return results
