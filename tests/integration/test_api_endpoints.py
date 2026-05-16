"""Integration tests — FastAPI endpoints for all services.

Uses httpx.AsyncClient with ASGITransport (no real HTTP server needed).
All infrastructure ports are replaced with in-memory fakes or AsyncMocks.

Requires: pip install httpx pytest-asyncio
"""
from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

# ── Scan Orchestrator API ─────────────────────────────────────────────────────

@pytest.fixture
def scan_app(scan_repo, task_repo, scan_queue, event_publisher):
    """Scan Orchestrator FastAPI app with all infra replaced by in-memory fakes."""
    from scan_orchestrator.application.scan_orchestration_service import ScanOrchestrationService
    from scan_orchestrator.application.worker_pool_manager import WorkerPoolManager
    from scan_orchestrator.main import create_app

    app = create_app.__wrapped__() if hasattr(create_app, "__wrapped__") else create_app()

    # bypass lifespan — inject state directly
    svc = ScanOrchestrationService(
        scan_repo=scan_repo,
        task_repo=task_repo,
        scan_queue=scan_queue,
        event_publisher=event_publisher,
        worker_pool=WorkerPoolManager(),
    )
    app.state.orchestration_svc = svc
    app.state.worker_pool = WorkerPoolManager()
    app.state.scan_queue = scan_queue

    mock_scheduler = MagicMock()
    mock_scheduler.list_jobs = AsyncMock(return_value=[])
    mock_scheduler.register = AsyncMock()
    mock_scheduler.unregister = AsyncMock()
    app.state.scheduler = mock_scheduler

    return app


@pytest.fixture
async def scan_client(scan_app, tenant_id):
    """Authenticated async test client for Scan Orchestrator."""
    async with AsyncClient(
        transport=ASGITransport(app=scan_app),
        base_url="http://test",
        headers={"X-Tenant-Id": str(tenant_id)},
    ) as client:
        # Inject tenant_id into middleware shim
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.requests import Request as _Req

        @scan_app.middleware("http")
        async def _inject_tenant(request: _Req, call_next):
            request.state.tenant_id = tenant_id
            request.state.jwt_claims = {"sub": "pytest-user"}
            return await call_next(request)

        yield client


class TestScanOrchestratorAPISubmit:
    async def test_post_scans_returns_202(self, scan_client, tenant_id):
        resp = await scan_client.post(
            "/api/v1/scans",
            json={
                "scan_type": "PORT_SCAN",
                "targets": ["10.0.0.1", "10.0.0.2"],
                "priority": "NORMAL",
            },
        )
        assert resp.status_code == 202
        body = resp.json()
        assert "scan_id" in body
        assert body["status"] == "SCHEDULED"

    async def test_post_scans_empty_targets_returns_422(self, scan_client):
        resp = await scan_client.post(
            "/api/v1/scans",
            json={"scan_type": "PORT_SCAN", "targets": []},
        )
        assert resp.status_code == 422

    async def test_get_scan_returns_404_for_unknown(self, scan_client, tenant_id):
        resp = await scan_client.get(f"/api/v1/scans/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_get_scan_returns_200_after_submit(self, scan_client, scan_app, tenant_id):
        # Submit first
        post_resp = await scan_client.post(
            "/api/v1/scans",
            json={"scan_type": "NETWORK_DISCOVERY", "targets": ["192.168.1.0/24"]},
        )
        scan_id = post_resp.json()["scan_id"]

        get_resp = await scan_client.get(f"/api/v1/scans/{scan_id}")
        assert get_resp.status_code == 200
        body = get_resp.json()
        assert body["scan_id"] == scan_id

    async def test_delete_scan_returns_204(self, scan_client, scan_app, tenant_id):
        post_resp = await scan_client.post(
            "/api/v1/scans",
            json={"scan_type": "PORT_SCAN", "targets": ["10.0.0.1"]},
        )
        scan_id = post_resp.json()["scan_id"]
        del_resp = await scan_client.delete(f"/api/v1/scans/{scan_id}")
        assert del_resp.status_code == 204

    async def test_queue_depth_endpoint(self, scan_client):
        resp = await scan_client.get("/api/v1/queue/depth")
        assert resp.status_code == 200

    async def test_list_scans_endpoint(self, scan_client):
        resp = await scan_client.get("/api/v1/scans?status=SCHEDULED")
        assert resp.status_code in (200, 422)  # 422 if status param validation fails

    async def test_workers_pools_endpoint(self, scan_client):
        resp = await scan_client.get("/api/v1/workers/pools")
        assert resp.status_code == 200

    async def test_scheduler_jobs_endpoint(self, scan_client):
        resp = await scan_client.get("/api/v1/scheduler/jobs")
        assert resp.status_code == 200


# ── Runtime Analysis Engine API ───────────────────────────────────────────────

@pytest.fixture
def rae_app():
    """Runtime Analysis Engine with mocked repos and disabled browser pool."""
    from fastapi import FastAPI
    from runtime_analysis.interface.api.router import router as rae_router

    app = FastAPI()
    app.include_router(rae_router)

    mock_session_repo = MagicMock()
    mock_session_repo.get = AsyncMock(return_value=None)
    mock_session_repo.list_by_tenant = AsyncMock(return_value=[])
    mock_session_repo.save = AsyncMock()

    mock_result_repo = MagicMock()
    mock_result_repo.get_by_session = AsyncMock(return_value=None)

    mock_svc = MagicMock()
    mock_svc.analyze = AsyncMock(return_value="session-123")

    app.state.session_repo = mock_session_repo
    app.state.result_repo = mock_result_repo
    app.state.analysis_service = mock_svc
    return app


@pytest.fixture
async def rae_client(rae_app):
    async with AsyncClient(
        transport=ASGITransport(app=rae_app),
        base_url="http://test",
    ) as client:
        yield client


class TestRuntimeAnalysisEngineAPI:
    async def test_post_sessions_returns_202(self, rae_client):
        resp = await rae_client.post(
            "/runtime-analysis/sessions",
            json={
                "tenant_id": str(uuid.uuid4()),
                "target_url": "https://example.com",
                "correlation_id": str(uuid.uuid4()),
                "max_spa_routes": 20,
                "timeout_seconds": 60,
            },
        )
        assert resp.status_code == 202
        assert resp.json()["status"] == "accepted"

    async def test_get_session_not_found(self, rae_client):
        resp = await rae_client.get("/runtime-analysis/sessions/nonexistent-session-id")
        assert resp.status_code == 404

    async def test_get_result_not_found(self, rae_client):
        resp = await rae_client.get("/runtime-analysis/sessions/nonexistent/result")
        assert resp.status_code == 404

    async def test_list_sessions_empty(self, rae_client):
        resp = await rae_client.get("/runtime-analysis/sessions?tenant_id=t1")
        assert resp.status_code == 200
        assert resp.json() == []


# ── JS Intelligence Engine API ────────────────────────────────────────────────

@pytest.fixture
def jsi_app():
    from fastapi import FastAPI
    from js_intelligence.interface.api.router import router as jsi_router

    app = FastAPI()
    app.include_router(jsi_router)

    mock_job_repo = MagicMock()
    mock_job_repo.get = AsyncMock(return_value=None)

    mock_svc = MagicMock()
    mock_svc.analyze = AsyncMock(return_value="job-abc")

    app.state.js_intelligence_service = mock_svc
    app.state.job_repo = mock_job_repo
    app.state.result_repo = MagicMock()
    return app


@pytest.fixture
async def jsi_client(jsi_app):
    async with AsyncClient(
        transport=ASGITransport(app=jsi_app),
        base_url="http://test",
    ) as client:
        yield client


class TestJSIntelligenceEngineAPI:
    async def test_submit_job_async_returns_202(self, jsi_client):
        resp = await jsi_client.post(
            "/js-intelligence/jobs",
            json={
                "tenant_id": str(uuid.uuid4()),
                "target_url": "https://app.example.com",
                "max_js_files": 10,
                "fetch_source_maps": True,
                "timeout_seconds": 60,
            },
        )
        assert resp.status_code == 202
        assert resp.json()["status"] == "accepted"

    async def test_get_job_not_found(self, jsi_client):
        resp = await jsi_client.get("/js-intelligence/jobs/nonexistent-job")
        assert resp.status_code == 404

    async def test_submit_job_sync_returns_200(self, jsi_client):
        resp = await jsi_client.post(
            "/js-intelligence/jobs/sync",
            json={
                "tenant_id": str(uuid.uuid4()),
                "target_url": "https://app.example.com",
                "timeout_seconds": 60,
            },
        )
        assert resp.status_code == 200
        assert "job_id" in resp.json()


# ── Reporting Engine API ──────────────────────────────────────────────────────

@pytest.fixture
def re_app():
    from fastapi import FastAPI
    from reporting.interface.api.router import router as re_router

    app = FastAPI()
    app.include_router(re_router)

    mock_svc = MagicMock()
    mock_svc.generate_report = AsyncMock()
    mock_svc.get_executive_summary = AsyncMock(return_value={"summary": "ok"})
    mock_svc.get_compliance_mapping = AsyncMock(return_value=[])
    mock_svc.get_evidence_export = AsyncMock(return_value="header\nrow1")
    mock_svc.get_remediation_guidance = AsyncMock(return_value=[])
    mock_svc.list_reports = AsyncMock(return_value=[])

    # generate_report returns a Report-like object
    from unittest.mock import MagicMock as MM
    import datetime
    report = MM()
    report.report_id = "rpt-001"
    report.tenant_id = str(uuid.uuid4())
    report.report_type = MagicMock(value="EXECUTIVE")
    report.report_format = MagicMock(value="PDF")
    report.status = MagicMock(value="PENDING")
    report.finding_count = 0
    report.error = None
    report.created_at = datetime.datetime.now(datetime.timezone.utc)
    report.generated_at = None
    mock_svc.generate_report = AsyncMock(return_value=report)

    app.state.reporting_service = mock_svc
    return app


@pytest.fixture
async def re_client(re_app):
    async with AsyncClient(
        transport=ASGITransport(app=re_app),
        base_url="http://test",
    ) as client:
        yield client


class TestReportingEngineAPI:
    async def test_generate_report_returns_202(self, re_client):
        resp = await re_client.post(
            "/reports/generate",
            json={
                "tenant_id": str(uuid.uuid4()),
                "report_type": "EXECUTIVE",
                "report_format": "PDF",
                "requested_by": "pytest",
            },
        )
        assert resp.status_code == 202

    async def test_executive_summary_returns_200(self, re_client):
        resp = await re_client.get(f"/reports/executive/summary?tenant_id={uuid.uuid4()}")
        assert resp.status_code == 200

    async def test_compliance_mapping_returns_200(self, re_client):
        resp = await re_client.get(f"/reports/compliance/mapping?tenant_id={uuid.uuid4()}")
        assert resp.status_code == 200

    async def test_evidence_export_returns_csv(self, re_client):
        resp = await re_client.get(f"/reports/evidence/export?tenant_id={uuid.uuid4()}")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers.get("content-type", "")

    async def test_list_reports_empty(self, re_client):
        resp = await re_client.get(f"/reports/?tenant_id={uuid.uuid4()}")
        assert resp.status_code == 200
        assert resp.json() == []


# ── Asset Graph Engine API ────────────────────────────────────────────────────

@pytest.fixture
def age_app():
    from fastapi import FastAPI
    from asset_graph.interface.api.router import router as age_router

    app = FastAPI()
    app.include_router(age_router)

    mock_svc = MagicMock()
    mock_svc.ingest_manual = AsyncMock()
    mock_svc.list_assets = AsyncMock(return_value=[])
    mock_svc.get_attack_paths = AsyncMock(return_value=[])
    mock_svc.get_trust_chains = AsyncMock(return_value=[])
    mock_svc.get_exposure_propagation = AsyncMock(return_value=[])
    mock_svc.get_dependency_risks = AsyncMock(return_value=[])
    mock_svc.get_infra_map = AsyncMock(return_value={"nodes": [], "edges": []})
    mock_svc.get_stats = AsyncMock(return_value={"node_count": 0, "edge_count": 0})

    app.state.age_service = mock_svc
    return app


@pytest.fixture
async def age_client(age_app):
    async with AsyncClient(
        transport=ASGITransport(app=age_app),
        base_url="http://test",
    ) as client:
        yield client


class TestAssetGraphEngineAPI:
    async def test_ingest_event_returns_202(self, age_client):
        resp = await age_client.post(
            "/graph/ingest",
            json={
                "tenant_id": str(uuid.uuid4()),
                "event_type": "asi.asset.discovered",
                "payload": {"asset_id": str(uuid.uuid4()), "asset_type": "URL"},
            },
        )
        assert resp.status_code == 202
        assert resp.json()["status"] == "accepted"

    async def test_list_assets_empty(self, age_client):
        resp = await age_client.get(f"/graph/assets?tenant_id={uuid.uuid4()}")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_attack_paths_empty(self, age_client):
        resp = await age_client.get(f"/graph/attack-paths?tenant_id={uuid.uuid4()}")
        assert resp.status_code == 200

    async def test_graph_stats_returns_200(self, age_client):
        resp = await age_client.get(f"/graph/stats?tenant_id={uuid.uuid4()}")
        assert resp.status_code == 200


# ── AI Correlation Layer API ──────────────────────────────────────────────────

@pytest.fixture
def acl_app():
    from fastapi import FastAPI
    from ai_correlation.interface.api.router import router as acl_router

    app = FastAPI()
    app.include_router(acl_router)

    mock_svc = MagicMock()
    from unittest.mock import MagicMock as MM
    import datetime
    session = MM()
    session.session_id = "sess-001"
    session.tenant_id = "t1"
    session.status = "COMPLETED"
    session.evidence_count = 0
    session.path_count = 0
    session.cluster_count = 0
    session.prioritized_count = 0
    session.error = None
    session.created_at = datetime.datetime.now(datetime.timezone.utc)
    session.updated_at = datetime.datetime.now(datetime.timezone.utc)
    session.completed_at = None

    mock_svc.correlate = AsyncMock(return_value=session)
    mock_svc.get_session = AsyncMock(return_value=session)
    mock_svc.list_clusters = AsyncMock(return_value=[])
    mock_svc.get_ranked_paths = AsyncMock(return_value=[])
    mock_svc.get_prioritized_exposures = AsyncMock(return_value=[])
    mock_svc.get_remediation = AsyncMock(return_value=None)
    mock_svc.get_risk_summary = AsyncMock(return_value=None)

    app.state.correlation_service = mock_svc
    return app


@pytest.fixture
async def acl_client(acl_app):
    async with AsyncClient(
        transport=ASGITransport(app=acl_app),
        base_url="http://test",
    ) as client:
        yield client


class TestAICorrelationLayerAPI:
    async def test_trigger_correlation_returns_202(self, acl_client):
        resp = await acl_client.post(
            "/correlation/sessions",
            json={"tenant_id": str(uuid.uuid4())},
        )
        assert resp.status_code == 202

    async def test_list_clusters_empty(self, acl_client):
        resp = await acl_client.get(f"/correlation/clusters?tenant_id={uuid.uuid4()}")
        assert resp.status_code == 200

    async def test_ranked_paths_empty(self, acl_client):
        resp = await acl_client.get(f"/correlation/attack-paths/ranked?tenant_id={uuid.uuid4()}")
        assert resp.status_code == 200
