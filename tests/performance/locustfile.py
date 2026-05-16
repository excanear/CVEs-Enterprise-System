"""Performance tests — Locust load-test scenarios for CVEs Enterprise System APIs.

Usage:
  # Run headless (1 minute, 50 users, ramp 10/s):
  locust -f tests/performance/locustfile.py \
    --host http://localhost:8000 \
    --headless -u 50 -r 10 --run-time 60s

Environment variables:
  SCAN_ORCHESTRATOR_URL     (default: http://localhost:8000)
  AI_CORRELATION_URL        (default: http://localhost:8003)
  REPORTING_ENGINE_URL      (default: http://localhost:8004)
  ASSET_GRAPH_URL           (default: http://localhost:8001)
  TENANT_ID                 UUID for tenant header (default: random UUID)
"""
from __future__ import annotations

import json
import os
import uuid
from typing import Any

from locust import HttpUser, between, events, task

# ── Configuration ─────────────────────────────────────────────────────────────

_TENANT_ID = os.getenv("TENANT_ID", str(uuid.UUID("11111111-1111-1111-1111-111111111111")))
_CORRELATION_ID = str(uuid.uuid4())

_COMMON_HEADERS = {
    "Content-Type": "application/json",
    "X-Tenant-ID": _TENANT_ID,
    "X-Correlation-ID": _CORRELATION_ID,
}


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _scan_payload(scan_type: str = "PORT_SCAN") -> dict[str, Any]:
    return {
        "tenant_id": _TENANT_ID,
        "scan_type": scan_type,
        "targets": [f"10.0.0.{i}" for i in range(1, 6)],
        "priority": "NORMAL",
        "correlation_id": str(uuid.uuid4()),
    }


# ── Scan Orchestrator Load User ────────────────────────────────────────────────

class ScanSubmissionUser(HttpUser):
    """Simulates the most common API pattern: submit scan → poll status."""

    host = os.getenv("SCAN_ORCHESTRATOR_URL", "http://localhost:8000")
    wait_time = between(1, 3)

    @task(3)
    def submit_scan(self):
        with self.client.post(
            "/api/v1/scans",
            json=_scan_payload(),
            headers=_COMMON_HEADERS,
            catch_response=True,
        ) as response:
            if response.status_code in (200, 201, 202):
                response.success()
                body = response.json()
                scan_id = body.get("scan_id") or body.get("id")
                if scan_id:
                    self._check_scan_status(scan_id)
            elif response.status_code == 422:
                response.failure(f"Validation error: {response.text[:200]}")
            else:
                response.failure(f"Unexpected status {response.status_code}")

    @task(5)
    def list_scans(self):
        self.client.get(
            "/api/v1/scans",
            headers=_COMMON_HEADERS,
            name="/api/v1/scans [list]",
        )

    @task(2)
    def get_queue_depth(self):
        self.client.get("/api/v1/queue/depth", headers=_COMMON_HEADERS)

    @task(1)
    def get_worker_pools(self):
        self.client.get("/api/v1/workers/pools", headers=_COMMON_HEADERS)

    def _check_scan_status(self, scan_id: str) -> None:
        self.client.get(
            f"/api/v1/scans/{scan_id}",
            headers=_COMMON_HEADERS,
            name="/api/v1/scans/{id} [status]",
        )


# ── AI Correlation API Load User ───────────────────────────────────────────────

class CorrelationAPIUser(HttpUser):
    """Simulates correlation session creation + cluster reads."""

    host = os.getenv("AI_CORRELATION_URL", "http://localhost:8003")
    wait_time = between(2, 5)

    @task(2)
    def start_correlation_session(self):
        payload = {
            "tenant_id": _TENANT_ID,
            "scan_ids": [str(uuid.uuid4())],
            "correlation_id": str(uuid.uuid4()),
        }
        self.client.post(
            "/api/v1/sessions",
            json=payload,
            headers=_COMMON_HEADERS,
            name="/api/v1/sessions [correlation]",
        )

    @task(5)
    def get_clusters(self):
        self.client.get(
            "/api/v1/clusters",
            params={"tenant_id": _TENANT_ID},
            headers=_COMMON_HEADERS,
        )

    @task(3)
    def get_ranked_attack_paths(self):
        self.client.get(
            "/api/v1/attack-paths/ranked",
            params={"tenant_id": _TENANT_ID, "limit": "10"},
            headers=_COMMON_HEADERS,
        )


# ── Reporting Engine Load User ─────────────────────────────────────────────────

class ReportAPIUser(HttpUser):
    """Simulates report generation and executive summary reads."""

    host = os.getenv("REPORTING_ENGINE_URL", "http://localhost:8004")
    wait_time = between(3, 8)

    @task(5)
    def get_executive_summary(self):
        self.client.get(
            "/api/v1/executive/summary",
            params={"tenant_id": _TENANT_ID},
            headers=_COMMON_HEADERS,
        )

    @task(3)
    def get_compliance_mapping(self):
        self.client.get(
            "/api/v1/compliance/mapping",
            params={"tenant_id": _TENANT_ID, "framework": "SOC2"},
            headers=_COMMON_HEADERS,
        )

    @task(2)
    def generate_report(self):
        payload = {
            "tenant_id": _TENANT_ID,
            "report_type": "EXECUTIVE",
            "format": "PDF",
            "correlation_id": str(uuid.uuid4()),
        }
        self.client.post(
            "/api/v1/generate",
            json=payload,
            headers=_COMMON_HEADERS,
        )

    @task(1)
    def export_evidence_csv(self):
        self.client.get(
            "/api/v1/evidence/export",
            params={"tenant_id": _TENANT_ID},
            headers={**_COMMON_HEADERS, "Accept": "text/csv"},
            name="/api/v1/evidence/export [csv]",
        )


# ── Asset Graph Engine Load User ───────────────────────────────────────────────

class GraphAPIUser(HttpUser):
    """Simulates asset listing and graph stats reads."""

    host = os.getenv("ASSET_GRAPH_URL", "http://localhost:8001")
    wait_time = between(1, 4)

    @task(5)
    def list_assets(self):
        self.client.get(
            "/api/v1/assets",
            params={"tenant_id": _TENANT_ID, "page": "1", "size": "20"},
            headers=_COMMON_HEADERS,
        )

    @task(3)
    def get_graph_stats(self):
        self.client.get(
            "/api/v1/stats",
            params={"tenant_id": _TENANT_ID},
            headers=_COMMON_HEADERS,
        )

    @task(2)
    def get_attack_paths(self):
        self.client.get(
            "/api/v1/attack-paths",
            params={"tenant_id": _TENANT_ID},
            headers=_COMMON_HEADERS,
        )

    @task(1)
    def ingest_asset(self):
        payload = {
            "tenant_id": _TENANT_ID,
            "asset_type": "HOST",
            "identifier": f"10.0.0.{uuid.uuid4().int % 255}",
            "correlation_id": str(uuid.uuid4()),
        }
        self.client.post(
            "/api/v1/ingest",
            json=payload,
            headers=_COMMON_HEADERS,
            name="/api/v1/ingest [asset]",
        )


# ── Event hooks for reporting ──────────────────────────────────────────────────

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    print(f"\n[CVEs Performance Test] Tenant: {_TENANT_ID}")
    print(f"[CVEs Performance Test] Targets: {environment.host}")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    stats = environment.stats.total
    print(f"\n[CVEs Performance Test] Finished")
    print(f"  Requests:      {stats.num_requests}")
    print(f"  Failures:      {stats.num_failures}")
    print(f"  Median RT:     {stats.median_response_time:.0f}ms")
    print(f"  p95 RT:        {stats.get_response_time_percentile(0.95):.0f}ms")
    print(f"  p99 RT:        {stats.get_response_time_percentile(0.99):.0f}ms")
    print(f"  RPS:           {stats.current_rps:.1f}")
