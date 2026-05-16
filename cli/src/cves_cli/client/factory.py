"""Client factory — builds service clients from current app state."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from cves_cli.client.base import CVEsHTTPClient, build_client
from cves_cli.client.correlation import CorrelationClient
from cves_cli.client.discovery import DiscoveryClient
from cves_cli.client.exposure import ExposureClient
from cves_cli.client.graph import GraphClient
from cves_cli.client.js import JSClient
from cves_cli.client.reporting import ReportingClient
from cves_cli.client.runtime import RuntimeClient
from cves_cli.client.scan import ScanClient


def _make_http(base_url: str) -> CVEsHTTPClient:
    from cves_cli.state import app_state

    cfg = app_state.get_config()
    ae = cfg.get_active_auth_entry()
    auth_name = ae.name if ae else "default"
    auth_type = ae.type if ae else "api_key"
    tenant_id = app_state.effective_tenant_id()

    return build_client(base_url, auth_name=auth_name, auth_type=auth_type, tenant_id=tenant_id)


@asynccontextmanager
async def scan_client() -> AsyncIterator[ScanClient]:
    from cves_cli.state import app_state

    ep = app_state.get_config().get_active_endpoints()
    async with _make_http(ep.scan_orchestrator) as http:
        yield ScanClient(http)


@asynccontextmanager
async def discovery_client() -> AsyncIterator[DiscoveryClient]:
    from cves_cli.state import app_state

    ep = app_state.get_config().get_active_endpoints()
    async with _make_http(ep.discovery_engine) as http:
        yield DiscoveryClient(http)


@asynccontextmanager
async def graph_client() -> AsyncIterator[GraphClient]:
    from cves_cli.state import app_state

    ep = app_state.get_config().get_active_endpoints()
    async with _make_http(ep.asset_graph_engine) as http:
        yield GraphClient(http)


@asynccontextmanager
async def correlation_client() -> AsyncIterator[CorrelationClient]:
    from cves_cli.state import app_state

    ep = app_state.get_config().get_active_endpoints()
    async with _make_http(ep.ai_correlation_layer) as http:
        yield CorrelationClient(http)


@asynccontextmanager
async def reporting_client() -> AsyncIterator[ReportingClient]:
    from cves_cli.state import app_state

    ep = app_state.get_config().get_active_endpoints()
    async with _make_http(ep.reporting_engine) as http:
        yield ReportingClient(http)


@asynccontextmanager
async def runtime_client() -> AsyncIterator[RuntimeClient]:
    from cves_cli.state import app_state

    ep = app_state.get_config().get_active_endpoints()
    async with _make_http(ep.runtime_analysis_engine) as http:
        yield RuntimeClient(http)


@asynccontextmanager
async def js_client() -> AsyncIterator[JSClient]:
    from cves_cli.state import app_state

    ep = app_state.get_config().get_active_endpoints()
    async with _make_http(ep.js_intelligence_engine) as http:
        yield JSClient(http)


@asynccontextmanager
async def exposure_client() -> AsyncIterator[ExposureClient]:
    from cves_cli.state import app_state

    ep = app_state.get_config().get_active_endpoints()
    async with _make_http(ep.exposure_validation_engine) as http:
        yield ExposureClient(http)
