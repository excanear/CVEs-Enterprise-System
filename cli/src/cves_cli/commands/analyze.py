"""Analyze commands — runtime SPA, JS intelligence, exposure validation."""
from __future__ import annotations

import anyio
import typer

from cves_cli.output.formatter import fmt

analyze_app = typer.Typer(name="analyze", help="Dynamic runtime and JS analysis.", no_args_is_help=True)


@analyze_app.command("runtime")
def analyze_runtime(
    url: str = typer.Argument(..., help="Target URL to analyze."),
    max_routes: int = typer.Option(20, "--max-routes"),
    timeout: int = typer.Option(120, "--timeout"),
    wait: bool = typer.Option(False, "--wait", "-w"),
) -> None:
    """Analyze a SPA/web app at runtime."""
    from cves_cli.client.factory import runtime_client
    from cves_cli.output.streaming import poll_until_terminal, RichLivePoller
    from cves_cli.state import app_state

    async def _start() -> dict:
        async with runtime_client() as c:
            return await c.analyze(
                tenant_id=app_state.effective_tenant_id() or "",
                target_url=url,
                max_spa_routes=max_routes,
                timeout_seconds=timeout,
            )

    result = anyio.run(_start)
    session_id = str(result.get("session_id", result.get("id", "")))
    fmt.success(f"Runtime session: {session_id}")
    fmt.print(result)

    if not wait:
        return

    async def _poll() -> dict:
        with RichLivePoller(f"Analyzing {url[:40]}…") as poller:
            async def fetch() -> dict:
                async with runtime_client() as c:
                    return await c.get_session(session_id)

            return await poll_until_terminal(fetch, interval=3, timeout=300)

    final = anyio.run(_poll)
    fmt.print(final, title="Runtime Analysis Complete")


@analyze_app.command("js")
def analyze_js(
    url: str = typer.Argument(..., help="Target URL."),
    max_files: int = typer.Option(50, "--max-files"),
    source_maps: bool = typer.Option(True, "--source-maps/--no-source-maps"),
    sync: bool = typer.Option(False, "--sync", help="Synchronous analysis (blocks until done)."),
    timeout: int = typer.Option(120, "--timeout"),
) -> None:
    """Analyze JavaScript bundles for secrets and API endpoints."""
    from cves_cli.client.factory import js_client
    from cves_cli.state import app_state

    async def _start() -> dict:
        async with js_client() as c:
            if sync:
                return await c.analyze_sync(
                    tenant_id=app_state.effective_tenant_id() or "",
                    target_url=url,
                    timeout_seconds=timeout,
                )
            return await c.analyze(
                tenant_id=app_state.effective_tenant_id() or "",
                target_url=url,
                max_js_files=max_files,
                fetch_source_maps=source_maps,
                timeout_seconds=timeout,
            )

    result = anyio.run(_start)
    fmt.print(result, title="JS Intelligence Job")


@analyze_app.command("exposure")
def analyze_exposure(
    url: str = typer.Argument(..., help="Target URL."),
    exposure_type: str = typer.Option("API_ENDPOINT", "--type", "-t"),
    wait: bool = typer.Option(False, "--wait", "-w"),
) -> None:
    """Validate an exposure finding."""
    from cves_cli.client.factory import exposure_client
    from cves_cli.output.streaming import poll_until_terminal, RichLivePoller
    from cves_cli.state import app_state

    async def _start() -> dict:
        async with exposure_client() as c:
            return await c.validate(
                tenant_id=app_state.effective_tenant_id() or "",
                target_url=url,
                exposure_type=exposure_type,
            )

    result = anyio.run(_start)
    job_id = str(result.get("job_id", result.get("id", "")))
    fmt.print(result, title="Exposure Validation Job")

    if not wait:
        return

    async def _poll() -> dict:
        with RichLivePoller(f"Validating {url[:40]}…") as poller:
            async def fetch() -> dict:
                async with exposure_client() as c:
                    return await c.get_job(job_id)

            return await poll_until_terminal(fetch, interval=3, timeout=300)

    final = anyio.run(_poll)
    fmt.print(final, title="Exposure Validation Complete")
