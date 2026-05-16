"""Discovery commands — start, list, get, assets, watch."""
from __future__ import annotations

from typing import List, Optional

import anyio
import typer

from cves_cli.output.formatter import fmt
from cves_cli.output.tables import asset_table, job_table

discover_app = typer.Typer(name="discover", help="Asset discovery operations.", no_args_is_help=True)


@discover_app.command("start")
def discover_start(
    domain: str = typer.Argument(..., help="Target domain to crawl."),
    scope: List[str] = typer.Option([], "--scope", "-s", help="Additional in-scope domains."),
    depth: int = typer.Option(3, "--depth", "-d"),
    pages: int = typer.Option(200, "--pages"),
    rps: float = typer.Option(5.0, "--rps"),
    wait: bool = typer.Option(False, "--wait", "-w"),
    no_tui: bool = typer.Option(False, "--no-tui"),
    timeout: int = typer.Option(3600, "--timeout"),
) -> None:
    """Start a new discovery crawl."""
    from cves_cli.client.factory import discovery_client
    from cves_cli.output.streaming import poll_until_terminal, RichLivePoller
    from cves_cli.state import app_state
    from cves_cli.tui.discover_watch import DiscoverWatchApp

    async def _start() -> dict:
        async with discovery_client() as c:
            return await c.start(
                target_domain=domain,
                scope_domains=list(scope) or [domain],
                max_depth=depth,
                max_pages=pages,
                max_rps=rps,
            )

    result = anyio.run(_start)
    job_id = str(result.get("job_id", result.get("id", "")))
    fmt.success(f"Discovery started: {job_id}")
    fmt.print(result)

    if not wait:
        return

    if not no_tui and not app_state.ci:
        cfg = app_state.get_config()
        ae = cfg.get_active_auth_entry()
        DiscoverWatchApp(
            job_id=job_id,
            auth_name=ae.name if ae else "default",
            auth_type=ae.type if ae else "api_key",
            tenant_id=app_state.effective_tenant_id(),
            endpoints=cfg.get_active_endpoints(),
        ).run()
        return

    async def _poll() -> dict:
        with RichLivePoller(f"Watching discovery {job_id[:8]}…") as poller:
            async def fetch() -> dict:
                async with discovery_client() as c:
                    return await c.get_job(job_id)

            def on_update(data: dict) -> None:
                s = data.get("status", "?")
                count = data.get("assets_found", data.get("assets_discovered", "?"))
                poller.update(f"[cyan]{job_id[:8]}[/cyan] {s} — {count} assets found")

            return await poll_until_terminal(fetch, interval=3, timeout=timeout, on_update=on_update)

    final = anyio.run(_poll)
    fmt.print(final, title="Discovery Complete")


@discover_app.command("list")
def discover_list(
    limit: int = typer.Option(20, "--limit", "-n"),
) -> None:
    """List discovery jobs."""
    from cves_cli.client.factory import discovery_client

    async def _list() -> list:
        async with discovery_client() as c:
            return await c.list_jobs(limit=limit)

    rows = anyio.run(_list)
    fmt.print(rows, table_factory=job_table, title="Discovery Jobs")


@discover_app.command("get")
def discover_get(
    job_id: str = typer.Argument(...),
) -> None:
    """Get details for a discovery job."""
    from cves_cli.client.factory import discovery_client

    async def _get() -> dict:
        async with discovery_client() as c:
            return await c.get_job(job_id)

    result = anyio.run(_get)
    fmt.print(result, table_factory=lambda d: job_table([d]))


@discover_app.command("assets")
def discover_assets(
    job_id: str = typer.Argument(...),
    asset_type: Optional[str] = typer.Option(None, "--type", "-t", help="HOST | DOMAIN | URL | ENDPOINT | CERTIFICATE"),
) -> None:
    """List assets discovered by a job."""
    from cves_cli.client.factory import discovery_client

    async def _assets() -> list:
        async with discovery_client() as c:
            return await c.job_assets(job_id, asset_type=asset_type)

    rows = anyio.run(_assets)
    fmt.print(rows, table_factory=asset_table, title=f"Assets [{job_id[:8]}]")


@discover_app.command("watch")
def discover_watch(
    job_id: str = typer.Argument(...),
) -> None:
    """Open live TUI watcher for a discovery job."""
    from cves_cli.state import app_state
    from cves_cli.tui.discover_watch import DiscoverWatchApp

    cfg = app_state.get_config()
    ae = cfg.get_active_auth_entry()
    DiscoverWatchApp(
        job_id=job_id,
        auth_name=ae.name if ae else "default",
        auth_type=ae.type if ae else "api_key",
        tenant_id=app_state.effective_tenant_id(),
        endpoints=cfg.get_active_endpoints(),
    ).run()
