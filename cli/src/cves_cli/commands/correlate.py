"""Correlation commands — trigger AI analysis, view clusters, paths, exposures."""
from __future__ import annotations

from typing import Optional

import anyio
import typer

from cves_cli.output.formatter import fmt
from cves_cli.output.tables import attack_path_table, cluster_table

correlate_app = typer.Typer(name="correlate", help="AI correlation analysis.", no_args_is_help=True)


def _tenant(t: Optional[str]) -> str:
    from cves_cli.state import app_state

    return t or app_state.effective_tenant_id() or ""


@correlate_app.command("run")
def correlate_run(
    tenant: Optional[str] = typer.Option(None, "--tenant"),
    wait: bool = typer.Option(False, "--wait", "-w"),
    timeout: int = typer.Option(300, "--timeout"),
) -> None:
    """Trigger AI correlation analysis for the tenant."""
    from cves_cli.client.factory import correlation_client
    from cves_cli.output.streaming import poll_until_terminal, RichLivePoller

    async def _start() -> dict:
        async with correlation_client() as c:
            return await c.trigger(tenant_id=_tenant(tenant))

    result = anyio.run(_start)
    session_id = str(result.get("session_id", result.get("id", "")))
    fmt.success(f"Correlation session: {session_id}")

    if not wait:
        return

    async def _poll() -> dict:
        with RichLivePoller("Running AI correlation…") as poller:
            async def fetch() -> dict:
                async with correlation_client() as c:
                    return await c.get_session(session_id)

            return await poll_until_terminal(fetch, interval=5, timeout=timeout)

    final = anyio.run(_poll)
    fmt.print(final, title="Correlation Complete")


@correlate_app.command("clusters")
def correlate_clusters(
    tenant: Optional[str] = typer.Option(None, "--tenant"),
    session: Optional[str] = typer.Option(None, "--session", "-s"),
) -> None:
    """Show vulnerability clusters."""
    from cves_cli.client.factory import correlation_client

    async def _get() -> list:
        async with correlation_client() as c:
            return await c.clusters(tenant_id=_tenant(tenant), session_id=session)

    rows = anyio.run(_get)
    fmt.print(rows, table_factory=cluster_table, title="Clusters")


@correlate_app.command("paths")
def correlate_paths(
    tenant: Optional[str] = typer.Option(None, "--tenant"),
    limit: int = typer.Option(50, "--limit", "-n"),
) -> None:
    """Show ranked attack paths from AI analysis."""
    from cves_cli.client.factory import correlation_client

    async def _get() -> list:
        async with correlation_client() as c:
            return await c.ranked_paths(tenant_id=_tenant(tenant), limit=limit)

    rows = anyio.run(_get)
    fmt.print(rows, table_factory=attack_path_table, title="Ranked Attack Paths")


@correlate_app.command("exposures")
def correlate_exposures(
    tenant: Optional[str] = typer.Option(None, "--tenant"),
) -> None:
    """Show prioritized exposures."""
    from cves_cli.client.factory import correlation_client

    async def _get() -> list:
        async with correlation_client() as c:
            return await c.prioritized_exposures(tenant_id=_tenant(tenant))

    rows = anyio.run(_get)
    fmt.print(rows, title="Prioritized Exposures")


@correlate_app.command("remediation")
def correlate_remediation(
    cluster_id: str = typer.Argument(...),
) -> None:
    """Get remediation guidance for a cluster."""
    from cves_cli.client.factory import correlation_client

    async def _get() -> dict:
        async with correlation_client() as c:
            return await c.remediation(cluster_id)

    data = anyio.run(_get)
    fmt.print(data, title=f"Remediation [{cluster_id[:8]}]")
