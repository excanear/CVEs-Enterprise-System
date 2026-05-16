"""Report commands — generate, list, get, download, executive, compliance, evidence."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import anyio
import typer

from cves_cli.output.formatter import fmt
from cves_cli.output.tables import report_table

report_app = typer.Typer(name="report", help="Report generation and download.", no_args_is_help=True)


def _tenant(t: Optional[str]) -> str:
    from cves_cli.state import app_state

    return t or app_state.effective_tenant_id() or ""


@report_app.command("generate")
def report_generate(
    report_type: str = typer.Option("EXECUTIVE", "--type", "-t", help="EXECUTIVE | TECHNICAL | REMEDIATION | COMPLIANCE | EVIDENCE_EXPORT"),
    report_format: str = typer.Option("JSON", "--format", "-f", help="JSON | HTML | PDF | CSV"),
    tenant: Optional[str] = typer.Option(None, "--tenant"),
    wait: bool = typer.Option(False, "--wait", "-w"),
    timeout: int = typer.Option(300, "--timeout"),
) -> None:
    """Generate a new report."""
    from cves_cli.client.factory import reporting_client
    from cves_cli.output.streaming import poll_until_terminal, RichLivePoller

    async def _start() -> dict:
        async with reporting_client() as c:
            return await c.generate(
                tenant_id=_tenant(tenant),
                report_type=report_type,
                report_format=report_format,
            )

    result = anyio.run(_start)
    report_id = str(result.get("report_id", result.get("id", "")))
    fmt.success(f"Report generating: {report_id}")

    if not wait:
        return

    async def _poll() -> dict:
        with RichLivePoller("Generating report…"):
            async def fetch() -> dict:
                async with reporting_client() as c:
                    return await c.get(tenant_id=_tenant(tenant), report_id=report_id)

            return await poll_until_terminal(fetch, interval=5, timeout=timeout)

    final = anyio.run(_poll)
    fmt.print(final, title="Report Ready")


@report_app.command("list")
def report_list(
    tenant: Optional[str] = typer.Option(None, "--tenant"),
    limit: int = typer.Option(50, "--limit", "-n"),
) -> None:
    """List generated reports."""
    from cves_cli.client.factory import reporting_client

    async def _list() -> list:
        async with reporting_client() as c:
            return await c.list(tenant_id=_tenant(tenant), limit=limit)

    rows = anyio.run(_list)
    fmt.print(rows, table_factory=report_table, title="Reports")


@report_app.command("get")
def report_get(
    report_id: str = typer.Argument(...),
    tenant: Optional[str] = typer.Option(None, "--tenant"),
) -> None:
    """Show details of a single report."""
    from cves_cli.client.factory import reporting_client

    async def _get() -> dict:
        async with reporting_client() as c:
            return await c.get(tenant_id=_tenant(tenant), report_id=report_id)

    data = anyio.run(_get)
    fmt.print(data, table_factory=lambda d: report_table([d]))


@report_app.command("download")
def report_download(
    report_id: str = typer.Argument(...),
    tenant: Optional[str] = typer.Option(None, "--tenant"),
    output: Path = typer.Option(Path("."), "--output", "-o", help="Output file or directory."),
) -> None:
    """Download a report file."""
    from cves_cli.client.factory import reporting_client

    async def _dl() -> bytes:
        async with reporting_client() as c:
            return await c.download(tenant_id=_tenant(tenant), report_id=report_id)

    content = anyio.run(_dl)
    out_path = output if output.suffix else output / f"report-{report_id[:8]}.bin"
    out_path.write_bytes(content)
    fmt.success(f"Downloaded {len(content):,} bytes → {out_path}")


@report_app.command("executive")
def report_executive(
    tenant: Optional[str] = typer.Option(None, "--tenant"),
) -> None:
    """Show the executive summary."""
    from cves_cli.client.factory import reporting_client

    async def _get() -> dict:
        async with reporting_client() as c:
            return await c.executive_summary(tenant_id=_tenant(tenant))

    data = anyio.run(_get)
    fmt.print(data, title="Executive Summary")


@report_app.command("compliance")
def report_compliance(
    tenant: Optional[str] = typer.Option(None, "--tenant"),
) -> None:
    """Show compliance mapping."""
    from cves_cli.client.factory import reporting_client

    async def _get() -> list:
        async with reporting_client() as c:
            return await c.compliance_mapping(tenant_id=_tenant(tenant))

    rows = anyio.run(_get)
    fmt.print(rows, title="Compliance Mapping")


@report_app.command("evidence")
def report_evidence(
    tenant: Optional[str] = typer.Option(None, "--tenant"),
    output: Path = typer.Option(Path("evidence.csv"), "--output", "-o"),
) -> None:
    """Export all evidence as CSV."""
    from cves_cli.client.factory import reporting_client

    async def _get() -> bytes:
        async with reporting_client() as c:
            return await c.evidence_export(tenant_id=_tenant(tenant))

    content = anyio.run(_get)
    output.write_bytes(content)
    fmt.success(f"Evidence exported → {output}")
