"""CVEs Enterprise CLI — root Typer application."""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from cves_cli import __app_name__, __version__
from cves_cli.commands.auth import auth_app
from cves_cli.commands.context_cmd import context_app
from cves_cli.commands.scan import scan_app
from cves_cli.commands.discover import discover_app
from cves_cli.commands.analyze import analyze_app
from cves_cli.commands.graph import graph_app
from cves_cli.commands.correlate import correlate_app
from cves_cli.commands.report import report_app
from cves_cli.commands.workers import workers_app
from cves_cli.commands.health import health_app
from cves_cli.commands.plugin_cmd import plugin_app
from cves_cli.plugins.loader import discover_plugins, register_plugins
from cves_cli.state import OutputFormat, app_state

app = typer.Typer(
    name=__app_name__,
    help=(
        "[bold cyan]CVEs Enterprise[/bold cyan] — Attack Surface Management Platform\n\n"
        "Run [bold]cves --help[/bold] on any sub-command for detailed usage."
    ),
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=True,
)

# Register all built-in sub-apps
app.add_typer(auth_app)
app.add_typer(context_app)
app.add_typer(scan_app)
app.add_typer(discover_app)
app.add_typer(analyze_app)
app.add_typer(graph_app)
app.add_typer(correlate_app)
app.add_typer(report_app)
app.add_typer(workers_app)
app.add_typer(health_app)
app.add_typer(plugin_app)

# Register discovered third-party plugins
register_plugins(app, discover_plugins())


@app.callback(invoke_without_command=False)
def root(
    profile: str = typer.Option(
        "default",
        "--profile",
        "-p",
        envvar="CVES_PROFILE",
        help="Configuration profile to use.",
        is_eager=False,
    ),
    output: OutputFormat = typer.Option(
        OutputFormat.TABLE,
        "--output",
        "-o",
        envvar="CVES_OUTPUT",
        help="Output format: table | json | yaml | csv",
        case_sensitive=False,
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-data output."),
    no_header: bool = typer.Option(False, "--no-header", help="Omit table headers."),
    ci: bool = typer.Option(
        False,
        "--ci",
        envvar="CI",
        help="CI mode: JSON output, no color, no progress.",
    ),
    tenant: Optional[str] = typer.Option(
        None,
        "--tenant",
        envvar="CVES_TENANT_ID",
        help="Override active tenant ID.",
    ),
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """CVEs Enterprise ASM Platform CLI."""
    if version:
        Console().print(
            f"[bold cyan]{__app_name__}[/bold cyan] [green]{__version__}[/green]"
        )
        raise typer.Exit()

    if ci:
        output = OutputFormat.JSON
        no_header = True

    app_state.profile = profile
    app_state.output = output
    app_state.quiet = quiet
    app_state.no_header = no_header
    app_state.ci = ci
    app_state.tenant_override = tenant
