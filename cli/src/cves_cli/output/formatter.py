"""OutputFormatter — routes data to Rich table, JSON, YAML, or CSV."""
from __future__ import annotations

import csv
import io
import sys
from typing import Any

import orjson
import yaml
from rich.console import Console
from rich.table import Table

from cves_cli.state import OutputFormat, app_state


def _console() -> Console:
    return Console(stderr=False, highlight=False, no_color=app_state.ci)


def _flatten(data: Any) -> list[dict]:
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    return [{"value": data}]


def _to_csv(data: Any) -> str:
    rows = _flatten(data)
    if not rows:
        return ""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()), extrasaction="ignore")
    if not app_state.no_header:
        writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


class OutputFormatter:
    """Central formatter — picks the right sink based on app_state.output."""

    def print(
        self,
        data: Any,
        *,
        table_factory: Any = None,
        title: str | None = None,
    ) -> None:
        """Render data.

        Args:
            data: Raw data (list/dict).
            table_factory: Callable that takes data and returns a Rich Table.
                           Only used when output==TABLE.
            title: Optional Rich markup title printed above TABLE output.
        """
        fmt = app_state.output
        quiet = app_state.quiet

        if fmt == OutputFormat.JSON or app_state.ci:
            if not quiet:
                raw = orjson.dumps(data, option=orjson.OPT_INDENT_2).decode()
                print(raw)
            return

        if fmt == OutputFormat.YAML:
            if not quiet:
                print(yaml.dump(data, default_flow_style=False, allow_unicode=True), end="")
            return

        if fmt == OutputFormat.CSV:
            if not quiet:
                print(_to_csv(data), end="")
            return

        # TABLE (default)
        if quiet:
            return

        console = _console()
        if title:
            console.print(f"[bold]{title}[/bold]")

        if table_factory is not None:
            table: Table = table_factory(data)
            if app_state.no_header:
                table.show_header = False
            console.print(table)
        else:
            # Fallback: pretty JSON
            raw = orjson.dumps(data, option=orjson.OPT_INDENT_2).decode()
            console.print_json(raw)

    def error(self, message: str) -> None:
        if app_state.ci:
            print(orjson.dumps({"error": message}).decode(), file=sys.stderr)
        else:
            Console(stderr=True).print(f"[bold red]Error:[/bold red] {message}")

    def warn(self, message: str) -> None:
        if not app_state.quiet:
            if app_state.ci:
                print(orjson.dumps({"warning": message}).decode(), file=sys.stderr)
            else:
                Console(stderr=True).print(f"[yellow]Warning:[/yellow] {message}")

    def info(self, message: str) -> None:
        if not app_state.quiet and not app_state.ci:
            Console(stderr=True).print(f"[dim]{message}[/dim]")

    def success(self, message: str) -> None:
        if not app_state.quiet:
            if app_state.ci:
                print(orjson.dumps({"message": message}).decode())
            else:
                Console().print(f"[green]✓[/green] {message}")


fmt = OutputFormatter()
