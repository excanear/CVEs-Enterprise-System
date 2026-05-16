"""Base Textual application with dark theme, keybindings, header/footer."""
from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header

DARK_CSS = """
Screen {
    background: $surface;
}

.panel {
    border: round $primary;
    padding: 1;
    margin: 1;
}

.panel-title {
    color: $accent;
    text-style: bold;
}

DataTable {
    height: 1fr;
}

ProgressBar {
    margin: 1;
}
"""


class CVEsApp(App):
    """Shared base for all CVEs TUI apps."""

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "force_refresh", "Refresh"),
        Binding("e", "export", "Export JSON"),
    ]

    CSS = DARK_CSS

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Footer()

    def action_force_refresh(self) -> None:
        """Override in subclasses to trigger manual refresh."""

    def action_export(self) -> None:
        """Override in subclasses to export current data as JSON."""
