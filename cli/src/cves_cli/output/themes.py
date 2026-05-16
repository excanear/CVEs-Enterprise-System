"""Rich color themes and status badges."""
from __future__ import annotations

from rich.text import Text

STATUS_COLORS: dict[str, str] = {
    # Scan / Job states
    "COMPLETED": "green",
    "PASSED": "green",
    "SUCCESS": "green",
    "FAILED": "red",
    "ERROR": "red",
    "RUNNING": "yellow",
    "IN_PROGRESS": "yellow",
    "ANALYZING": "yellow",
    "CANCELLED": "dim",
    "CANCELED": "dim",
    "STOPPED": "dim",
    "ABORTED": "dim",
    "PENDING": "blue",
    "QUEUED": "blue",
    "SCHEDULED": "blue",
    "WAITING": "blue",
    "PARTIAL": "orange3",
    "RETRYING": "orange3",
    # Health
    "HEALTHY": "green",
    "DEGRADED": "yellow",
    "UNHEALTHY": "red",
    "UNKNOWN": "dim",
}

TIER_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "dark_orange",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "dim",
}

_STATUS_ICON: dict[str, str] = {
    "COMPLETED": "●",
    "PASSED": "●",
    "SUCCESS": "●",
    "FAILED": "✗",
    "ERROR": "✗",
    "RUNNING": "◉",
    "IN_PROGRESS": "◉",
    "ANALYZING": "◉",
    "CANCELLED": "○",
    "CANCELED": "○",
    "STOPPED": "○",
    "ABORTED": "○",
    "PENDING": "◌",
    "QUEUED": "◌",
    "SCHEDULED": "◌",
    "PARTIAL": "◑",
    "RETRYING": "↺",
    "HEALTHY": "●",
    "DEGRADED": "◑",
    "UNHEALTHY": "✗",
    "UNKNOWN": "?",
}


def status_badge(status: str) -> Text:
    """Return a Rich Text badge like [bold green]● COMPLETED[/]."""
    norm = (status or "UNKNOWN").upper().replace("-", "_").replace(" ", "_")
    color = STATUS_COLORS.get(norm, "white")
    icon = _STATUS_ICON.get(norm, "·")
    t = Text()
    t.append(f"{icon} {norm}", style=color)
    return t


def tier_badge(tier: str) -> Text:
    norm = (tier or "").upper()
    color = TIER_COLORS.get(norm, "white")
    t = Text()
    t.append(norm, style=color)
    return t


def truncate_id(uuid: str, length: int = 8) -> str:
    return uuid[:length] if uuid else "—"


def fmt_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return "—"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


def fmt_pct(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value:.1f}%"
