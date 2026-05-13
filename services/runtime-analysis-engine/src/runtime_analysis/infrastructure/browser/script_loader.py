from __future__ import annotations

from pathlib import Path

_SCRIPTS_DIR = Path(__file__).parent / "scripts"

# Order matters: hydration markers must run first (captures SSR data before
# the framework removes it), then network hooks, then framework probe, then
# route tracker, then DOM observer.
_SCRIPT_ORDER = [
    "hydration_markers.js",
    "network_hooks.js",
    "framework_probe.js",
    "route_tracker.js",
    "dom_observer.js",
]


def _load_scripts() -> str:
    parts: list[str] = []
    for name in _SCRIPT_ORDER:
        path = _SCRIPTS_DIR / name
        parts.append(f"/* ===== {name} ===== */")
        parts.append(path.read_text(encoding="utf-8"))
    return "\n\n".join(parts)


# Loaded once at module import time — all workers share the same string
combined_script: str = _load_scripts()
