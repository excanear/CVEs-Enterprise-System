from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import AsyncIterator
from urllib.parse import urlparse

from playwright.async_api import Browser, BrowserContext, Page

from runtime_analysis.domain.value_objects.websocket_endpoint import WebSocketEndpoint
from runtime_analysis.infrastructure.browser.network_interceptor import (
    NetworkInterceptor,
)
from runtime_analysis.infrastructure.browser.script_loader import combined_script

log = logging.getLogger(__name__)

_HYDRATION_WAIT_MS = 2_000
_NAVIGATION_TIMEOUT_MS = 30_000

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _ssrf_check(url: str) -> None:
    """Raise ValueError if the hostname resolves to a private/loopback address."""
    try:
        hostname = urlparse(url).hostname or ""
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        if any(ip in net for net in _PRIVATE_NETS):
            raise ValueError(f"SSRF guard: {url!r} resolves to private IP {ip!s}")
    except ValueError:
        raise
    except Exception:
        pass  # DNS failure — let the browser handle it (will timeout or fail)


@dataclass
class SessionCaptures:
    """All data collected during one isolated browser session."""

    html_before: str = ""
    html_after: str = ""
    hydration_markers: dict = field(default_factory=dict)
    framework_signals: list[dict] = field(default_factory=list)
    route_changes: list[dict] = field(default_factory=list)
    dom_mutations: list[dict] = field(default_factory=list)
    ws_events: list[dict] = field(default_factory=list)
    network_calls: list[dict] = field(default_factory=list)
    console_errors: list[str] = field(default_factory=list)


class IsolatedBrowserSession:
    """
    Creates a clean BrowserContext (no shared cookies/storage) per analysis.
    Installs all instrumentation scripts and exposes Python callbacks.
    Closes the context on exit — no cross-session state leakage.
    """

    def __init__(self, browser: Browser) -> None:
        self._browser = browser
        self._context: BrowserContext | None = None
        self._page: Page | None = None
        self._interceptor = NetworkInterceptor()
        self.captures = SessionCaptures()

    async def __aenter__(self) -> "IsolatedBrowserSession":
        self._context = await self._browser.new_context(
            java_script_enabled=True,
            bypass_csp=True,          # allow init scripts on CSP-protected pages
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 "
                "CVEsRAE/1.0"
            ),
        )
        await self._context.add_init_script(combined_script)

        self._page = await self._context.new_page()
        page = self._page

        # Network interception (SSRF guard + API capture)
        await self._interceptor.install(page)

        # Expose Python callbacks that JS can invoke
        await page.expose_function("__onNetworkCall", self._on_network_call)
        await page.expose_function("__onWSEvent", self._on_ws_event)
        await page.expose_function("__onRouteChange", self._on_route_change)
        await page.expose_function("__onMutation", self._on_mutation)
        await page.expose_function("__onFrameworkSignal", self._on_framework_signal)

        # Capture console errors for hydration mismatch detection
        page.on("console", self._on_console)

        return self

    async def __aexit__(self, *_: object) -> None:
        if self._context:
            try:
                await self._context.close()
            except Exception:
                pass
        self._context = None
        self._page = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def navigate(self, url: str) -> None:
        _ssrf_check(url)
        page = self._page
        assert page is not None

        # Capture HTML *before* hydration (plain HTTP response body)
        response = await page.goto(
            url,
            wait_until="domcontentloaded",
            timeout=_NAVIGATION_TIMEOUT_MS,
        )
        if response:
            try:
                self.captures.html_before = await response.text()
            except Exception:
                self.captures.html_before = ""

        # Wait for network to settle + SPA hydration
        try:
            await page.wait_for_load_state("networkidle", timeout=_NAVIGATION_TIMEOUT_MS)
        except Exception:
            pass
        await asyncio.sleep(_HYDRATION_WAIT_MS / 1000)

        # Capture HTML *after* hydration
        self.captures.html_after = await page.content()

        # Read hydration markers injected by our init script
        try:
            markers = await page.evaluate("() => window.__hydrationMarkers || {}")
            self.captures.hydration_markers = markers or {}
        except Exception:
            pass

    @property
    def page(self) -> Page:
        assert self._page is not None
        return self._page

    @property
    def network_interceptor(self) -> NetworkInterceptor:
        return self._interceptor

    # ------------------------------------------------------------------
    # JS callback handlers (called from page JS, run in asyncio context)
    # ------------------------------------------------------------------

    def _on_network_call(self, data: dict) -> None:
        self.captures.network_calls.append(data)

    def _on_ws_event(self, data: dict) -> None:
        self.captures.ws_events.append(data)

    def _on_route_change(self, data: dict) -> None:
        self.captures.route_changes.append(data)

    def _on_mutation(self, data: dict) -> None:
        self.captures.dom_mutations.append(data)

    def _on_framework_signal(self, data: dict) -> None:
        self.captures.framework_signals.append(data)

    def _on_console(self, msg: object) -> None:
        try:
            if getattr(msg, "type", None) == "error":
                self.captures.console_errors.append(str(msg.text))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helpers to build domain value objects from captures
    # ------------------------------------------------------------------

    def get_websocket_endpoints(self) -> list[WebSocketEndpoint]:
        seen: dict[str, WebSocketEndpoint] = {}
        for evt in self.captures.ws_events:
            url = evt.get("url", "")
            if not url:
                continue
            if url not in seen:
                seen[url] = WebSocketEndpoint(
                    url=url,
                    protocols=tuple(evt.get("protocols", [])),
                    message_samples=(),
                    first_seen_at=datetime.now(UTC),
                )
            else:
                existing = seen[url]
                if evt.get("event") in ("message_sent", "message_received"):
                    data = evt.get("data", "")
                    if data:
                        seen[url] = WebSocketEndpoint(
                            url=existing.url,
                            protocols=existing.protocols,
                            message_samples=existing.message_samples + (data[:256],),
                            first_seen_at=existing.first_seen_at,
                        )
        return list(seen.values())
