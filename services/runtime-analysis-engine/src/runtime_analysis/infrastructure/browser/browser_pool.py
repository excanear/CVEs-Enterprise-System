from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import AsyncIterator

from playwright.async_api import Browser, Playwright, async_playwright

log = logging.getLogger(__name__)

_WATCHDOG_INTERVAL = 10  # seconds


@dataclass
class _BrowserSlot:
    browser: Browser
    index: int


class BrowserPool:
    """
    Manages a fixed pool of Playwright Browser instances with back-pressure
    via an asyncio.Semaphore. A watchdog task restarts dead browsers.
    """

    def __init__(self, size: int = 3) -> None:
        self._size = size
        self._playwright: Playwright | None = None
        self._slots: list[_BrowserSlot] = []
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(size)
        self._available: asyncio.Queue[_BrowserSlot] = asyncio.Queue()
        self._watchdog_task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._stopped = False

        # Stats
        self._acquired: int = 0
        self._released: int = 0

    async def start(self, playwright: Playwright) -> None:
        self._playwright = playwright
        for i in range(self._size):
            browser = await playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                ],
            )
            slot = _BrowserSlot(browser=browser, index=i)
            self._slots.append(slot)
            self._available.put_nowait(slot)
        self._watchdog_task = asyncio.create_task(self._watchdog())
        log.info("browser_pool.started", extra={"pool_size": self._size})

    async def stop(self) -> None:
        self._stopped = True
        if self._watchdog_task:
            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except asyncio.CancelledError:
                pass
        for slot in self._slots:
            try:
                await slot.browser.close()
            except Exception:
                pass
        log.info("browser_pool.stopped")

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[Browser]:
        """Acquire a browser from the pool (blocks when pool is exhausted)."""
        async with self._semaphore:
            slot = await self._available.get()
            self._acquired += 1
            try:
                # Restart dead browser before handing it over
                if not slot.browser.is_connected():
                    slot.browser = await self._restart_browser(slot.index)
                yield slot.browser
            finally:
                self._released += 1
                self._available.put_nowait(slot)

    async def _restart_browser(self, index: int) -> Browser:
        assert self._playwright is not None
        log.warning("browser_pool.restarting", extra={"index": index})
        browser = await self._playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-extensions",
            ],
        )
        self._slots[index].browser = browser
        return browser

    async def _watchdog(self) -> None:
        while not self._stopped:
            await asyncio.sleep(_WATCHDOG_INTERVAL)
            for slot in self._slots:
                try:
                    if not slot.browser.is_connected():
                        log.warning(
                            "browser_pool.watchdog.dead_browser",
                            extra={"index": slot.index},
                        )
                        # Put the restarted browser back; the acquire context
                        # manager also handles this, but proactive restart
                        # keeps the pool healthy.
                        slot.browser = await self._restart_browser(slot.index)
                except Exception as exc:
                    log.exception(
                        "browser_pool.watchdog.error",
                        extra={"index": slot.index, "error": str(exc)},
                    )

    @property
    def stats(self) -> dict[str, int]:
        return {
            "pool_size": self._size,
            "acquired_total": self._acquired,
            "released_total": self._released,
            "available": self._available.qsize(),
        }
