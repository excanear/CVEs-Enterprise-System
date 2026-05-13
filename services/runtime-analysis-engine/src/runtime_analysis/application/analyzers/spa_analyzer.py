from __future__ import annotations

import asyncio
import logging

from playwright.async_api import Page

from runtime_analysis.domain.value_objects.spa_route import SPARoute

log = logging.getLogger(__name__)

_ROUTE_SETTLE_MS = 1_000  # wait after pushState before sampling new calls
_SCRIPT_SRC_SELECTOR = "script[src]"


class SPAAnalyzer:
    """
    Enumerates SPA routes by replaying captured pushState changes and
    observing network activity per route.
    """

    async def enumerate(
        self,
        page: Page,
        discovered_paths: list[str],
        max_routes: int = 20,
        initial_path: str = "/",
    ) -> list[SPARoute]:
        routes: list[SPARoute] = []

        # Initial route
        routes.append(
            SPARoute(
                path=initial_path,
                triggered_by="initial",
                lazy_chunks=(),
                api_calls_count=0,
            )
        )

        seen_paths: set[str] = {initial_path}

        for path in discovered_paths:
            if len(routes) >= max_routes:
                break
            if path in seen_paths:
                continue
            seen_paths.add(path)

            try:
                # Collect scripts before navigation
                scripts_before: set[str] = await self._get_script_srcs(page)

                # Trigger client-side navigation
                await page.evaluate(
                    "([path]) => history.pushState({}, '', path)",
                    [path],
                )
                await asyncio.sleep(_ROUTE_SETTLE_MS / 1000)

                # Collect scripts after navigation to detect lazy chunks
                scripts_after: set[str] = await self._get_script_srcs(page)
                lazy_chunks = tuple(scripts_after - scripts_before)

                routes.append(
                    SPARoute(
                        path=path,
                        triggered_by="pushState",
                        lazy_chunks=lazy_chunks,
                        api_calls_count=0,  # caller may enrich later
                    )
                )
            except Exception as exc:
                log.debug(
                    "spa_analyzer.route_error",
                    extra={"path": path, "error": str(exc)},
                )

        return routes

    async def _get_script_srcs(self, page: Page) -> set[str]:
        try:
            srcs: list[str] = await page.evaluate(
                "() => Array.from(document.querySelectorAll('script[src]')).map(s => s.src)"
            )
            return set(srcs)
        except Exception:
            return set()
