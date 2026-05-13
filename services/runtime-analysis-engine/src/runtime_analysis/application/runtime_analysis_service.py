from __future__ import annotations

import asyncio
import logging

import structlog

from runtime_analysis.application.analyzers.api_analyzer import APIAnalyzer
from runtime_analysis.application.analyzers.framework_classifier import (
    FrameworkClassifier,
)
from runtime_analysis.application.analyzers.hydration_analyzer import HydrationAnalyzer
from runtime_analysis.application.analyzers.spa_analyzer import SPAAnalyzer
from runtime_analysis.application.commands import AnalyzeURLCommand
from runtime_analysis.domain.entities.analysis_result import AnalysisResult
from runtime_analysis.domain.entities.analysis_session import AnalysisSession
from runtime_analysis.domain.ports import (
    AnalysisResultRepository,
    AnalysisSessionRepository,
    RuntimeEventPublisher,
)
from runtime_analysis.domain.value_objects.dom_snapshot import DOMSnapshot
from runtime_analysis.infrastructure.browser.browser_pool import BrowserPool
from runtime_analysis.infrastructure.browser.isolated_session import (
    IsolatedBrowserSession,
)

log = structlog.get_logger(__name__)


class RuntimeAnalysisService:
    def __init__(
        self,
        browser_pool: BrowserPool,
        session_repo: AnalysisSessionRepository,
        result_repo: AnalysisResultRepository,
        event_publisher: RuntimeEventPublisher,
    ) -> None:
        self._pool = browser_pool
        self._session_repo = session_repo
        self._result_repo = result_repo
        self._publisher = event_publisher

        self._hydration_analyzer = HydrationAnalyzer()
        self._spa_analyzer = SPAAnalyzer()
        self._api_analyzer = APIAnalyzer()
        self._framework_classifier = FrameworkClassifier()

    async def analyze(self, cmd: AnalyzeURLCommand) -> str:
        """
        Orchestrate a full browser-based runtime analysis.
        Returns session_id. Raises on unrecoverable errors.
        """
        session = AnalysisSession.create(
            tenant_id=cmd.tenant_id,  # type: ignore[arg-type]
            target_url=cmd.target_url,
            correlation_id=cmd.correlation_id,
            options={
                "max_spa_routes": cmd.max_spa_routes,
                "timeout_seconds": cmd.timeout_seconds,
            },
        )
        await self._session_repo.save(session)
        session.start()
        await self._session_repo.save(session)

        try:
            async with asyncio.timeout(cmd.timeout_seconds):
                result = await self._run_analysis(session, cmd)
        except TimeoutError:
            session.timeout()
            await self._session_repo.save(session)
            raise
        except Exception as exc:
            session.fail(str(exc))
            await self._session_repo.save(session)
            raise

        await self._result_repo.save(result)
        session.complete(result.result_id)
        await self._session_repo.save(session)

        await self._emit(session, result)
        return session.session_id

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------

    async def _run_analysis(
        self,
        session: AnalysisSession,
        cmd: AnalyzeURLCommand,
    ) -> AnalysisResult:
        async with self._pool.acquire() as browser:
            async with IsolatedBrowserSession(browser) as sess:
                await sess.navigate(cmd.target_url)
                captures = sess.captures

                # Run hydration analysis + framework classification in parallel
                hydration_result, response_headers = await asyncio.gather(
                    asyncio.to_thread(
                        self._hydration_analyzer.analyze,
                        captures.html_before,
                        captures.html_after,
                        captures.hydration_markers,
                        captures.console_errors,
                    ),
                    self._get_response_headers(sess),
                )

                framework_fingerprints = self._framework_classifier.assemble(
                    js_signals=captures.framework_signals,
                    hydration=hydration_result,
                    response_headers=response_headers,
                )

                # SPA route enumeration (sequential — mutates page state)
                discovered_paths = [rc["path"] for rc in captures.route_changes if rc.get("path")]
                spa_routes = await self._spa_analyzer.enumerate(
                    page=sess.page,
                    discovered_paths=discovered_paths,
                    max_routes=cmd.max_spa_routes,
                )

                # API classification (from both network interceptor + JS hooks)
                raw_calls = list(captures.network_calls)
                # Also include calls captured by the route-level interceptor
                raw_calls += [
                    {
                        "url": api.url,
                        "method": api.method,
                        "status": api.status_code,
                        "requestBody": api.request_body_sample,
                        "responseBody": api.response_body_sample,
                    }
                    for api in sess.network_interceptor.intercepted_apis
                ]
                intercepted_apis = self._api_analyzer.classify(raw_calls)

                ws_endpoints = sess.get_websocket_endpoints()

                # Build DOM snapshot from mutation events
                dom_snapshot = self._build_dom_snapshot(
                    captures.html_before,
                    captures.html_after,
                    captures.dom_mutations,
                )

        return AnalysisResult.create(
            session_id=session.session_id,
            intercepted_apis=intercepted_apis,
            websocket_endpoints=ws_endpoints,
            spa_routes=spa_routes,
            framework_fingerprints=framework_fingerprints,
            dom_snapshot=dom_snapshot,
            hydration_markers=captures.hydration_markers,
        )

    async def _get_response_headers(self, sess: IsolatedBrowserSession) -> dict[str, str]:
        try:
            resp = await sess.page.evaluate(
                """() => {
                    const entries = performance.getEntriesByType('navigation');
                    if (!entries.length) return {};
                    const entry = entries[0];
                    return {};
                }"""
            )
        except Exception:
            pass
        # Headers are not directly accessible from JS; rely on interceptor
        return {}

    def _build_dom_snapshot(
        self,
        html_before: str,
        html_after: str,
        mutations: list[dict],
    ) -> DOMSnapshot | None:
        if not mutations:
            return DOMSnapshot(
                html_bytes_before=len(html_before.encode()),
                html_bytes_after=len(html_after.encode()),
                node_additions=0,
                node_removals=0,
                attr_changes=0,
            )

        added_scripts: list[str] = []
        added_forms: list[str] = []
        total_additions = 0
        total_removals = 0
        total_attrs = 0

        for mut in mutations:
            total_additions += mut.get("nodeAdditions", 0)
            total_removals += mut.get("nodeRemovals", 0)
            total_attrs += mut.get("attrChanges", 0)
            added_scripts.extend(mut.get("addedScripts", []))
            added_forms.extend(mut.get("addedForms", []))

        return DOMSnapshot(
            html_bytes_before=len(html_before.encode()),
            html_bytes_after=len(html_after.encode()),
            node_additions=total_additions,
            node_removals=total_removals,
            attr_changes=total_attrs,
            added_scripts=tuple(added_scripts),
            added_forms=tuple(added_forms),
        )

    async def _emit(self, session: AnalysisSession, result: AnalysisResult) -> None:
        try:
            await self._publisher.publish_result(session, result)
        except Exception as exc:
            log.error(
                "runtime_analysis.publish_failed",
                session_id=session.session_id,
                error=str(exc),
            )
