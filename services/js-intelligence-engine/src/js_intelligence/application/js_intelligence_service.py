from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

import structlog

from cves_db.types import TenantId

from js_intelligence.application.analyzers.bundle_discoverer import BundleDiscoverer
from js_intelligence.application.analyzers.bundler_detector import BundlerDetector
from js_intelligence.application.analyzers.chunk_correlator import ChunkCorrelator
from js_intelligence.application.analyzers.dependency_graph_builder import (
    DependencyGraphBuilder,
)
from js_intelligence.application.analyzers.route_inference_engine import (
    RouteInferenceEngine,
)
from js_intelligence.application.analyzers.source_map_analyzer import SourceMapAnalyzer
from js_intelligence.application.analyzers.vite_analyzer import ViteAnalyzer
from js_intelligence.application.analyzers.webpack_analyzer import WebpackAnalyzer
from js_intelligence.application.commands import AnalyzeJSCommand
from js_intelligence.domain.entities.js_analysis_job import JSAnalysisJob
from js_intelligence.domain.entities.js_intelligence_result import JSIntelligenceResult
from js_intelligence.domain.ports import (
    JSAnalysisJobRepository,
    JSIntelligenceEventPublisher,
    JSIntelligenceResultRepository,
)
from js_intelligence.domain.value_objects.bundler_signature import BundlerSignature
from js_intelligence.domain.value_objects.dependency_graph import DependencyGraph
from js_intelligence.domain.value_objects.js_bundle import JSBundle
from js_intelligence.domain.value_objects.source_map_entry import SourceMapEntry
from js_intelligence.infrastructure.ast.tree_sitter_parser import (
    ParseResult,
    TreeSitterJSParser,
)
from js_intelligence.infrastructure.fetcher.js_fetcher import JSFetcher, JSFetchResult

log = structlog.get_logger(__name__)

# Maximum concurrent JS fetches
_FETCH_SEMAPHORE = asyncio.Semaphore(10)


class JSIntelligenceService:
    """Orchestrates the full JS static analysis pipeline."""

    def __init__(
        self,
        job_repo: JSAnalysisJobRepository,
        result_repo: JSIntelligenceResultRepository,
        event_publisher: JSIntelligenceEventPublisher,
    ) -> None:
        self._job_repo = job_repo
        self._result_repo = result_repo
        self._publisher = event_publisher

        # Analyzers (stateless — shared across requests)
        self._discoverer = BundleDiscoverer()
        self._detector = BundlerDetector()
        self._sm_analyzer = SourceMapAnalyzer()
        self._webpack_analyzer = WebpackAnalyzer()
        self._vite_analyzer = ViteAnalyzer()
        self._route_engine = RouteInferenceEngine()
        self._graph_builder = DependencyGraphBuilder()
        self._correlator = ChunkCorrelator()

    async def analyze(self, cmd: AnalyzeJSCommand) -> str:
        """Submit a JS analysis job and execute the full pipeline.

        Returns the job_id. Execution happens in the calling task (use
        BackgroundTasks in the FastAPI router to run this non-blocking).
        """
        tenant_id = TenantId(cmd.tenant_id)
        job = JSAnalysisJob.create(
            tenant_id=tenant_id,
            target_url=cmd.target_url,
            correlation_id=cmd.correlation_id,
            options={
                "max_js_files": cmd.max_js_files,
                "fetch_source_maps": cmd.fetch_source_maps,
                "timeout_seconds": cmd.timeout_seconds,
            },
        )
        job.start()
        await self._job_repo.save(job)

        log.info(
            "js_intelligence_service.started",
            job_id=job.job_id,
            tenant_id=str(tenant_id),
            target_url=cmd.target_url,
        )

        async with JSFetcher(max_file_size_bytes=cmd.max_file_size_bytes) as fetcher:
            try:
                async with asyncio.timeout(cmd.timeout_seconds):
                    result = await self._run_pipeline(cmd, job, fetcher)
            except TimeoutError:
                job.fail("Analysis timed out")
                await self._job_repo.save(job)
                log.warning("js_intelligence_service.timeout", job_id=job.job_id)
                return job.job_id
            except Exception as exc:
                job.fail(str(exc)[:1024])
                await self._job_repo.save(job)
                log.exception(
                    "js_intelligence_service.failed",
                    job_id=job.job_id,
                    error=str(exc),
                )
                return job.job_id

        await self._result_repo.save(result)

        try:
            await self._publisher.publish_result(job, result)
        except Exception as exc:
            log.warning(
                "js_intelligence_service.publish_failed",
                job_id=job.job_id,
                error=str(exc),
            )

        stats = {
            "bundle_count": len(result.bundles),
            "route_count": len(result.hidden_routes),
            "source_map_entry_count": len(result.source_map_entries),
            "node_count": result.dependency_graph.node_count,
            "edge_count": result.dependency_graph.edge_count,
            "has_cycles": result.dependency_graph.has_cycles,
        }
        job.complete(result.result_id, stats)
        await self._job_repo.save(job)

        log.info(
            "js_intelligence_service.completed",
            job_id=job.job_id,
            **stats,
        )
        return job.job_id

    async def _run_pipeline(
        self,
        cmd: AnalyzeJSCommand,
        job: JSAnalysisJob,
        fetcher: JSFetcher,
    ) -> JSIntelligenceResult:
        # ── Step 1: Fetch HTML page ────────────────────────────────────────
        html_result = await fetcher.fetch_html(cmd.target_url)
        html_text = html_result.content.decode("utf-8", errors="replace")

        # ── Step 2: Discover JS bundle URLs ───────────────────────────────
        js_urls = self._discoverer.discover(html_text, cmd.target_url, cmd.max_js_files)
        log.debug("js_intelligence_service.bundles_discovered", count=len(js_urls), job_id=job.job_id)

        if not js_urls:
            # No JS found — return empty result
            return JSIntelligenceResult.create(
                job_id=job.job_id,
                bundles=[],
                source_map_entries=[],
                hidden_routes=[],
                dependency_graph=DependencyGraph(),
                bundler_signature=BundlerSignature(),
            )

        # ── Step 3: Fetch all JS bundles in parallel ───────────────────────
        fetch_results: list[JSFetchResult | None] = await asyncio.gather(
            *[self._fetch_js_safe(fetcher, url) for url in js_urls],
            return_exceptions=False,
        )
        valid_fetches = [fr for fr in fetch_results if fr is not None]

        # ── Step 4: Detect bundler (majority vote) ─────────────────────────
        contents = [fr.content.decode("utf-8", errors="replace") for fr in valid_fetches]
        bundler_sig = self._detector.detect(contents)

        # ── Step 5: AST parse all bundles in thread pool (CPU-bound) ──────
        parser = TreeSitterJSParser.get()
        parse_tasks = [
            asyncio.to_thread(parser.parse, fr.content, fr.url)
            for fr in valid_fetches
        ]
        parse_results: list[ParseResult] = list(await asyncio.gather(*parse_tasks))

        # ── Step 6: Source maps + webpack/vite analysis in parallel ───────
        async def _empty_sm() -> list[list[SourceMapEntry]]:
            return []

        sm_task = (
            self._collect_source_maps(valid_fetches, fetcher)
            if cmd.fetch_source_maps
            else _empty_sm()
        )

        async def _noop_bundler():
            return None

        if bundler_sig.bundler == "WEBPACK":
            bundler_task = asyncio.to_thread(
                self._run_webpack_analysis, contents, parse_results
            )
        elif bundler_sig.bundler == "VITE":
            vite_manifest = await self._fetch_vite_manifest(fetcher, cmd.target_url)
            bundler_task = asyncio.to_thread(
                self._run_vite_analysis, contents, vite_manifest
            )
        else:
            bundler_task = _noop_bundler()

        source_entries, bundler_data = await asyncio.gather(sm_task, bundler_task)

        webpack_manifest = bundler_data if bundler_sig.bundler == "WEBPACK" else None
        vite_manifest_result = bundler_data if bundler_sig.bundler == "VITE" else None

        # Merge all source map entries, deduplicate by (generated, original)
        all_sm_entries: list[SourceMapEntry] = []
        seen_sm = set()
        for entries in source_entries:
            for e in entries:
                key = (e.generated_file, e.original_file)
                if key not in seen_sm:
                    seen_sm.add(key)
                    all_sm_entries.append(e)

        # ── Step 7: Route inference ────────────────────────────────────────
        hidden_routes = self._route_engine.infer(
            parse_results, all_sm_entries, bundler_sig.bundler
        )

        # ── Step 8: Dependency graph ───────────────────────────────────────
        dep_graph = await self._graph_builder.build(parse_results, webpack_manifest)

        # ── Step 9: Chunk correlation ──────────────────────────────────────
        chunks = webpack_manifest.chunks if webpack_manifest else {}
        if vite_manifest_result:
            for src, outs in vite_manifest_result.chunks.items():
                chunks.setdefault(src, []).extend(outs)

        enriched_routes = self._correlator.correlate(hidden_routes, dep_graph, chunks)

        # ── Step 10: Build JSBundle value objects ─────────────────────────
        is_minified_threshold = 0.8  # >80% of lines are very long → minified
        bundles: list[JSBundle] = []
        for fr in valid_fetches:
            text = fr.content.decode("utf-8", errors="replace")
            lines = text.splitlines()
            long_lines = sum(1 for l in lines if len(l) > 500)
            is_minified = bool(lines) and (long_lines / max(len(lines), 1)) > is_minified_threshold

            bundles.append(
                JSBundle(
                    url=fr.url,
                    content_hash=fr.content_hash,
                    size_bytes=fr.size_bytes,
                    is_minified=is_minified,
                    bundler=bundler_sig.bundler,
                    source_map_url=fr.source_map_url,
                )
            )

        return JSIntelligenceResult.create(
            job_id=job.job_id,
            bundles=bundles,
            source_map_entries=all_sm_entries,
            hidden_routes=enriched_routes,
            dependency_graph=dep_graph,
            bundler_signature=bundler_sig,
        )

    async def _fetch_js_safe(self, fetcher: JSFetcher, url: str) -> JSFetchResult | None:
        async with _FETCH_SEMAPHORE:
            try:
                return await fetcher.fetch_js(url)
            except Exception as exc:
                log.debug("js_intelligence_service.fetch_failed", url=url, error=str(exc))
                return None

    async def _collect_source_maps(
        self,
        fetch_results: list[JSFetchResult],
        fetcher: JSFetcher,
    ) -> list[list[SourceMapEntry]]:
        tasks = [self._sm_analyzer.analyze(fr, fetcher) for fr in fetch_results]
        return list(await asyncio.gather(*tasks))

    async def _fetch_vite_manifest(
        self, fetcher: JSFetcher, base_url: str
    ) -> dict | None:
        manifest_url = _make_vite_manifest_url(base_url)
        try:
            raw = await fetcher.fetch_raw(manifest_url)
            import json
            return json.loads(raw.content)
        except Exception:
            return None

    def _run_webpack_analysis(self, contents: list[str], parse_results: list[ParseResult]):
        from js_intelligence.application.analyzers.webpack_analyzer import WebpackManifest
        manifest = WebpackManifest()
        for content, pr in zip(contents, parse_results):
            m = self._webpack_analyzer.analyze(content, pr)
            manifest.modules.update(m.modules)
            for k, v in m.chunks.items():
                manifest.chunks.setdefault(k, []).extend(v)
        return manifest

    def _run_vite_analysis(self, contents: list[str], vite_manifest):
        result = None
        for content in contents:
            r = self._vite_analyzer.analyze(content, vite_manifest)
            if result is None:
                result = r
            else:
                for k, v in r.chunks.items():
                    result.chunks.setdefault(k, []).extend(v)
                result.entry_points.extend(r.entry_points)
        return result


def _make_vite_manifest_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    return f"{parsed.scheme}://{parsed.netloc}/assets/manifest.json"
