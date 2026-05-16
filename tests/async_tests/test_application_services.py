"""Async tests — RuntimeAnalysisService and JSIntelligenceService."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestRuntimeAnalysisServiceAsync:
    """Tests for RuntimeAnalysisService without real browser pool."""

    @pytest.fixture
    def mock_browser_pool(self):
        pool = MagicMock()
        pool.acquire = AsyncMock()
        pool.release = AsyncMock()
        # Context manager support
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=MagicMock())
        ctx.__aexit__ = AsyncMock(return_value=None)
        pool.acquire.return_value = ctx
        return pool

    @pytest.fixture
    def mock_session_repo(self):
        repo = MagicMock()
        repo.save = AsyncMock()
        repo.get = AsyncMock(return_value=None)
        return repo

    @pytest.fixture
    def mock_result_repo(self):
        repo = MagicMock()
        repo.save = AsyncMock()
        repo.get_by_session = AsyncMock(return_value=None)
        return repo

    @pytest.fixture
    def mock_event_publisher(self):
        pub = MagicMock()
        pub.publish_result = AsyncMock()
        return pub

    async def test_analyze_creates_session_and_persists(
        self, mock_browser_pool, mock_session_repo, mock_result_repo, mock_event_publisher
    ):
        """Verify analyze() saves a session even if browser fails gracefully."""
        from runtime_analysis.application.commands import AnalyzeURLCommand

        with patch("runtime_analysis.application.runtime_analysis_service.BrowserPool", return_value=mock_browser_pool):
            from runtime_analysis.application.runtime_analysis_service import RuntimeAnalysisService

            svc = RuntimeAnalysisService(
                browser_pool=mock_browser_pool,
                session_repo=mock_session_repo,
                result_repo=mock_result_repo,
                event_publisher=mock_event_publisher,
            )

            cmd = AnalyzeURLCommand(
                tenant_id=str(uuid.uuid4()),
                target_url="https://example.com",
                correlation_id=str(uuid.uuid4()),
                max_spa_routes=5,
                timeout_seconds=30,
            )

            try:
                await svc.analyze(cmd)
            except Exception:
                pass  # Browser pool errors are expected without real infra

            # Session should have been saved at least once (on create)
            assert mock_session_repo.save.called


class TestJSIntelligenceServiceAsync:
    """Tests for JSIntelligenceService without real tree-sitter."""

    @pytest.fixture
    def mock_job_repo(self):
        repo = MagicMock()
        repo.save = AsyncMock()
        repo.get = AsyncMock(return_value=None)
        return repo

    @pytest.fixture
    def mock_result_repo(self):
        repo = MagicMock()
        repo.save = AsyncMock()
        repo.get_by_job = AsyncMock(return_value=None)
        return repo

    @pytest.fixture
    def mock_jsi_publisher(self):
        pub = MagicMock()
        pub.publish_result = AsyncMock()
        return pub

    async def test_analyze_persists_job_on_start(
        self, mock_job_repo, mock_result_repo, mock_jsi_publisher
    ):
        from js_intelligence.application.commands import AnalyzeJSCommand

        with patch("js_intelligence.application.js_intelligence_service.TreeSitterJSParser"):
            with patch("js_intelligence.application.js_intelligence_service.httpx") as mock_httpx:
                mock_httpx.AsyncClient.return_value.__aenter__ = AsyncMock(
                    return_value=MagicMock(
                        get=AsyncMock(side_effect=Exception("network not available"))
                    )
                )
                mock_httpx.AsyncClient.return_value.__aexit__ = AsyncMock(return_value=None)

                from js_intelligence.application.js_intelligence_service import JSIntelligenceService

                svc = JSIntelligenceService(
                    job_repo=mock_job_repo,
                    result_repo=mock_result_repo,
                    event_publisher=mock_jsi_publisher,
                )

                cmd = AnalyzeJSCommand(
                    tenant_id=str(uuid.uuid4()),
                    target_url="https://example.com",
                    correlation_id="",
                    max_js_files=5,
                    fetch_source_maps=False,
                    timeout_seconds=30,
                )

                try:
                    await svc.analyze(cmd)
                except Exception:
                    pass  # network failures expected in unit test

                assert mock_job_repo.save.called


class TestCorrelationServiceAsync:
    """Tests for CorrelationService with all ports mocked."""

    @pytest.fixture
    def mock_correlation_repo(self):
        repo = MagicMock()
        repo.save_session = AsyncMock()
        repo.update_session = AsyncMock()
        repo.get_session = AsyncMock(return_value=None)
        repo.save_cluster = AsyncMock()
        repo.list_clusters = AsyncMock(return_value=[])
        return repo

    @pytest.fixture
    def mock_correlation_cache(self):
        cache = MagicMock()
        cache.get_clusters = AsyncMock(return_value=None)
        cache.set_clusters = AsyncMock()
        cache.get_ranked_paths = AsyncMock(return_value=None)
        cache.set_ranked_paths = AsyncMock()
        cache.get_prioritized = AsyncMock(return_value=None)
        cache.set_prioritized = AsyncMock()
        cache.get_remediation = AsyncMock(return_value=None)
        cache.set_remediation = AsyncMock()
        return cache

    @pytest.fixture
    def mock_correlation_publisher(self):
        pub = MagicMock()
        pub.publish_cluster_created = AsyncMock()
        pub.publish_paths_ranked = AsyncMock()
        pub.publish_exposure_prioritized = AsyncMock()
        pub.publish_remediation_generated = AsyncMock()
        return pub

    async def test_correlate_saves_session(
        self, mock_correlation_repo, mock_correlation_cache, mock_correlation_publisher
    ):
        from ai_correlation.application.commands import TriggerCorrelationCommand
        from ai_correlation.application.algorithms.evidence_clusterer import EvidenceClusterer
        from ai_correlation.application.algorithms.attack_path_ranker import AttackPathRanker
        from ai_correlation.application.algorithms.exposure_prioritizer import ExposurePrioritizer
        from ai_correlation.application.algorithms.remediation_generator import RemediationGenerator
        from ai_correlation.application.correlation_service import CorrelationService

        svc = CorrelationService(
            repo=mock_correlation_repo,
            cache=mock_correlation_cache,
            publisher=mock_correlation_publisher,
            clusterer=EvidenceClusterer(),
            ranker=AttackPathRanker(),
            prioritizer=ExposurePrioritizer(),
            remediator=RemediationGenerator(),
            llm_client=None,
        )

        tid = str(uuid.uuid4())
        sid = str(uuid.uuid4())
        cmd = TriggerCorrelationCommand(tenant_id=tid, session_id=sid)

        session = await svc.correlate(cmd)
        assert session is not None
        assert mock_correlation_repo.save_session.called

    async def test_correlate_with_empty_evidence_returns_session(
        self, mock_correlation_repo, mock_correlation_cache, mock_correlation_publisher
    ):
        from ai_correlation.application.commands import TriggerCorrelationCommand
        from ai_correlation.application.algorithms.evidence_clusterer import EvidenceClusterer
        from ai_correlation.application.algorithms.attack_path_ranker import AttackPathRanker
        from ai_correlation.application.algorithms.exposure_prioritizer import ExposurePrioritizer
        from ai_correlation.application.algorithms.remediation_generator import RemediationGenerator
        from ai_correlation.application.correlation_service import CorrelationService

        svc = CorrelationService(
            repo=mock_correlation_repo,
            cache=mock_correlation_cache,
            publisher=mock_correlation_publisher,
            clusterer=EvidenceClusterer(),
            ranker=AttackPathRanker(),
            prioritizer=ExposurePrioritizer(),
            remediator=RemediationGenerator(),
            llm_client=None,
        )

        tid = str(uuid.uuid4())
        cmd = TriggerCorrelationCommand(tenant_id=tid, session_id=str(uuid.uuid4()))
        session = await svc.correlate(cmd)
        assert session.tenant_id == tid
