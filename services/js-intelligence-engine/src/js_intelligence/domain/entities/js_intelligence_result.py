from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from cves_db.types import uuid7

from js_intelligence.domain.value_objects.bundler_signature import BundlerSignature
from js_intelligence.domain.value_objects.dependency_graph import DependencyGraph
from js_intelligence.domain.value_objects.hidden_route import HiddenRoute
from js_intelligence.domain.value_objects.js_bundle import JSBundle
from js_intelligence.domain.value_objects.source_map_entry import SourceMapEntry


@dataclass(frozen=True)
class JSIntelligenceResult:
    """Immutable result entity produced by a completed JSAnalysisJob."""

    result_id: str
    job_id: str
    bundles: tuple[JSBundle, ...]
    source_map_entries: tuple[SourceMapEntry, ...]
    hidden_routes: tuple[HiddenRoute, ...]
    dependency_graph: DependencyGraph
    bundler_signature: BundlerSignature
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def create(
        cls,
        job_id: str,
        bundles: list[JSBundle],
        source_map_entries: list[SourceMapEntry],
        hidden_routes: list[HiddenRoute],
        dependency_graph: DependencyGraph,
        bundler_signature: BundlerSignature,
    ) -> "JSIntelligenceResult":
        return cls(
            result_id=uuid7(),
            job_id=job_id,
            bundles=tuple(bundles),
            source_map_entries=tuple(source_map_entries),
            hidden_routes=tuple(hidden_routes),
            dependency_graph=dependency_graph,
            bundler_signature=bundler_signature,
        )
