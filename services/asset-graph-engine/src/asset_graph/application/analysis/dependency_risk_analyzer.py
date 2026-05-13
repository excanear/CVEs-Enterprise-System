"""Dependency Risk Analyzer.

Queries DEPENDS_ON edges from Asset nodes and enriches results with any
HAS_CVE edges (created by the Findings Indexer when available).
Returns DependencyRisk value objects sorted by CVE presence and CVSS score.
"""
from __future__ import annotations

import structlog

from asset_graph.application.commands import QueryDependenciesCommand
from asset_graph.domain.ports import GraphRepository
from asset_graph.domain.value_objects.dependency_risk import DependencyRisk

log = structlog.get_logger(__name__)


class DependencyRiskAnalyzer:
    def __init__(self, graph_repo: GraphRepository) -> None:
        self._graph = graph_repo

    async def analyze(self, cmd: QueryDependenciesCommand) -> list[DependencyRisk]:
        risks = await self._graph.find_dependency_risks(tenant_id=cmd.tenant_id)

        # Sort: CVE-bearing first, then by max_cvss DESC
        risks.sort(
            key=lambda r: (
                not r.has_known_cves,
                -(r.max_cvss or 0.0),
                r.name,
            )
        )
        log.info(
            "age.dependency_risks.found",
            tenant_id=cmd.tenant_id,
            total=len(risks),
            with_cves=sum(1 for r in risks if r.has_known_cves),
        )
        return risks
