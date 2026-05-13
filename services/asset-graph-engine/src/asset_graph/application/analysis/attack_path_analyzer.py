"""Attack Path Analyzer.

Delegates to GraphRepository.find_attack_paths (allShortestPaths Cypher)
and optionally emits AttackPathDiscovered events for newly found paths.
"""
from __future__ import annotations

import structlog

from asset_graph.application.commands import QueryAttackPathsCommand
from asset_graph.domain.ports import GraphEventPublisher, GraphRepository
from asset_graph.domain.value_objects.attack_path import AttackPath

log = structlog.get_logger(__name__)


class AttackPathAnalyzer:
    def __init__(
        self,
        graph_repo: GraphRepository,
        event_publisher: GraphEventPublisher,
    ) -> None:
        self._graph = graph_repo
        self._publisher = event_publisher

    async def analyze(self, cmd: QueryAttackPathsCommand) -> list[AttackPath]:
        paths = await self._graph.find_attack_paths(
            tenant_id=cmd.tenant_id,
            max_paths=cmd.max_paths,
        )
        log.info(
            "age.attack_paths.found",
            tenant_id=cmd.tenant_id,
            count=len(paths),
        )
        for path in paths:
            try:
                await self._publisher.publish_attack_path(path, cmd.tenant_id)
            except Exception as exc:
                log.warning("age.attack_path.publish_failed", error=str(exc))
        return paths
