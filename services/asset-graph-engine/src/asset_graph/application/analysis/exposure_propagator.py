"""Exposure Propagator.

Uses APOC `apoc.path.subgraphNodes` (with native Cypher fallback) to trace
how a confirmed exposure propagates transitively through CALLS and TRUSTS edges.
"""
from __future__ import annotations

import structlog

from asset_graph.application.commands import QueryPropagationCommand
from asset_graph.domain.ports import GraphEventPublisher, GraphRepository
from asset_graph.domain.value_objects.propagation_result import ExposurePropagation

log = structlog.get_logger(__name__)


class ExposurePropagator:
    def __init__(
        self,
        graph_repo: GraphRepository,
        event_publisher: GraphEventPublisher,
    ) -> None:
        self._graph = graph_repo
        self._publisher = event_publisher

    async def propagate(self, cmd: QueryPropagationCommand) -> list[ExposurePropagation]:
        results = await self._graph.find_exposure_propagation(
            tenant_id=cmd.tenant_id,
            max_depth=cmd.max_depth,
        )
        log.info(
            "age.propagation.computed",
            tenant_id=cmd.tenant_id,
            origin_count=len(results),
            total_affected=sum(r.affected_count for r in results),
        )
        for propagation in results:
            if propagation.affected_count > 0:
                try:
                    await self._publisher.publish_propagation(propagation)
                except Exception as exc:
                    log.warning("age.propagation.publish_failed", error=str(exc))
        return results
