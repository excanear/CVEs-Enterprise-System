"""Trust Chain Analyzer.

Queries TRUSTS*1..max_depth paths from a given Asset node.
Models OAuth delegation, CORS trust, and JWT issuer relationships.
"""
from __future__ import annotations

import structlog

from asset_graph.application.commands import QueryTrustChainsCommand
from asset_graph.domain.ports import GraphRepository
from asset_graph.domain.value_objects.trust_chain import TrustChain

log = structlog.get_logger(__name__)


class TrustChainAnalyzer:
    def __init__(self, graph_repo: GraphRepository) -> None:
        self._graph = graph_repo

    async def analyze(self, cmd: QueryTrustChainsCommand) -> list[TrustChain]:
        chains = await self._graph.find_trust_chains(
            tenant_id=cmd.tenant_id,
            asset_id=cmd.asset_id,
            max_depth=cmd.max_depth,
        )
        log.info(
            "age.trust_chains.found",
            tenant_id=cmd.tenant_id,
            asset_id=cmd.asset_id,
            count=len(chains),
        )
        return chains
