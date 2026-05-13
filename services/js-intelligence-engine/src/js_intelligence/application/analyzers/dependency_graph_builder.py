from __future__ import annotations

import asyncio
import logging

import networkx as nx

from js_intelligence.application.analyzers.webpack_analyzer import WebpackManifest
from js_intelligence.domain.value_objects.dependency_graph import (
    DependencyGraph,
    DependencyNode,
)
from js_intelligence.infrastructure.ast.tree_sitter_parser import ParseResult

log = logging.getLogger(__name__)

_MAX_NODES = 5000  # guard against pathological bundles


class DependencyGraphBuilder:
    """Builds a module dependency graph from AST parse results."""

    async def build(
        self,
        parse_results: list[ParseResult],
        webpack_manifest: WebpackManifest | None,
    ) -> DependencyGraph:
        """Build the dependency graph.

        CPU-bound networkx operations are run in a thread pool.
        """
        return await asyncio.to_thread(
            self._build_sync, parse_results, webpack_manifest
        )

    def _build_sync(
        self,
        parse_results: list[ParseResult],
        webpack_manifest: WebpackManifest | None,
    ) -> DependencyGraph:
        g: nx.DiGraph = nx.DiGraph()

        # Build node set from parse results
        for pr in parse_results:
            source_node = _url_to_node_id(pr.source_url)
            _ensure_node(g, source_node, pr.source_url)

            for dep in pr.import_paths + pr.require_paths + pr.dynamic_import_paths:
                if dep.startswith(".") or dep.startswith("/"):
                    dep_id = dep
                else:
                    dep_id = dep  # external package name

                if dep_id and dep_id != source_node:
                    _ensure_node(g, dep_id, dep_id)
                    if g.number_of_nodes() < _MAX_NODES:
                        g.add_edge(source_node, dep_id)

        # Supplement with webpack module IDs if available
        if webpack_manifest:
            for mod_id, label in webpack_manifest.modules.items():
                _ensure_node(g, mod_id, label)

        # SCC — detect cycles
        cycle_nodes: set[str] = set()
        for scc in nx.strongly_connected_components(g):
            if len(scc) > 1:  # a cycle requires at least 2 nodes in an SCC
                cycle_nodes.update(scc)

        # Entry points: nodes with in-degree == 0
        entry_point_ids = {n for n in g.nodes() if g.in_degree(n) == 0}

        # Build chunk_ids map from webpack manifest
        node_chunks: dict[str, list[str]] = {}
        if webpack_manifest:
            for chunk_id, filenames in webpack_manifest.chunks.items():
                for fn in filenames:
                    node_chunks.setdefault(fn, []).append(chunk_id)

        nodes = [
            DependencyNode(
                node_id=n,
                label=g.nodes[n].get("label", n),
                chunk_ids=tuple(node_chunks.get(n, [])),
                is_entry_point=n in entry_point_ids,
            )
            for n in g.nodes()
        ]

        edges = tuple(g.edges())

        return DependencyGraph(
            nodes=tuple(nodes),
            edges=edges,
            cycle_node_ids=tuple(cycle_nodes),
        )


def _url_to_node_id(url: str) -> str:
    """Convert a bundle URL to a stable node identifier."""
    return url.rsplit("/", 1)[-1].split("?")[0] if "/" in url else url


def _ensure_node(g: nx.DiGraph, node_id: str, label: str) -> None:
    if node_id not in g:
        g.add_node(node_id, label=label)
