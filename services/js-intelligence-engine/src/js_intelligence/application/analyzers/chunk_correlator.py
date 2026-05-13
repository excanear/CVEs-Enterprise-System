from __future__ import annotations

from js_intelligence.domain.value_objects.dependency_graph import DependencyGraph
from js_intelligence.domain.value_objects.hidden_route import HiddenRoute


class ChunkCorrelator:
    """Enriches HiddenRoute objects with lazy chunk IDs from the dependency graph."""

    def correlate(
        self,
        routes: list[HiddenRoute],
        graph: DependencyGraph,
        chunks: dict[str, list[str]],
    ) -> list[HiddenRoute]:
        """Enrich each route's ``lazy_chunks`` with chunk IDs that contain the
        route's component.

        Strategy:
        - If a route has a ``component_hint``, find graph nodes whose label
          contains the hint and collect their chunk_ids.
        - If no component_hint, try matching the route path against chunk names.

        Returns a new list of HiddenRoute (frozen — requires reconstruction).
        """
        if not routes:
            return routes

        # Build a label → chunk_ids index from the graph
        label_to_chunks: dict[str, list[str]] = {}
        for node in graph.nodes:
            if node.chunk_ids:
                label_lower = node.label.lower()
                label_to_chunks.setdefault(label_lower, []).extend(node.chunk_ids)

        enriched: list[HiddenRoute] = []
        for route in routes:
            lazy = set(route.lazy_chunks)

            if route.component_hint:
                hint_lower = route.component_hint.lower()
                for label, cids in label_to_chunks.items():
                    if hint_lower in label or label in hint_lower:
                        lazy.update(cids)

            # Also check direct chunk map (webpack/vite manifest)
            path_key = route.path.strip("/").lower()
            for chunk_id, filenames in chunks.items():
                for fn in filenames:
                    if path_key and path_key in fn.lower():
                        lazy.add(chunk_id)

            if lazy != set(route.lazy_chunks):
                enriched.append(
                    HiddenRoute(
                        path=route.path,
                        router_type=route.router_type,
                        component_hint=route.component_hint,
                        confidence=route.confidence,
                        discovered_in_chunk=route.discovered_in_chunk,
                        lazy_chunks=tuple(sorted(lazy)),
                    )
                )
            else:
                enriched.append(route)

        return enriched
