from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class DependencyNode(BaseModel):
    """A single node in the JS dependency graph."""

    model_config = ConfigDict(frozen=True)

    node_id: str  # module ID or path
    label: str  # human-readable name
    chunk_ids: tuple[str, ...] = ()
    is_entry_point: bool = False


class DependencyGraph(BaseModel):
    """Immutable dependency graph produced by DependencyGraphBuilder."""

    model_config = ConfigDict(frozen=True)

    nodes: tuple[DependencyNode, ...] = Field(default=())
    # edges: list of (source_node_id, target_node_id)
    edges: tuple[tuple[str, str], ...] = Field(default=())
    cycle_node_ids: tuple[str, ...] = Field(default=())

    @property
    def has_cycles(self) -> bool:
        return len(self.cycle_node_ids) > 0

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    @property
    def entry_points(self) -> list[str]:
        return [n.node_id for n in self.nodes if n.is_entry_point]
