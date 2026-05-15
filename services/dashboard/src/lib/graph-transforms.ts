/**
 * Transforms AGE API responses into @xyflow/react node/edge format
 * with auto-layout via dagre.
 */
import Dagre from "@dagrejs/dagre";
import type { Node, Edge } from "@xyflow/react";
import type { AGEAsset, AttackPath } from "@/types/api";

export type AssetNodeData = {
  label: string;
  host?: string;
  url?: string;
  asset_type: string;
  is_endpoint: boolean;
  risk_score?: number;
  [key: string]: unknown;
};

const NODE_W = 220;
const NODE_H = 60;

function applyDagreLayout(
  nodes: Node<AssetNodeData>[],
  edges: Edge[],
  direction: "LR" | "TB" = "LR"
): { nodes: Node<AssetNodeData>[]; edges: Edge[] } {
  if (nodes.length === 0) return { nodes, edges };

  const g = new Dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: direction, nodesep: 60, ranksep: 100 });

  nodes.forEach((n) => g.setNode(n.id, { width: NODE_W, height: NODE_H }));
  edges.forEach((e) => g.setEdge(e.source, e.target));

  Dagre.layout(g);

  return {
    nodes: nodes.map((n) => {
      const pos = g.node(n.id);
      return { ...n, position: { x: pos.x - NODE_W / 2, y: pos.y - NODE_H / 2 } };
    }),
    edges,
  };
}

export function transformToReactFlow(
  assets: AGEAsset[],
  attackPaths: AttackPath[]
): { nodes: Node<AssetNodeData>[]; edges: Edge[] } {
  const nodeMap = new Map<string, Node<AssetNodeData>>();

  assets.forEach((a) => {
    nodeMap.set(a.node_id, {
      id: a.node_id,
      type: "assetNode",
      position: { x: 0, y: 0 },
      data: {
        label: a.host ?? a.url ?? a.node_id.slice(0, 12),
        host: a.host,
        url: a.url,
        asset_type: a.asset_type ?? "asset",
        is_endpoint: false,
      },
    });
  });

  const edges: Edge[] = [];
  const seenEdges = new Set<string>();

  attackPaths.forEach((path) => {
    // Add path nodes not already in nodeMap
    path.nodes.forEach((pn) => {
      if (!nodeMap.has(pn.node_id)) {
        nodeMap.set(pn.node_id, {
          id: pn.node_id,
          type: "assetNode",
          position: { x: 0, y: 0 },
          data: {
            label: pn.host ?? pn.url ?? pn.label ?? pn.node_id.slice(0, 12),
            host: pn.host,
            url: pn.url,
            asset_type: pn.label?.toLowerCase().includes("endpoint") ? "endpoint" : "asset",
            is_endpoint: pn.label?.toLowerCase().includes("endpoint") ?? false,
            risk_score: path.risk_score,
          },
        });
      }
    });

    // Edges between consecutive path nodes
    for (let i = 0; i < path.nodes.length - 1; i++) {
      const src = path.nodes[i].node_id;
      const tgt = path.nodes[i + 1].node_id;
      const eid = `${src}→${tgt}`;
      if (!seenEdges.has(eid)) {
        seenEdges.add(eid);
        const isCritical = path.risk_score > 0.7;
        edges.push({
          id: eid,
          source: src,
          target: tgt,
          type: "smoothstep",
          animated: isCritical,
          style: {
            stroke: isCritical ? "#dc2626" : "#475569",
            strokeWidth: isCritical ? 2.5 : 1.5,
          },
        });
      }
    }
  });

  return applyDagreLayout(Array.from(nodeMap.values()), edges, "LR");
}
