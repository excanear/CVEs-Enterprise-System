"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type ReactFlowInstance,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { AssetNode } from "./AssetNode";
import { GraphControls } from "./GraphControls";
import { transformToReactFlow } from "@/lib/graph-transforms";
import { Skeleton } from "@/components/ui/skeleton";
import type { AGEAsset, AttackPath } from "@/types/api";
import type { AssetNodeData } from "@/lib/graph-transforms";

const NODE_TYPES = { assetNode: AssetNode };

interface Props {
  assets: AGEAsset[];
  attackPaths: AttackPath[];
  isLoading: boolean;
}

export function AssetGraphCanvas({ assets, attackPaths, isLoading }: Props) {
  const rfRef = useRef<ReactFlowInstance<AssetNodeData> | null>(null);
  const [nodes, setNodes, onNodesChange] = useNodesState<AssetNodeData>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [direction, setDirection] = useState<"LR" | "TB">("LR");

  // Build React Flow nodes/edges whenever data or layout direction changes
  const { nodes: layoutedNodes, edges: layoutedEdges } = useMemo(
    () => transformToReactFlow(assets, attackPaths),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [assets, attackPaths, direction]
  );

  useEffect(() => {
    setNodes(layoutedNodes);
    setEdges(layoutedEdges);
  }, [layoutedNodes, layoutedEdges, setNodes, setEdges]);

  const handleFitView = useCallback(() => {
    rfRef.current?.fitView({ padding: 0.1 });
  }, []);

  const handleRelayout = useCallback(
    (dir: "LR" | "TB") => {
      setDirection(dir);
    },
    []
  );

  if (isLoading) {
    return <Skeleton className="h-[600px] w-full rounded-lg" />;
  }

  if (assets.length === 0 && attackPaths.length === 0) {
    return (
      <div className="flex h-[600px] items-center justify-center rounded-lg border border-dashed border-border text-sm text-muted-foreground">
        No asset graph data — run a scan to populate
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <GraphControls
        onRelayout={handleRelayout}
        onFitView={handleFitView}
        nodeCount={nodes.length}
        edgeCount={edges.length}
      />

      <div className="h-[600px] overflow-hidden rounded-lg border border-border">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={NODE_TYPES}
          onInit={(instance) => {
            rfRef.current = instance;
            instance.fitView({ padding: 0.1 });
          }}
          fitView
          proOptions={{ hideAttribution: true }}
        >
          <Background color="hsl(217 19% 18%)" gap={16} />
          <Controls
            style={{
              background: "hsl(222 47% 10%)",
              border: "1px solid hsl(217 19% 20%)",
              borderRadius: 6,
            }}
          />
          <MiniMap
            nodeColor={(n) => {
              const d = n.data as AssetNodeData;
              if (d.risk_score != null && d.risk_score > 0.7) return "#dc2626";
              if (d.is_endpoint) return "#3b82f6";
              return "#475569";
            }}
            style={{
              background: "hsl(222 47% 10%)",
              border: "1px solid hsl(217 19% 20%)",
            }}
          />
        </ReactFlow>
      </div>
    </div>
  );
}
