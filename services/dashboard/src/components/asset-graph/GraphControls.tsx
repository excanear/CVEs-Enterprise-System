"use client";

import { Button } from "@/components/ui/button";
import { LayoutGrid, Columns, Maximize } from "lucide-react";

interface Props {
  onRelayout: (dir: "LR" | "TB") => void;
  onFitView: () => void;
  nodeCount: number;
  edgeCount: number;
}

export function GraphControls({ onRelayout, onFitView, nodeCount, edgeCount }: Props) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-border bg-card px-4 py-2.5">
      <span className="text-xs text-muted-foreground">
        {nodeCount} nodes · {edgeCount} edges
      </span>

      <div className="ml-auto flex gap-2">
        <Button variant="outline" size="sm" onClick={() => onRelayout("LR")} title="Horizontal layout">
          <Columns className="h-4 w-4 mr-1" />
          Horizontal
        </Button>
        <Button variant="outline" size="sm" onClick={() => onRelayout("TB")} title="Vertical layout">
          <LayoutGrid className="h-4 w-4 mr-1" />
          Vertical
        </Button>
        <Button variant="outline" size="sm" onClick={onFitView} title="Fit to view">
          <Maximize className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
