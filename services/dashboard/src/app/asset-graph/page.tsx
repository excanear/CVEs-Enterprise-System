"use client";

import dynamic from "next/dynamic";
import { useAssetGraph } from "@/hooks/useAssetGraph";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

// SSR must be off — React Flow uses browser APIs
const AssetGraphCanvas = dynamic(
  () => import("@/components/asset-graph/AssetGraphCanvas").then((m) => m.AssetGraphCanvas),
  { ssr: false, loading: () => <Skeleton className="h-[600px] w-full rounded-lg" /> }
);

export default function AssetGraphPage() {
  const { assets, attackPaths, stats, isLoading } = useAssetGraph();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Asset Graph</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Interactive topology of assets, endpoints, and attack paths
        </p>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-3 gap-4 lg:grid-cols-6">
        {[
          ["Nodes", stats.node_count],
          ["Relationships", stats.relationship_count],
          ["Endpoints", stats.endpoint_count],
          ["Assets", stats.asset_count],
          ["Attack Paths", attackPaths.length],
          ["Loaded Assets", assets.length],
        ].map(([label, val]) => (
          <Card key={label}>
            <CardContent className="pt-4 pb-4 text-center">
              <p className="text-2xl font-bold tabular-nums">{val ?? "—"}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{label}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Topology</CardTitle>
        </CardHeader>
        <CardContent className="p-4">
          <AssetGraphCanvas
            assets={assets}
            attackPaths={attackPaths}
            isLoading={isLoading}
          />
        </CardContent>
      </Card>
    </div>
  );
}
