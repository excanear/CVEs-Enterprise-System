"use client";

import { TierBadge } from "@/components/layout/TierBadge";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { TIER_HEX } from "@/lib/tier-colors";
import type { Cluster } from "@/types/api";

interface Props {
  clusters: Cluster[];
  isLoading: boolean;
}

export function ClusterView({ clusters, isLoading }: Props) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-36 rounded-lg" />
        ))}
      </div>
    );
  }

  if (clusters.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center text-sm text-muted-foreground">
        No clusters yet
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-4">
      {clusters.map((c) => (
        <Card
          key={c.cluster_id}
          className="border-l-4 transition-shadow hover:shadow-md"
          style={{ borderLeftColor: TIER_HEX[c.tier] }}
        >
          <CardContent className="p-4 space-y-2">
            <div className="flex items-center justify-between">
              <TierBadge tier={c.tier} />
              <span className="text-xs text-muted-foreground tabular-nums">
                {c.size} signals
              </span>
            </div>

            <p className="text-xs font-mono truncate text-foreground" title={c.host ?? c.cluster_id}>
              {c.host ?? c.cluster_id.slice(0, 20)}
            </p>

            <div className="flex flex-wrap gap-1">
              {c.exposure_types.slice(0, 2).map((t) => (
                <span key={t} className="rounded-sm bg-muted px-1.5 py-0.5 text-[9px] text-muted-foreground">
                  {t.replace(/_/g, " ")}
                </span>
              ))}
              {c.exposure_types.length > 2 && (
                <span className="text-[9px] text-muted-foreground self-center">
                  +{c.exposure_types.length - 2}
                </span>
              )}
            </div>

            <div className="flex justify-between text-xs text-muted-foreground">
              <span>Conf: {(c.avg_confidence * 100).toFixed(0)}%</span>
              <span className="text-red-400 font-medium">
                {c.poc_triggered_count > 0 ? `${c.poc_triggered_count} PoC` : ""}
              </span>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
