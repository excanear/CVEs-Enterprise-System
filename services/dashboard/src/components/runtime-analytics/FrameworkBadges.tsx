"use client";

import { useQuery } from "@tanstack/react-query";
import { raeApi } from "@/lib/api-client";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import type { AnalysisResult } from "@/types/api";

interface Props {
  sessionId: string | null;
}

export function FrameworkBadges({ sessionId }: Props) {
  const { data, isLoading } = useQuery<AnalysisResult>({
    queryKey: ["session-result", sessionId],
    queryFn: () => raeApi.getResult(sessionId!) as Promise<AnalysisResult>,
    enabled: !!sessionId,
    staleTime: 60_000,
  });

  if (!sessionId) return null;

  if (isLoading) {
    return (
      <div className="flex gap-2">
        <Skeleton className="h-6 w-20 rounded-full" />
        <Skeleton className="h-6 w-16 rounded-full" />
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        {data.frameworks.map((fw) => (
          <Badge key={fw.name} variant="secondary" className="text-xs gap-1.5">
            {fw.name}
            {fw.version && <span className="text-muted-foreground">v{fw.version}</span>}
            {fw.confidence != null && (
              <span className="text-primary">{(fw.confidence * 100).toFixed(0)}%</span>
            )}
          </Badge>
        ))}
        {data.frameworks.length === 0 && (
          <span className="text-xs text-muted-foreground">No frameworks detected</span>
        )}
      </div>
      <div className="grid grid-cols-3 gap-3 text-center text-xs">
        <div className="rounded-md border p-2">
          <p className="text-xl font-bold tabular-nums">{data.intercepted_apis_count}</p>
          <p className="text-muted-foreground">APIs</p>
        </div>
        <div className="rounded-md border p-2">
          <p className="text-xl font-bold tabular-nums">{data.websocket_endpoints_count}</p>
          <p className="text-muted-foreground">WebSockets</p>
        </div>
        <div className="rounded-md border p-2">
          <p className="text-xl font-bold tabular-nums">{data.spa_routes_count}</p>
          <p className="text-muted-foreground">SPA Routes</p>
        </div>
      </div>
    </div>
  );
}
