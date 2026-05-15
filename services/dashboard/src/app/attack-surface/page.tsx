"use client";

import { useRiskSummary } from "@/hooks/useRiskSummary";
import { useExposures } from "@/hooks/useExposures";
import { AttackSurfaceKPIs } from "@/components/attack-surface/AttackSurfaceKPIs";
import { ExposureTable } from "@/components/attack-surface/ExposureTable";
import { ExposureTrendChart } from "@/components/attack-surface/ExposureTrendChart";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";

export default function AttackSurfacePage() {
  const { data: riskSummary, isLoading: riskLoading } = useRiskSummary();
  const { exposures, isLoading: expLoading } = useExposures();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Attack Surface</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Real-time exposure overview across all discovered endpoints
        </p>
      </div>

      <AttackSurfaceKPIs data={riskSummary} isLoading={riskLoading} />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Exposure Distribution by Type</CardTitle>
          </CardHeader>
          <CardContent>
            <ExposureTrendChart exposures={exposures} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Summary</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Total Clusters</span>
              <span className="font-semibold tabular-nums">
                {riskSummary?.total_clusters ?? "—"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Total Exposures</span>
              <span className="font-semibold tabular-nums">
                {riskSummary?.total_exposures ?? "—"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Avg Confidence</span>
              <span className="font-semibold tabular-nums">
                {riskSummary
                  ? `${(riskSummary.avg_confidence * 100).toFixed(1)}%`
                  : "—"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Last Updated</span>
              <span className="text-xs text-muted-foreground">
                {riskSummary
                  ? new Date(riskSummary.generated_at).toLocaleTimeString()
                  : "—"}
              </span>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Prioritized Exposures</CardTitle>
        </CardHeader>
        <CardContent>
          <ExposureTable exposures={exposures} isLoading={expLoading} />
        </CardContent>
      </Card>
    </div>
  );
}
