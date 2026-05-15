"use client";

import { useExposures } from "@/hooks/useExposures";
import { useRemediation } from "@/hooks/useRemediation";
import { ClusterView } from "@/components/exposure/ClusterView";
import { PrioritizedList } from "@/components/exposure/PrioritizedList";
import { ComplianceMatrix } from "@/components/exposure/ComplianceMatrix";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function ExposurePage() {
  const { clusters, exposures, isLoading: expLoading } = useExposures();
  const { compliance, isLoading: compLoading } = useRemediation();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Exposure Prioritization</h1>
        <p className="text-sm text-muted-foreground mt-1">
          AI-ranked clusters, composite scores, and compliance mapping
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            Correlation Clusters
            <span className="ml-2 text-sm font-normal text-muted-foreground">
              ({clusters.length})
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ClusterView clusters={clusters} isLoading={expLoading} />
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Prioritized Exposures</CardTitle>
          </CardHeader>
          <CardContent>
            <PrioritizedList exposures={exposures} isLoading={expLoading} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Compliance Coverage Matrix</CardTitle>
          </CardHeader>
          <CardContent>
            <ComplianceMatrix findings={compliance} isLoading={compLoading} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
