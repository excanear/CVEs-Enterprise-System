import { useQuery } from "@tanstack/react-query";
import { useTenant } from "@/app/providers";
import { aclApi } from "@/lib/api-client";
import type { RiskSummary } from "@/types/api";

export function useRiskSummary() {
  const { tenantId } = useTenant();
  return useQuery<RiskSummary>({
    queryKey: ["risk-summary", tenantId],
    queryFn: () => aclApi.getRiskSummary(tenantId) as Promise<RiskSummary>,
    staleTime: 25_000,
    refetchInterval: 30_000,
  });
}
