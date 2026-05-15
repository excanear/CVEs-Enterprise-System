import { useQuery } from "@tanstack/react-query";
import { useTenant } from "@/app/providers";
import { reApi } from "@/lib/api-client";
import type { RemediationGuidance, ComplianceFinding } from "@/types/api";

export function useRemediation() {
  const { tenantId } = useTenant();

  const guidance = useQuery<RemediationGuidance[]>({
    queryKey: ["remediation-guidance", tenantId],
    queryFn: () => reApi.getRemediationGuidance(tenantId) as Promise<RemediationGuidance[]>,
    staleTime: 60_000,
  });

  const compliance = useQuery<ComplianceFinding[]>({
    queryKey: ["compliance-mapping", tenantId],
    queryFn: () => reApi.getComplianceMapping(tenantId) as Promise<ComplianceFinding[]>,
    staleTime: 60_000,
  });

  return {
    guidance: guidance.data ?? [],
    compliance: compliance.data ?? [],
    isLoading: guidance.isLoading || compliance.isLoading,
    isError: guidance.isError || compliance.isError,
  };
}
