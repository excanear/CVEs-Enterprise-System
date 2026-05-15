import { useQuery } from "@tanstack/react-query";
import { eveApi } from "@/lib/api-client";
import type { EvidenceBreakdown, ValidationJob } from "@/types/api";

export function useEvidenceDetail(jobId: string | null) {
  const evidence = useQuery<EvidenceBreakdown>({
    queryKey: ["evidence", jobId],
    queryFn: () => eveApi.getEvidence(jobId!) as Promise<EvidenceBreakdown>,
    enabled: !!jobId,
    staleTime: 60_000,
  });

  return {
    evidence: evidence.data ?? null,
    isLoading: evidence.isLoading,
    isError: evidence.isError,
  };
}

export function useValidationJobs(tenantId: string) {
  return useQuery<ValidationJob[]>({
    queryKey: ["validation-jobs", tenantId],
    queryFn: () => eveApi.listJobs(tenantId, 50) as Promise<ValidationJob[]>,
    staleTime: 20_000,
    refetchInterval: 30_000,
  });
}
