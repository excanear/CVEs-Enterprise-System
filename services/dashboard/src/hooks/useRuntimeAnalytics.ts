import { useQuery } from "@tanstack/react-query";
import { useTenant } from "@/app/providers";
import { raeApi, jsiApi } from "@/lib/api-client";
import type { AnalysisSession, JSJob } from "@/types/api";

export function useRuntimeAnalytics() {
  const { tenantId } = useTenant();

  const raeSessions = useQuery<AnalysisSession[]>({
    queryKey: ["rae-sessions", tenantId],
    queryFn: () => raeApi.listSessions(tenantId, 20) as Promise<AnalysisSession[]>,
    staleTime: 20_000,
    refetchInterval: 30_000,
  });

  const jsiJobs = useQuery<JSJob[]>({
    queryKey: ["jsi-jobs", tenantId],
    queryFn: () => jsiApi.listJobs(tenantId, 30) as Promise<JSJob[]>,
    staleTime: 20_000,
    refetchInterval: 30_000,
  });

  return {
    sessions: raeSessions.data ?? [],
    jsiJobs: jsiJobs.data ?? [],
    isLoading: raeSessions.isLoading || jsiJobs.isLoading,
    isError: raeSessions.isError || jsiJobs.isError,
  };
}
