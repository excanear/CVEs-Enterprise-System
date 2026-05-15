import { useQuery } from "@tanstack/react-query";
import { useTenant } from "@/app/providers";
import { aclApi } from "@/lib/api-client";
import type { Cluster, ExposurePrioritized } from "@/types/api";

export function useExposures() {
  const { tenantId } = useTenant();

  const clusters = useQuery<Cluster[]>({
    queryKey: ["clusters", tenantId],
    queryFn: () => aclApi.getClusters(tenantId) as Promise<Cluster[]>,
    staleTime: 25_000,
    refetchInterval: 30_000,
  });

  const exposures = useQuery<ExposurePrioritized[]>({
    queryKey: ["exposures-prioritized", tenantId],
    queryFn: () => aclApi.getExposures(tenantId) as Promise<ExposurePrioritized[]>,
    staleTime: 25_000,
    refetchInterval: 30_000,
  });

  return {
    clusters: clusters.data ?? [],
    exposures: exposures.data ?? [],
    isLoading: clusters.isLoading || exposures.isLoading,
    isError: clusters.isError || exposures.isError,
  };
}
