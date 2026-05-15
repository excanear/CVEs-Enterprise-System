import { useQueries } from "@tanstack/react-query";
import { useTenant } from "@/app/providers";
import { ageApi } from "@/lib/api-client";
import type { AGEAsset, AttackPath } from "@/types/api";

export function useAssetGraph() {
  const { tenantId } = useTenant();

  const results = useQueries({
    queries: [
      {
        queryKey: ["age-assets", tenantId],
        queryFn: () => ageApi.getAssets(tenantId, 150) as Promise<AGEAsset[]>,
        staleTime: 60_000,
      },
      {
        queryKey: ["age-attack-paths", tenantId],
        queryFn: () => ageApi.getAttackPaths(tenantId, 40) as Promise<AttackPath[]>,
        staleTime: 60_000,
      },
      {
        queryKey: ["age-stats", tenantId],
        queryFn: () => ageApi.getStats(tenantId) as Promise<Record<string, number>>,
        staleTime: 60_000,
      },
    ],
  });

  return {
    assets: results[0].data ?? [],
    attackPaths: results[1].data ?? [],
    stats: results[2].data ?? {},
    isLoading: results.some((r) => r.isLoading),
    isError: results.some((r) => r.isError),
  };
}
