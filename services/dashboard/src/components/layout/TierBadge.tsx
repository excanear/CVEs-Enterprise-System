import { Badge } from "@/components/ui/badge";
import { TIER_HEX } from "@/lib/tier-colors";
import { cn } from "@/lib/utils";

interface TierBadgeProps {
  tier: string;
  className?: string;
}

const VARIANT_MAP: Record<string, "critical" | "high" | "medium" | "low"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
};

export function TierBadge({ tier, className }: TierBadgeProps) {
  const variant = VARIANT_MAP[tier] ?? "outline";
  return (
    <Badge variant={variant} className={cn("font-mono text-xs", className)}>
      {tier}
    </Badge>
  );
}

// Inline dot indicator for use in tables
export function TierDot({ tier }: { tier: string }) {
  return (
    <span
      className="inline-block h-2 w-2 rounded-full flex-shrink-0"
      style={{ backgroundColor: TIER_HEX[tier] ?? "#6b7280" }}
    />
  );
}
