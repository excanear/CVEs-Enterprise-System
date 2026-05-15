// Tier color constants — used across all views
export const TIER_BG: Record<string, string> = {
  CRITICAL: "bg-red-600",
  HIGH: "bg-orange-600",
  MEDIUM: "bg-yellow-600",
  LOW: "bg-green-600",
};

export const TIER_TEXT: Record<string, string> = {
  CRITICAL: "text-red-400",
  HIGH: "text-orange-400",
  MEDIUM: "text-yellow-400",
  LOW: "text-green-400",
};

export const TIER_BORDER: Record<string, string> = {
  CRITICAL: "border-red-600",
  HIGH: "border-orange-600",
  MEDIUM: "border-yellow-500",
  LOW: "border-green-600",
};

export const TIER_HEX: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#ca8a04",
  LOW: "#16a34a",
};

export const TIER_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

export const STATUS_COLOR: Record<string, string> = {
  COMPLETED: "text-green-400",
  RUNNING: "text-blue-400",
  PENDING: "text-yellow-400",
  FAILED: "text-red-400",
  TRUE_POSITIVE: "text-red-400",
  FALSE_POSITIVE: "text-green-400",
  INCONCLUSIVE: "text-yellow-400",
};
