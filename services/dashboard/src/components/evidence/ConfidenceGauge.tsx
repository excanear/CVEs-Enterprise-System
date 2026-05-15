"use client";

import type { EvidenceBreakdown } from "@/types/api";

interface Props {
  evidence: EvidenceBreakdown | null;
  threshold?: number;
}

export function ConfidenceGauge({ evidence, threshold = 0.75 }: Props) {
  if (!evidence) return null;

  const score = evidence.inference_score_estimate;
  const pct = Math.round(score * 100);
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference * (1 - score);

  const color =
    score >= threshold
      ? "#dc2626"
      : score >= 0.5
      ? "#ea580c"
      : score >= 0.3
      ? "#ca8a04"
      : "#16a34a";

  const label =
    score >= threshold ? "TRUE POSITIVE" : score >= 0.5 ? "LIKELY" : score >= 0.3 ? "UNCERTAIN" : "FALSE POSITIVE";

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width="128" height="128" viewBox="0 0 128 128">
        {/* Track */}
        <circle
          cx="64"
          cy="64"
          r={radius}
          fill="none"
          stroke="hsl(217 19% 20%)"
          strokeWidth="10"
        />
        {/* Progress */}
        <circle
          cx="64"
          cy="64"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          transform="rotate(-90 64 64)"
          style={{ transition: "stroke-dashoffset 0.5s ease" }}
        />
        {/* Score text */}
        <text
          x="64"
          y="60"
          textAnchor="middle"
          fill="white"
          fontSize="22"
          fontWeight="700"
          fontFamily="monospace"
        >
          {pct}%
        </text>
        <text x="64" y="76" textAnchor="middle" fill={color} fontSize="8" fontWeight="600">
          {label}
        </text>
      </svg>

      <div className="text-center text-xs text-muted-foreground">
        <p>{evidence.correlation_count} correlated signals</p>
        {score >= threshold && (
          <p className="mt-0.5 font-semibold text-red-400">Exceeds {threshold * 100}% threshold</p>
        )}
      </div>
    </div>
  );
}
