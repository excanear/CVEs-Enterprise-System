"""CSV renderer — stdlib only, no external deps."""
from __future__ import annotations

import csv
import io


def render_evidence_csv(exposures: list[dict]) -> str:
    """Render a flat CSV of all exposure records."""
    if not exposures:
        return "exposure_id,target_url,exposure_type,tier,composite_score,rationale,session_id,recorded_at\n"

    fieldnames = [
        "exposure_id", "target_url", "exposure_type", "tier",
        "composite_score", "rationale", "session_id", "recorded_at",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(exposures)
    return buf.getvalue()


def render_remediation_csv(remediations: list[dict]) -> str:
    """Render remediation records as CSV."""
    if not remediations:
        return "cluster_id,exposure_type,step_index,step,llm_enriched,llm_narrative\n"

    rows: list[dict] = []
    for r in remediations:
        for idx, step in enumerate(r.get("steps", []), start=1):
            rows.append(
                {
                    "cluster_id": r.get("cluster_id", ""),
                    "exposure_type": r.get("exposure_type", ""),
                    "step_index": idx,
                    "step": step,
                    "llm_enriched": r.get("llm_enriched", False),
                    "llm_narrative": r.get("llm_narrative", ""),
                }
            )

    fieldnames = ["cluster_id", "exposure_type", "step_index", "step", "llm_enriched", "llm_narrative"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()
