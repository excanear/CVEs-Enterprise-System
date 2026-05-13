"""Stage 2 — Inference: scores a candidate and filters low-confidence noise.

Scoring formula (weighted sum, capped at 0.95):
  signal_count_score  (30%) = min(len(raw_signals) / 5, 1.0)
  confidence_hint     (40%) = candidate.confidence_hint
  exposure_type_weight(30%) = per-type baseline weight
"""
from __future__ import annotations

import structlog

from cves_event_schemas.eve.eve_events import ExposureType

from exposure_validation.domain.value_objects.exposure_candidate import ExposureCandidate

log = structlog.get_logger(__name__)

_MIN_SCORE = 0.15  # discard anything below this

# Per-type baseline risk weight
_TYPE_WEIGHTS: dict[ExposureType, float] = {
    ExposureType.MISSING_AUTH: 0.90,
    ExposureType.CORS_MISCONFIGURATION: 0.80,
    ExposureType.INJECTION_SURFACE: 0.75,
    ExposureType.EXPOSED_API: 0.70,
    ExposureType.WEBSOCKET_UNPROTECTED: 0.65,
    ExposureType.SECURITY_HEADER_MISSING: 0.60,
    ExposureType.EXPOSED_ROUTE: 0.55,
    ExposureType.PATH_TRAVERSAL: 0.50,
}


class InferenceStage:
    @staticmethod
    def score(candidate: ExposureCandidate) -> float:
        """Return a 0–1 inference score, or -1 if below noise floor."""
        signal_count_score = min(len(candidate.raw_signals) / 5, 1.0)
        type_weight = _TYPE_WEIGHTS.get(candidate.exposure_type, 0.50)

        raw = (
            signal_count_score * 0.30
            + candidate.confidence_hint * 0.40
            + type_weight * 0.30
        )
        score = min(round(raw, 4), 0.95)

        if score < _MIN_SCORE:
            log.debug("eve.stage2.filtered", score=score, type=candidate.exposure_type.value)
            return -1.0

        return score
