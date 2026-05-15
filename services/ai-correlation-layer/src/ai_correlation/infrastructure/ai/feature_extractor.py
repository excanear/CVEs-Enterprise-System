"""Evidence Feature Extractor — converts EvidenceItem list to numpy feature matrix.

Features per item (all normalized to [0, 1]):
  [0..7]  exposure_type one-hot (8 ExposureType values)
  [8]     confidence (float 0–1, already normalized)
  [9]     poc_triggered (0.0 or 1.0)
  [10]    propagation_depth_norm (depth / MAX_DEPTH)
  [11]    hop_count_norm (1 / max(hops, 1), so fewer hops = higher score)

The host column is NOT a feature — it's used post-clustering for labeling only.
"""
from __future__ import annotations

import numpy as np

from ai_correlation.domain.entities.evidence_cluster import EvidenceItem

# Must match ExposureType enum order in eve_events
_EXPOSURE_TYPES = [
    "MISSING_AUTH",
    "EXPOSED_API",
    "CORS_MISCONFIGURATION",
    "SECURITY_HEADER_MISSING",
    "PATH_TRAVERSAL",
    "INJECTION_SURFACE",
    "EXPOSED_ROUTE",
    "WEBSOCKET_UNPROTECTED",
]
_N_EXPOSURE_TYPES = len(_EXPOSURE_TYPES)
_EXPOSURE_TYPE_INDEX: dict[str, int] = {t: i for i, t in enumerate(_EXPOSURE_TYPES)}

_MAX_PROPAGATION_DEPTH = 10.0
_MAX_HOP_COUNT = 8.0

FEATURE_DIM = _N_EXPOSURE_TYPES + 4  # 8 one-hot + confidence + poc + prop_depth + hops


def build_feature_matrix(items: list[EvidenceItem]) -> np.ndarray:
    """Return a float32 matrix of shape (n_items, FEATURE_DIM).

    Each row is the feature vector for one EvidenceItem.
    """
    n = len(items)
    matrix = np.zeros((n, FEATURE_DIM), dtype=np.float32)

    for i, item in enumerate(items):
        # One-hot for exposure type
        type_idx = _EXPOSURE_TYPE_INDEX.get(item.exposure_type, -1)
        if type_idx >= 0:
            matrix[i, type_idx] = 1.0

        # Continuous features
        matrix[i, _N_EXPOSURE_TYPES]     = float(item.confidence)
        matrix[i, _N_EXPOSURE_TYPES + 1] = 1.0 if item.poc_triggered else 0.0
        matrix[i, _N_EXPOSURE_TYPES + 2] = min(item.propagation_depth, _MAX_PROPAGATION_DEPTH) / _MAX_PROPAGATION_DEPTH
        matrix[i, _N_EXPOSURE_TYPES + 3] = 1.0 / max(float(item.hop_count), 1.0) / _MAX_HOP_COUNT

    return matrix
