"""ExposureCandidate — normalized input for the validation pipeline."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cves_event_schemas.eve.eve_events import ExposureType


class ExposureCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    tenant_id: str
    target_url: str
    exposure_type: ExposureType
    signal_source: str
    endpoint_path: str = ""
    method: str = "GET"
    param_names: tuple[str, ...] = Field(default_factory=tuple)
    confidence_hint: float = Field(default=0.5, ge=0.0, le=1.0)
    raw_signals: tuple[dict[str, Any], ...] = Field(default_factory=tuple)

    @property
    def full_url(self) -> str:
        if self.endpoint_path and not self.endpoint_path.startswith("http"):
            base = self.target_url.rstrip("/")
            path = self.endpoint_path if self.endpoint_path.startswith("/") else f"/{self.endpoint_path}"
            return f"{base}{path}"
        return self.endpoint_path or self.target_url
