"""ParserFindings — response body risk analysis."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ParserFindings(BaseModel):
    model_config = ConfigDict(frozen=True)

    content_type: str = ""
    has_reflected_input: bool = False
    reflected_in: str | None = None
    has_json_error_leak: bool = False
    has_stack_trace: bool = False
    has_debug_info: bool = False
    risk_indicators: tuple[str, ...] = Field(default_factory=tuple)

    @property
    def risk_score(self) -> float:
        """0–1 risk score derived from findings."""
        score = 0.0
        if self.has_stack_trace:
            score += 0.4
        if self.has_reflected_input:
            score += 0.3
        if self.has_json_error_leak:
            score += 0.2
        if self.has_debug_info:
            score += 0.1
        return min(score, 1.0)
