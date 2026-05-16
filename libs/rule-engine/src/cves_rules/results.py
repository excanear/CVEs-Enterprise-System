"""Result types returned by RuleEngine evaluation methods."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cves_rules.models import AnyAction, DetectionPolicy, CorrelationRule, Priority, RuleType


@dataclass
class RuleMatch:
    """A single detection or suppression rule that matched."""
    rule_id: str
    rule_name: str
    rule_type: RuleType
    priority: Priority
    actions: list[AnyAction]
    matched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskEvaluation:
    """Aggregate result of all risk policies evaluated against a context."""
    final_score: float
    clamped_score: float
    base_score: float
    applied_modifiers: list[dict[str, Any]]  # [{name, modifier, policy_id}]
    policies_evaluated: int
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def tier(self) -> str:
        s = self.clamped_score
        if s >= 9.0:
            return "CRITICAL"
        if s >= 7.0:
            return "HIGH"
        if s >= 4.0:
            return "MEDIUM"
        if s >= 1.0:
            return "LOW"
        return "INFO"


@dataclass
class SuppressionDecision:
    """Whether the evaluated context is suppressed and why."""
    suppressed: bool
    rule_id: str | None = None
    rule_name: str | None = None
    reason: str | None = None
    expires_at: datetime | None = None


@dataclass
class CorrelationMatch:
    """A correlation rule that fired over a window of events."""
    rule_id: str
    rule_name: str
    group_key: dict[str, Any]   # the group_by field values
    event_count: int
    unique_count: int | None
    actions: list[AnyAction]
    matched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class FieldError:
    """A single field validation error."""
    field: str
    message: str
    value: Any = None


@dataclass
class ValidationResult:
    """Result of running a ValidationRule against a data payload."""
    valid: bool
    rule_id: str
    errors: list[FieldError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    validated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add_error(self, field_name: str, message: str, value: Any = None) -> None:
        self.errors.append(FieldError(field=field_name, message=message, value=value))
        self.valid = False


@dataclass
class EvaluationReport:
    """Full engine evaluation report — all rule types in one pass."""
    detection_matches: list[RuleMatch]
    suppressed: bool
    suppression_rule: SuppressionDecision | None
    risk: RiskEvaluation | None
    correlation_matches: list[CorrelationMatch]
    validation_errors: list[FieldError]
    tenant_id: str | None
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def should_alert(self) -> bool:
        return bool(self.detection_matches) and not self.suppressed

    @property
    def risk_tier(self) -> str | None:
        return self.risk.tier if self.risk else None
