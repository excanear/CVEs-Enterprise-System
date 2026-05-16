"""All Pydantic models for the CVEs Rule Engine.

Rule type hierarchy:
  BaseRule
  ├── DetectionPolicy   — pattern match → alerts / tags / incidents
  ├── RiskPolicy        — additive score modifiers → risk score
  ├── SuppressionRule   — mute matched findings
  ├── CorrelationRule   — temporal window grouping → incidents
  └── ValidationRule    — field-level validation (YAML-driven or class-based)

Condition language (recursive):
  AnyCondition = FieldCondition | ConditionGroup
  FieldCondition: { field, op, value, case_sensitive }
  ConditionGroup: { all_of | any_of | none_of | not }

Action types:
  alert | tag | score | suppress | create_incident | webhook | log
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, Tag, Discriminator, model_validator


# ─── Enums ───────────────────────────────────────────────────────────────────

class RuleType(StrEnum):
    DETECTION = "detection"
    RISK = "risk"
    SUPPRESSION = "suppression"
    CORRELATION = "correlation"
    VALIDATION = "validation"


class Priority(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ConditionOp(StrEnum):
    # Equality
    EQ = "eq"
    NE = "ne"
    # Numeric comparison
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    # Membership
    IN = "in"
    NOT_IN = "not_in"
    # Regex
    MATCHES = "matches"
    NOT_MATCHES = "not_matches"
    # String / list contains
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    # Null / emptiness
    IS_EMPTY = "is_empty"
    NOT_EMPTY = "not_empty"
    # Field existence
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class ActionType(StrEnum):
    ALERT = "alert"
    TAG = "tag"
    SCORE = "score"
    SUPPRESS = "suppress"
    CREATE_INCIDENT = "create_incident"
    WEBHOOK = "webhook"
    LOG = "log"


class FieldType(StrEnum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    URL = "url"
    EMAIL = "email"
    UUID = "uuid"
    IP = "ip"
    CIDR = "cidr"
    ENUM = "enum"
    LIST = "list"
    DICT = "dict"


# ─── Condition models (recursive) ────────────────────────────────────────────

class FieldCondition(BaseModel):
    """A single field comparison."""
    field: str
    op: ConditionOp
    value: Any = None  # Optional for EXISTS / NOT_EXISTS / IS_EMPTY / NOT_EMPTY
    case_sensitive: bool = True


def _condition_discriminator(v: Any) -> str:
    if isinstance(v, dict):
        return "field" if ("field" in v and "op" in v) else "group"
    if isinstance(v, FieldCondition):
        return "field"
    return "group"


# Forward reference — rebuilt after ConditionGroup is defined
AnyCondition = Any  # placeholder


class ConditionGroup(BaseModel):
    """Boolean combination of conditions."""

    model_config = ConfigDict(populate_by_name=True)

    all_of: list[Any] | None = None   # AND — type will be AnyCondition after rebuild
    any_of: list[Any] | None = None   # OR
    none_of: list[Any] | None = None  # NOR
    not_: Any | None = Field(None, alias="not")  # single NOT

    @model_validator(mode="before")
    @classmethod
    def _require_one_key(cls, data: Any) -> Any:
        if isinstance(data, dict):
            valid = {"all_of", "any_of", "none_of", "not"}
            if not set(data.keys()).intersection(valid):
                raise ValueError(f"ConditionGroup must contain one of: {valid}")
        return data


# Build the real discriminated union now that both classes exist
AnyCondition = Annotated[
    Union[
        Annotated[FieldCondition, Tag("field")],
        Annotated[ConditionGroup, Tag("group")],
    ],
    Discriminator(_condition_discriminator),
]

# Rebuild so recursive references resolve
ConditionGroup.model_rebuild()


# ─── Action models ────────────────────────────────────────────────────────────

class AlertAction(BaseModel):
    type: Literal[ActionType.ALERT] = ActionType.ALERT
    severity: Priority = Priority.HIGH
    channel: str | None = None
    message: str | None = None


class TagAction(BaseModel):
    type: Literal[ActionType.TAG] = ActionType.TAG
    tags: list[str]


class ScoreAction(BaseModel):
    type: Literal[ActionType.SCORE] = ActionType.SCORE
    modifier: float


class SuppressAction(BaseModel):
    type: Literal[ActionType.SUPPRESS] = ActionType.SUPPRESS
    reason: str = ""


class CreateIncidentAction(BaseModel):
    type: Literal[ActionType.CREATE_INCIDENT] = ActionType.CREATE_INCIDENT
    severity: Priority = Priority.HIGH
    title: str
    description: str | None = None


class WebhookAction(BaseModel):
    type: Literal[ActionType.WEBHOOK] = ActionType.WEBHOOK
    url: str
    method: str = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    body_template: str | None = None


class LogAction(BaseModel):
    type: Literal[ActionType.LOG] = ActionType.LOG
    level: str = "info"
    message: str = ""


def _action_discriminator(v: Any) -> str:
    if isinstance(v, dict):
        return v.get("type", "log")
    if hasattr(v, "type"):
        return str(v.type)
    return "log"


AnyAction = Annotated[
    Union[
        Annotated[AlertAction, Tag("alert")],
        Annotated[TagAction, Tag("tag")],
        Annotated[ScoreAction, Tag("score")],
        Annotated[SuppressAction, Tag("suppress")],
        Annotated[CreateIncidentAction, Tag("create_incident")],
        Annotated[WebhookAction, Tag("webhook")],
        Annotated[LogAction, Tag("log")],
    ],
    Discriminator(_action_discriminator),
]


# ─── Base rule ────────────────────────────────────────────────────────────────

class BaseRule(BaseModel):
    """Common fields shared by all rule types."""
    id: str
    type: RuleType
    name: str
    description: str = ""
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None


# ─── Detection policy ─────────────────────────────────────────────────────────

class DetectionPolicy(BaseRule):
    """Fire actions when conditions match a finding/asset context."""
    type: Literal[RuleType.DETECTION] = RuleType.DETECTION
    priority: Priority = Priority.MEDIUM
    conditions: AnyCondition
    actions: list[AnyAction] = Field(default_factory=list)
    ttl_seconds: int | None = None  # cooldown: rule won't re-fire within this window


# ─── Risk policy ──────────────────────────────────────────────────────────────

class RiskScoreModifier(BaseModel):
    """A single conditional score modifier within a risk policy."""
    name: str
    conditions: AnyCondition
    score_modifier: float  # positive = increase risk; negative = decrease


class RiskPolicy(BaseRule):
    """Additive risk scoring — evaluates all matching modifiers and sums them."""
    type: Literal[RuleType.RISK] = RuleType.RISK
    base_score: float = 0.0
    rules: list[RiskScoreModifier]
    clamp: tuple[float, float] = (0.0, 10.0)  # [min, max]
    actions: list[AnyAction] = Field(default_factory=list)  # fired after scoring


# ─── Suppression rule ─────────────────────────────────────────────────────────

class SuppressionRule(BaseRule):
    """Suppress (mute) findings that match conditions."""
    type: Literal[RuleType.SUPPRESSION] = RuleType.SUPPRESSION
    reason: str
    conditions: AnyCondition
    expires_at: datetime | None = None  # None = never expires


# ─── Correlation rule ─────────────────────────────────────────────────────────

class CorrelationRule(BaseRule):
    """Group events within a time window and fire when threshold is reached."""
    type: Literal[RuleType.CORRELATION] = RuleType.CORRELATION
    window_seconds: int = 3600
    group_by: list[str] = Field(default_factory=list)  # field paths to group on
    min_events: int = 2
    unique_on: str | None = None  # count unique values of this field (not raw events)
    conditions: AnyCondition | None = None  # optional per-event filter
    actions: list[AnyAction] = Field(default_factory=list)


# ─── Validation rule ──────────────────────────────────────────────────────────

class FieldValidation(BaseModel):
    """Schema for a single field in a validation rule."""
    name: str
    required: bool = True
    type: FieldType = FieldType.STRING
    min_length: int | None = None
    max_length: int | None = None
    min_value: float | None = None
    max_value: float | None = None
    pattern: str | None = None    # regex
    enum: list[Any] | None = None  # allowed values
    description: str = ""


class ValidationRule(BaseRule):
    """YAML-driven field validation, optionally backed by a custom validator class."""
    type: Literal[RuleType.VALIDATION] = RuleType.VALIDATION
    validator_class: str | None = None  # importable dotted path to a BaseValidator subclass
    fields: list[FieldValidation] = Field(default_factory=list)
    conditions: AnyCondition | None = None  # extra conditions evaluated after field checks


# ─── Discriminated union of all rule types ────────────────────────────────────

def _rule_type_discriminator(v: Any) -> str:
    if isinstance(v, dict):
        return v.get("type", "detection")
    if hasattr(v, "type"):
        return str(v.type)
    return "detection"


AnyRule = Annotated[
    Union[
        Annotated[DetectionPolicy, Tag("detection")],
        Annotated[RiskPolicy, Tag("risk")],
        Annotated[SuppressionRule, Tag("suppression")],
        Annotated[CorrelationRule, Tag("correlation")],
        Annotated[ValidationRule, Tag("validation")],
    ],
    Discriminator(_rule_type_discriminator),
]
