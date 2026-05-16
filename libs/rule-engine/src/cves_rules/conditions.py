"""Condition evaluator — pure deterministic logic, zero I/O.

Supports:
  - FieldCondition: field comparisons with 16 operators
  - ConditionGroup: all_of (AND), any_of (OR), none_of (NOR), not (NOT)
  - Dot-path field resolution: "finding.category", "asset.tags"
  - List membership, regex matching, type coercion
"""
from __future__ import annotations

import re
from typing import Any

from cves_rules.models import AnyCondition, ConditionGroup, ConditionOp, FieldCondition


# ─── Field resolution ────────────────────────────────────────────────────────

def _resolve(ctx: dict[str, Any], path: str) -> tuple[bool, Any]:
    """Resolve a dot-separated path from a context dict.

    Returns (exists: bool, value: Any).
    Supports nested dicts and objects with attributes.
    """
    parts = path.split(".")
    current: Any = ctx
    for part in parts:
        if isinstance(current, dict):
            if part not in current:
                return False, None
            current = current[part]
        elif hasattr(current, part):
            current = getattr(current, part)
        else:
            return False, None
    return True, current


def _coerce_numeric(value: Any) -> float:
    """Coerce value to float for numeric comparisons."""
    if isinstance(value, bool):
        return float(value)
    return float(value)


def _normalize_str(s: str, case_sensitive: bool) -> str:
    return s if case_sensitive else s.lower()


# ─── Single field condition ───────────────────────────────────────────────────

def _eval_field(cond: FieldCondition, ctx: dict[str, Any]) -> bool:
    exists, value = _resolve(ctx, cond.field)
    op = cond.op
    cv = cond.value  # comparison value from rule definition

    # Existence operators — don't need value
    if op == ConditionOp.EXISTS:
        return exists
    if op == ConditionOp.NOT_EXISTS:
        return not exists

    # Emptiness operators
    if op == ConditionOp.IS_EMPTY:
        if not exists or value is None:
            return True
        return len(value) == 0 if isinstance(value, (str, list, dict, set)) else False
    if op == ConditionOp.NOT_EMPTY:
        if not exists or value is None:
            return False
        return len(value) > 0 if isinstance(value, (str, list, dict, set)) else True

    if not exists:
        return False

    # Case normalization for string operators
    cs = cond.case_sensitive
    v = value
    c = cv

    # Equality
    if op == ConditionOp.EQ:
        if not cs and isinstance(v, str) and isinstance(c, str):
            return v.lower() == c.lower()
        # Try type coercion (e.g. YAML loads "true" as bool, ctx has True)
        if type(v) is not type(c):
            try:
                return v == type(v)(c)
            except (TypeError, ValueError):
                pass
        return v == c

    if op == ConditionOp.NE:
        if not cs and isinstance(v, str) and isinstance(c, str):
            return v.lower() != c.lower()
        if type(v) is not type(c):
            try:
                return v != type(v)(c)
            except (TypeError, ValueError):
                pass
        return v != c

    # Numeric comparisons
    if op == ConditionOp.GT:
        return _coerce_numeric(v) > _coerce_numeric(c)
    if op == ConditionOp.GTE:
        return _coerce_numeric(v) >= _coerce_numeric(c)
    if op == ConditionOp.LT:
        return _coerce_numeric(v) < _coerce_numeric(c)
    if op == ConditionOp.LTE:
        return _coerce_numeric(v) <= _coerce_numeric(c)

    # Membership
    if op == ConditionOp.IN:
        targets = c if isinstance(c, list) else [c]
        if not cs:
            targets = [t.lower() if isinstance(t, str) else t for t in targets]
            v_cmp = v.lower() if isinstance(v, str) else v
        else:
            v_cmp = v
        return v_cmp in targets

    if op == ConditionOp.NOT_IN:
        targets = c if isinstance(c, list) else [c]
        if not cs:
            targets = [t.lower() if isinstance(t, str) else t for t in targets]
            v_cmp = v.lower() if isinstance(v, str) else v
        else:
            v_cmp = v
        return v_cmp not in targets

    # Regex
    if op == ConditionOp.MATCHES:
        flags = 0 if cs else re.IGNORECASE
        return bool(re.search(str(c), str(v), flags))
    if op == ConditionOp.NOT_MATCHES:
        flags = 0 if cs else re.IGNORECASE
        return not bool(re.search(str(c), str(v), flags))

    # Contains
    if op == ConditionOp.CONTAINS:
        if isinstance(v, (list, set)):
            return c in v
        if not cs:
            return str(c).lower() in str(v).lower()
        return str(c) in str(v)
    if op == ConditionOp.NOT_CONTAINS:
        if isinstance(v, (list, set)):
            return c not in v
        if not cs:
            return str(c).lower() not in str(v).lower()
        return str(c) not in str(v)

    # String prefix/suffix
    if op == ConditionOp.STARTS_WITH:
        v_s, c_s = (str(v), str(c)) if cs else (str(v).lower(), str(c).lower())
        return v_s.startswith(c_s)
    if op == ConditionOp.ENDS_WITH:
        v_s, c_s = (str(v), str(c)) if cs else (str(v).lower(), str(c).lower())
        return v_s.endswith(c_s)

    raise ValueError(f"Unsupported operator: {op!r}")


# ─── Recursive group evaluator ───────────────────────────────────────────────

def evaluate(condition: AnyCondition, ctx: dict[str, Any]) -> bool:
    """Recursively evaluate a condition (FieldCondition or ConditionGroup) against ctx."""
    if isinstance(condition, FieldCondition):
        return _eval_field(condition, ctx)

    if isinstance(condition, ConditionGroup):
        group = condition
        if group.all_of is not None:
            return all(evaluate(c, ctx) for c in group.all_of)
        if group.any_of is not None:
            return any(evaluate(c, ctx) for c in group.any_of)
        if group.none_of is not None:
            return not any(evaluate(c, ctx) for c in group.none_of)
        if group.not_ is not None:
            return not evaluate(group.not_, ctx)
        raise ValueError("Empty ConditionGroup")

    raise TypeError(f"Unknown condition type: {type(condition)}")


def evaluate_safe(condition: AnyCondition, ctx: dict[str, Any]) -> bool:
    """evaluate() with error swallowed to False — use in production hot paths."""
    try:
        return evaluate(condition, ctx)
    except Exception:
        return False
