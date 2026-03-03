"""Decorator-based policy registry — each check self-registers its metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from vlamguard.engine.environment import CheckBehavior
    from vlamguard.models.response import PolicyCheckResult

CheckFn = Callable[[dict], "PolicyCheckResult"]


@dataclass(frozen=True)
class PolicyMeta:
    """Metadata for a registered policy check."""

    check_id: str
    name: str
    severity: str
    category: str
    risk_points: int
    prod_behavior: str
    other_behavior: str
    fn: CheckFn


_REGISTRY: list[PolicyMeta] = []


def policy_check(
    *,
    check_id: str,
    name: str,
    severity: str,
    category: str,
    risk_points: int,
    prod_behavior: str,
    other_behavior: str,
) -> Callable[[CheckFn], CheckFn]:
    """Decorator that registers a policy check with its metadata."""

    def decorator(fn: CheckFn) -> CheckFn:
        _REGISTRY.append(
            PolicyMeta(
                check_id=check_id,
                name=name,
                severity=severity,
                category=category,
                risk_points=risk_points,
                prod_behavior=prod_behavior,
                other_behavior=other_behavior,
                fn=fn,
            )
        )
        return fn

    return decorator


def get_all_checks() -> list[PolicyMeta]:
    """Return all registered policy checks."""
    return list(_REGISTRY)


def get_check_fns() -> list[CheckFn]:
    """Return just the check functions (backward-compatible)."""
    return [meta.fn for meta in _REGISTRY]


def get_environment_matrix() -> dict[str, tuple[str, str]]:
    """Return {check_id: (prod_behavior, other_behavior)} from registry."""
    return {meta.check_id: (meta.prod_behavior, meta.other_behavior) for meta in _REGISTRY}


def get_risk_points() -> dict[str, int]:
    """Return {check_id: risk_points} from registry."""
    return {meta.check_id: meta.risk_points for meta in _REGISTRY}
