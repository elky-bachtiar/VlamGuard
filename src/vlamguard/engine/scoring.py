"""Risk scoring and gating logic."""

from dataclasses import dataclass

from vlamguard.engine.environment import CheckBehavior, get_check_behavior
from vlamguard.models.response import PolicyCheckResult, RiskLevel


@dataclass
class RiskResult:
    """Computed risk assessment."""

    score: int
    level: RiskLevel
    blocked: bool
    hard_blocks: list[str]


def calculate_risk(checks: list[PolicyCheckResult], environment: str) -> RiskResult:
    """Calculate risk score from policy check results and environment."""
    hard_blocks: list[str] = []
    soft_score = 0

    for check in checks:
        if check.passed:
            continue

        behavior = get_check_behavior(check.check_id, environment)

        if behavior == CheckBehavior.HARD_BLOCK:
            hard_blocks.append(f"{check.name}: {check.message}")
        elif behavior == CheckBehavior.SOFT_RISK:
            from vlamguard.engine.registry import get_risk_points

            risk_points = get_risk_points()
            soft_score += risk_points.get(check.check_id, 10)

    if hard_blocks:
        return RiskResult(
            score=100,
            level=RiskLevel.CRITICAL,
            blocked=True,
            hard_blocks=hard_blocks,
        )

    score = min(soft_score, 100)
    level = _score_to_level(score)

    return RiskResult(
        score=score,
        level=level,
        blocked=score > 60,
        hard_blocks=[],
    )


def _score_to_level(score: int) -> RiskLevel:
    """Map a numeric score to a RiskLevel bucket."""
    if score <= 30:
        return RiskLevel.LOW
    if score <= 60:
        return RiskLevel.MEDIUM
    return RiskLevel.HIGH
