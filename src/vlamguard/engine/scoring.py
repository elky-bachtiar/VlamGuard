"""Risk scoring and gating logic."""

from __future__ import annotations

from dataclasses import dataclass

from vlamguard.engine.environment import CheckBehavior, get_check_behavior
from vlamguard.engine.secrets import HARD_PATTERNS
from vlamguard.models.response import PolicyCheckResult, RiskLevel, SecretsDetectionResult


@dataclass
class RiskResult:
    """Computed risk assessment."""

    score: int
    level: RiskLevel
    blocked: bool
    hard_blocks: list[str]


def calculate_risk(
    checks: list[PolicyCheckResult],
    environment: str,
    secrets_result: SecretsDetectionResult | None = None,
) -> RiskResult:
    """Calculate risk score from policy check results, environment, and secrets."""
    hard_blocks: list[str] = []
    soft_score = 0

    for check in checks:
        if check.passed:
            continue

        # Waived checks are downgraded: hard_block → soft_risk
        if getattr(check, "waived", False):
            from vlamguard.engine.registry import get_risk_points

            risk_points = get_risk_points()
            soft_score += risk_points.get(check.check_id, 10)
            continue

        behavior = get_check_behavior(check.check_id, environment)

        if behavior == CheckBehavior.HARD_BLOCK:
            hard_blocks.append(f"{check.name}: {check.message}")
        elif behavior == CheckBehavior.SOFT_RISK:
            from vlamguard.engine.registry import get_risk_points

            risk_points = get_risk_points()
            soft_score += risk_points.get(check.check_id, 10)

    # Integrate secrets detection into scoring
    if secrets_result is not None:
        is_production = environment == "production"

        if is_production and secrets_result.confirmed_secrets > 0:
            for finding in secrets_result.hard_blocks:
                hard_blocks.append(
                    f"Secrets Detection: {finding.type} at {finding.location}"
                )
        elif not is_production:
            # Non-production: hard-pattern findings that were downgraded to soft_risks add +30 each
            hard_pattern_types = set(HARD_PATTERNS.keys())
            for finding in secrets_result.soft_risks:
                if finding.type in hard_pattern_types:
                    soft_score += 30

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
