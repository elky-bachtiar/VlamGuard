"""Binary environment logic: production=strict, everything else=soft."""

from enum import StrEnum


class CheckBehavior(StrEnum):
    """How a check behaves in a given environment."""

    HARD_BLOCK = "hard_block"
    SOFT_RISK = "soft_risk"
    OFF = "off"


def get_check_behavior(check_id: str, environment: str) -> CheckBehavior:
    """Return the behavior for a check in a given environment.

    Binary logic: 'production' is strict, everything else is soft.
    """
    from vlamguard.engine.registry import get_environment_matrix

    matrix = get_environment_matrix()
    prod_behavior, other_behavior = matrix[check_id]
    if environment == "production":
        return CheckBehavior(prod_behavior)
    return CheckBehavior(other_behavior)
