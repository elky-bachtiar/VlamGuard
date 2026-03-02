"""Binary environment logic: production=strict, everything else=soft."""

from enum import StrEnum


class CheckBehavior(StrEnum):
    """How a check behaves in a given environment."""

    HARD_BLOCK = "hard_block"
    SOFT_RISK = "soft_risk"
    OFF = "off"


# Matrix: check_id -> (production_behavior, other_behavior)
_ENVIRONMENT_MATRIX: dict[str, tuple[CheckBehavior, CheckBehavior]] = {
    "image_tag": (CheckBehavior.HARD_BLOCK, CheckBehavior.SOFT_RISK),
    "security_context": (CheckBehavior.HARD_BLOCK, CheckBehavior.SOFT_RISK),
    "rbac_scope": (CheckBehavior.HARD_BLOCK, CheckBehavior.HARD_BLOCK),
    "resource_limits": (CheckBehavior.SOFT_RISK, CheckBehavior.OFF),
    "replica_count": (CheckBehavior.SOFT_RISK, CheckBehavior.OFF),
}


def get_check_behavior(check_id: str, environment: str) -> CheckBehavior:
    """Return the behavior for a check in a given environment.

    Binary logic: 'production' is strict, everything else is soft.
    """
    behaviors = _ENVIRONMENT_MATRIX[check_id]
    if environment == "production":
        return behaviors[0]
    return behaviors[1]
