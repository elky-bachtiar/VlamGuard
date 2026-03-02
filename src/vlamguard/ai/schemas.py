"""JSON schema validation for AI output."""

from vlamguard.models.response import AIContext, ImpactItem


def validate_ai_response(data: object) -> AIContext | None:
    """Validate and parse AI response data into AIContext model. Returns None if validation fails."""
    if not isinstance(data, dict):
        return None

    try:
        return AIContext(
            summary=data["summary"],
            impact_analysis=[ImpactItem(**item) for item in data["impact_analysis"]],
            recommendations=data["recommendations"],
            rollback_suggestion=data["rollback_suggestion"],
        )
    except (KeyError, TypeError, ValueError):
        return None
