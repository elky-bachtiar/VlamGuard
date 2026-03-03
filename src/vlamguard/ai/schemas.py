"""JSON schema validation for AI output."""

import jsonschema

from vlamguard.models.response import AIContext, ImpactItem

AI_RESPONSE_SCHEMA: dict = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["summary", "impact_analysis", "recommendations", "rollback_suggestion"],
    "properties": {
        "summary": {"type": "string", "minLength": 1},
        "impact_analysis": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["severity", "resource", "description"],
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                    },
                    "resource": {"type": "string"},
                    "description": {"type": "string"},
                },
            },
        },
        "recommendations": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
        },
        "rollback_suggestion": {"type": "string", "minLength": 1},
    },
    "additionalProperties": False,
}


def validate_ai_response(data: object) -> AIContext | None:
    """Validate and parse AI response data into AIContext model.

    Uses JSON Schema validation first, then Pydantic for type safety.
    Returns None if validation fails at any stage.
    """
    if not isinstance(data, dict):
        return None

    try:
        jsonschema.validate(instance=data, schema=AI_RESPONSE_SCHEMA)
    except jsonschema.ValidationError:
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
