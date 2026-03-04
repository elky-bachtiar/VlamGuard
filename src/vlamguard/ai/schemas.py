"""JSON schema validation for AI output."""

import jsonschema

from vlamguard.models.response import AIContext, HardeningAction, ImpactItem, Recommendation

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
            "items": {
                "oneOf": [
                    {"type": "string"},
                    {
                        "type": "object",
                        "required": ["action"],
                        "properties": {
                            "action": {"type": "string", "minLength": 1},
                            "reason": {"type": "string"},
                            "resource": {"type": "string"},
                            "yaml_snippet": {"type": "string"},
                        },
                        "additionalProperties": False,
                    },
                ]
            },
            "minItems": 1,
        },
        "rollback_suggestion": {"type": "string", "minLength": 1},
        "secrets_detection": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "location": {"type": "string"},
                            "ai_context": {"type": "string"},
                            "recommendation": {"type": "string"},
                            "effort": {
                                "type": "string",
                                "enum": ["low", "medium", "high"],
                            },
                        },
                        "required": ["location", "ai_context", "recommendation"],
                    },
                },
            },
        },
        "hardening_recommendations": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["priority", "category", "action", "effort", "impact"],
                "properties": {
                    "priority": {"type": "integer", "minimum": 1},
                    "category": {
                        "type": "string",
                        "enum": ["container", "network", "supply_chain", "operational"],
                    },
                    "action": {"type": "string", "minLength": 1},
                    "effort": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                    },
                    "impact": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                    },
                    "resource": {"type": "string"},
                    "details": {"type": "string"},
                    "yaml_hint": {"type": "string"},
                },
            },
        },
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
        recommendations: list[str | Recommendation] = []
        for item in data["recommendations"]:
            if isinstance(item, str):
                recommendations.append(item)
            elif isinstance(item, dict):
                recommendations.append(Recommendation(**item))
        return AIContext(
            summary=data["summary"],
            impact_analysis=[ImpactItem(**item) for item in data["impact_analysis"]],
            recommendations=recommendations,
            rollback_suggestion=data["rollback_suggestion"],
        )
    except (KeyError, TypeError, ValueError):
        return None


def validate_security_ai_response(data: object) -> dict | None:
    """Extract security-specific AI fields from a validated response.

    Returns dict with optional keys: secrets_detection, hardening_recommendations.
    Returns None if data is not a dict.
    """
    if not isinstance(data, dict):
        return None

    result: dict = {}

    if "secrets_detection" in data:
        result["secrets_detection"] = data["secrets_detection"]

    if "hardening_recommendations" in data:
        recs = []
        for item in data["hardening_recommendations"]:
            try:
                recs.append(
                    HardeningAction(
                        priority=item["priority"],
                        category=item["category"],
                        action=item["action"],
                        effort=item["effort"],
                        impact=item["impact"],
                        resource=item.get("resource"),
                        details=item.get("details"),
                        yaml_hint=item.get("yaml_hint"),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        result["hardening_recommendations"] = recs

    return result if result else None
