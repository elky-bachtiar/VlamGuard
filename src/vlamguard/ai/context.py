"""Vlam AI client — OpenAI-compatible API integration."""

import json
import os

import httpx

from vlamguard.ai.schemas import validate_ai_response
from vlamguard.models.response import AIContext, PolicyCheckResult

_DEFAULT_BASE_URL = "http://localhost:11434/v1"
_DEFAULT_MODEL = "llama3.2"
_TIMEOUT_SECONDS = 15

_SYSTEM_PROMPT = """You are VlamGuard AI, an infrastructure risk analyst. You receive Kubernetes manifest metadata and policy check results. Respond with a JSON object containing:

- "summary": 2-3 sentences about what changes and why it matters
- "impact_analysis": array of {"severity": "low|medium|high|critical", "resource": "Kind/name", "description": "..."}
- "recommendations": array of concrete actionable recommendations, highest priority first
- "rollback_suggestion": how to rollback if problems occur

Respond ONLY with valid JSON. No markdown, no explanation outside the JSON."""


async def get_ai_context(
    manifests_metadata: list[dict],
    policy_results: list[PolicyCheckResult],
    environment: str,
) -> AIContext | None:
    """Call Vlam AI for context analysis. Returns None on any failure."""
    base_url = os.environ.get("VLAM_AI_BASE_URL", _DEFAULT_BASE_URL)
    model = os.environ.get("VLAM_AI_MODEL", _DEFAULT_MODEL)

    user_content = json.dumps(
        {
            "environment": environment,
            "manifests": manifests_metadata,
            "policy_results": [
                {
                    "check_id": r.check_id,
                    "name": r.name,
                    "passed": r.passed,
                    "severity": r.severity,
                    "message": r.message,
                }
                for r in policy_results
            ],
        },
        indent=2,
    )

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"{base_url}/chat/completions",
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_content},
                    ],
                    "temperature": 0.2,
                },
            )
            response.raise_for_status()
            data = response.json()

        content = data["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        return validate_ai_response(parsed)

    except (httpx.TimeoutException, httpx.HTTPError):
        return None
    except (json.JSONDecodeError, KeyError, IndexError):
        return None
