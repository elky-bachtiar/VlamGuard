"""Vlam AI client — OpenAI-compatible API integration."""

import json
import os

import httpx

from vlamguard.ai.schemas import validate_ai_response, validate_security_ai_response
from vlamguard.models.response import (
    AIContext,
    ExternalFinding,
    HardeningAction,
    PolicyCheckResult,
    SecretsDetectionResult,
)

_DEFAULT_BASE_URL = "http://localhost:11434/v1"
_DEFAULT_MODEL = "llama3.2"
_DEFAULT_TIMEOUT_SECONDS = 30


def _get_timeout() -> int:
    """Get AI request timeout from env or default."""
    try:
        return int(os.environ.get("VLAM_AI_TIMEOUT", _DEFAULT_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        return _DEFAULT_TIMEOUT_SECONDS

_SYSTEM_PROMPT = """You are VlamGuard AI, an infrastructure risk analyst. You receive Kubernetes manifest metadata, policy check results, and optionally external tool findings from kube-score, KubeLinter, and Polaris. Respond with a JSON object containing:

- "summary": 2-3 sentences about what changes and why it matters
- "impact_analysis": array of {"severity": "low|medium|high|critical", "resource": "Kind/name", "description": "..."}
- "recommendations": array of recommendations (highest priority first). Each item is either a plain string OR an object: {"action": "what to do", "reason": "why this matters — explain the security/reliability risk", "resource": "Kind/name (e.g. Deployment/web)", "yaml_snippet": "the YAML change to apply"}. Use the object form when you can provide a concrete YAML fix. Always include "reason" to explain why the recommendation matters. The resource should match a resource from the manifests. Include recommendations for external tool findings when provided — explain what the external tool detected and how to fix it.
- "rollback_suggestion": how to rollback if problems occur

Respond ONLY with valid JSON. No markdown, no explanation outside the JSON."""

_SECURITY_SYSTEM_PROMPT = """You are VlamGuard AI, an infrastructure security analyst. You receive Kubernetes manifest metadata, policy check results, security scan findings, and optionally external tool findings from kube-score, KubeLinter, and Polaris. Respond with a JSON object containing:

- "summary": 2-3 sentences about what changes and why it matters
- "impact_analysis": array of {"severity": "low|medium|high|critical", "resource": "Kind/name", "description": "..."}
- "recommendations": array of recommendations (highest priority first). Each item is either a plain string OR an object: {"action": "what to do", "reason": "why this matters — explain the security/reliability risk", "resource": "Kind/name (e.g. Deployment/web)", "yaml_snippet": "the YAML change to apply"}. Use the object form when you can provide a concrete YAML fix. Always include "reason" to explain why the recommendation matters. The resource should match a resource from the manifests. Include recommendations for external tool findings when provided — explain what the external tool detected and how to fix it.
- "rollback_suggestion": how to rollback if problems occur
- "secrets_detection": (optional, include if secret findings are provided) {"summary": "...", "findings": [{"location": "...", "ai_context": "why this is a risk", "recommendation": "how to fix", "effort": "low|medium|high"}]}
- "hardening_recommendations": (optional, include if security checks are provided) array of {"priority": 1, "category": "container|network|supply_chain|operational", "action": "what to do", "effort": "low|medium|high", "impact": "low|medium|high", "resource": "Kind/name", "details": "...", "yaml_hint": "..."}

IMPORTANT: Never include actual secret values in your response — only reference locations and types.
Respond ONLY with valid JSON. No markdown, no explanation outside the JSON."""


def _serialize_external_findings(findings: list[ExternalFinding]) -> list[dict]:
    """Serialize external findings for the AI prompt."""
    return [
        {
            "tool": f.tool,
            "check_id": f.check_id,
            "severity": f.severity,
            "message": f.message,
            "resource": f.resource,
        }
        for f in findings
    ]


async def get_ai_context(
    manifests_metadata: list[dict],
    policy_results: list[PolicyCheckResult],
    environment: str,
    security_findings: dict | None = None,
    external_findings: list[ExternalFinding] | None = None,
) -> AIContext | None:
    """Call Vlam AI for context analysis. Returns None on any failure.

    Args:
        manifests_metadata: Filtered manifest metadata.
        policy_results: Policy check results.
        environment: Target environment.
        security_findings: Optional dict with secrets_detection and extended_checks
                          for security-aware AI context.
        external_findings: Optional list of findings from external tools
                          (kube-score, KubeLinter, Polaris).
    """
    base_url = os.environ.get("VLAM_AI_BASE_URL", _DEFAULT_BASE_URL)
    model = os.environ.get("VLAM_AI_MODEL", _DEFAULT_MODEL)

    use_security_prompt = security_findings is not None
    system_prompt = _SECURITY_SYSTEM_PROMPT if use_security_prompt else _SYSTEM_PROMPT

    user_data: dict = {
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
    }

    if external_findings:
        user_data["external_tool_findings"] = _serialize_external_findings(external_findings)

    if security_findings:
        # Include security findings metadata (never values)
        if "secrets_detection" in security_findings:
            sd = security_findings["secrets_detection"]
            user_data["security_scan"] = {
                "secrets": {
                    "total_suspects": sd.get("total_suspects", 0),
                    "confirmed_secrets": sd.get("confirmed_secrets", 0),
                    "findings": [
                        {"type": f["type"], "location": f["location"], "detection": f["detection"]}
                        for f in sd.get("hard_blocks", []) + sd.get("soft_risks", [])
                    ],
                },
            }
        if "extended_checks" in security_findings:
            user_data["security_scan"] = user_data.get("security_scan", {})
            user_data["security_scan"]["extended_checks"] = [
                {
                    "check_id": r.check_id,
                    "name": r.name,
                    "passed": r.passed,
                    "message": r.message,
                }
                for r in security_findings["extended_checks"]
            ]

    user_content = json.dumps(user_data, indent=2)

    api_key = os.environ.get("VLAM_AI_API_KEY")
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    try:
        async with httpx.AsyncClient(timeout=_get_timeout()) as client:
            response = await client.post(
                f"{base_url}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
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


async def get_security_ai_context(
    manifests_metadata: list[dict],
    policy_results: list[PolicyCheckResult],
    secrets_result: SecretsDetectionResult | None,
    environment: str,
    external_findings: list[ExternalFinding] | None = None,
) -> tuple[AIContext | None, list[HardeningAction], dict | None]:
    """Call AI with full security context. Returns (ai_context, hardening_recs, secrets_ai_data).

    This is the security-enhanced version that passes security findings to AI
    and extracts hardening recommendations + secrets context from the response.
    """
    security_findings: dict = {}

    if secrets_result:
        security_findings["secrets_detection"] = {
            "total_suspects": secrets_result.total_suspects,
            "confirmed_secrets": secrets_result.confirmed_secrets,
            "hard_blocks": [f.model_dump() for f in secrets_result.hard_blocks],
            "soft_risks": [f.model_dump() for f in secrets_result.soft_risks],
        }

    extended_checks = [r for r in policy_results if r.check_id in {
        "host_namespace", "dangerous_volume_mounts", "excessive_capabilities",
        "service_account_token", "exposed_services",
    }]
    if extended_checks:
        security_findings["extended_checks"] = extended_checks

    base_url = os.environ.get("VLAM_AI_BASE_URL", _DEFAULT_BASE_URL)
    model = os.environ.get("VLAM_AI_MODEL", _DEFAULT_MODEL)

    user_data: dict = {
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
    }

    if external_findings:
        user_data["external_tool_findings"] = _serialize_external_findings(external_findings)

    if security_findings.get("secrets_detection"):
        sd = security_findings["secrets_detection"]
        user_data["security_scan"] = {
            "secrets": {
                "total_suspects": sd["total_suspects"],
                "confirmed_secrets": sd["confirmed_secrets"],
                "findings": [
                    {"type": f["type"], "location": f["location"], "detection": f["detection"]}
                    for f in sd.get("hard_blocks", []) + sd.get("soft_risks", [])
                ],
            },
        }
    if security_findings.get("extended_checks"):
        user_data["security_scan"] = user_data.get("security_scan", {})
        user_data["security_scan"]["extended_checks"] = [
            {"check_id": r.check_id, "name": r.name, "passed": r.passed, "message": r.message}
            for r in security_findings["extended_checks"]
        ]

    user_content = json.dumps(user_data, indent=2)

    api_key = os.environ.get("VLAM_AI_API_KEY")
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    try:
        async with httpx.AsyncClient(timeout=_get_timeout()) as client:
            response = await client.post(
                f"{base_url}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": _SECURITY_SYSTEM_PROMPT},
                        {"role": "user", "content": user_content},
                    ],
                    "temperature": 0.2,
                },
            )
            response.raise_for_status()
            data = response.json()

        content = data["choices"][0]["message"]["content"]
        parsed = json.loads(content)

        ai_context = validate_ai_response(parsed)
        security_ai = validate_security_ai_response(parsed)

        hardening_recs: list[HardeningAction] = []
        secrets_ai_data: dict | None = None

        if security_ai:
            hardening_recs = security_ai.get("hardening_recommendations", [])
            secrets_ai_data = security_ai.get("secrets_detection")

        return ai_context, hardening_recs, secrets_ai_data

    except (httpx.TimeoutException, httpx.HTTPError):
        return None, [], None
    except (json.JSONDecodeError, KeyError, IndexError):
        return None, [], None
