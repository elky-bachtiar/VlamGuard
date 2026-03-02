"""Core analyze pipeline — orchestrates Helm rendering, policy checks, AI, and scoring."""

from vlamguard.ai.context import get_ai_context
from vlamguard.ai.filtering import extract_metadata
from vlamguard.engine.helm import render_chart
from vlamguard.engine.policies import (
    check_image_tag,
    check_rbac_scope,
    check_replica_count,
    check_resource_limits,
    check_security_context,
)
from vlamguard.engine.scoring import calculate_risk
from vlamguard.models.request import AnalyzeRequest
from vlamguard.models.response import AnalyzeResponse, PolicyCheckResult

_ALL_CHECKS = [
    check_image_tag,
    check_security_context,
    check_rbac_scope,
    check_resource_limits,
    check_replica_count,
]


async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """Run the full VlamGuard analysis pipeline.

    1. Render Helm chart to manifests
    2. Run all policy checks on each manifest
    3. Optionally call AI for context
    4. Score and return response
    """
    # Step 1: Render
    manifests = render_chart(request.chart, request.values)

    # Step 2: Policy checks
    all_results: list[PolicyCheckResult] = []
    for manifest in manifests:
        for check_fn in _ALL_CHECKS:
            result = check_fn(manifest)
            if result.message.endswith("skipped."):
                continue
            all_results.append(result)

    # Step 3: Scoring
    risk = calculate_risk(all_results, request.environment)

    # Step 4: AI context (optional)
    ai_context = None
    if not request.skip_ai:
        manifests_metadata = [extract_metadata(m) for m in manifests]
        ai_context = await get_ai_context(
            manifests_metadata=manifests_metadata,
            policy_results=all_results,
            environment=request.environment,
        )

    return AnalyzeResponse(
        risk_score=risk.score,
        risk_level=risk.level,
        blocked=risk.blocked,
        hard_blocks=risk.hard_blocks,
        policy_checks=all_results,
        ai_context=ai_context,
        metadata={
            "environment": request.environment,
            "chart": request.chart,
            "manifest_count": len(manifests),
        },
    )
