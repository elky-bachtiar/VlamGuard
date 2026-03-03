"""Core analyze pipeline — orchestrates Helm rendering, policy checks, external tools, AI, and scoring."""

import yaml

from vlamguard.ai.context import get_ai_context
from vlamguard.ai.filtering import extract_metadata
from vlamguard.engine.external import run_all_external_tools
from vlamguard.engine.helm import render_chart
from vlamguard.engine.registry import get_check_fns
from vlamguard.engine.scoring import calculate_risk
from vlamguard.models.request import AnalyzeRequest
from vlamguard.models.response import AnalyzeResponse, PolicyCheckResult

import vlamguard.engine.policies  # noqa: F401


async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """Run the full VlamGuard analysis pipeline.

    1. Render Helm chart to manifests
    2. Run all policy checks on each manifest
    3. Run external tools (kube-score, KubeLinter, Polaris) if not skipped
    4. Optionally call AI for context
    5. Score and return response
    """
    # Step 1: Render
    manifests = render_chart(request.chart, request.values)

    # Step 2: Policy checks
    all_results: list[PolicyCheckResult] = []
    for manifest in manifests:
        for check_fn in get_check_fns():
            result = check_fn(manifest)
            if result.message.endswith("skipped."):
                continue
            all_results.append(result)

    # Step 3: Scoring
    risk = calculate_risk(all_results, request.environment)

    # Step 4: External tools (optional)
    external_findings = []
    polaris_score = None
    if not request.skip_external:
        manifests_yaml = yaml.dump_all(manifests, default_flow_style=False)
        external_findings, polaris_score = run_all_external_tools(manifests_yaml)

    # Step 5: AI context (optional)
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
        external_findings=external_findings,
        polaris_score=polaris_score,
        ai_context=ai_context,
        metadata={
            "environment": request.environment,
            "chart": request.chart,
            "manifest_count": len(manifests),
        },
    )
