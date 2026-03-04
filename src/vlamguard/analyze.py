"""Core analyze pipeline — orchestrates Helm rendering, policy checks, external tools, AI, and scoring."""

import yaml

from vlamguard.ai.context import get_ai_context, get_security_ai_context
from vlamguard.ai.filtering import extract_metadata
from vlamguard.engine.external import run_all_external_tools
from vlamguard.engine.grading import calculate_security_grade
from vlamguard.engine.helm import render_chart
from vlamguard.engine.registry import get_check_fns
from vlamguard.engine.scoring import calculate_risk
from vlamguard.engine.secrets import scan_secrets
from vlamguard.engine.waivers import apply_waivers, load_waivers
from vlamguard.models.request import AnalyzeRequest
from vlamguard.models.response import AnalyzeResponse, PolicyCheckResult, SecuritySection

import vlamguard.engine.policies  # noqa: F401
import vlamguard.engine.policies_extended  # noqa: F401
import vlamguard.engine.crd.keda  # noqa: F401
import vlamguard.engine.crd.argocd  # noqa: F401
import vlamguard.engine.crd.istio  # noqa: F401
import vlamguard.engine.crd.certmanager  # noqa: F401
import vlamguard.engine.crd.externalsecrets  # noqa: F401

_EXTENDED_CHECK_IDS = {
    "host_namespace", "dangerous_volume_mounts", "excessive_capabilities",
    "service_account_token", "exposed_services",
}


async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """Run the full VlamGuard analysis pipeline.

    1. Render Helm chart to manifests
    2. Run all policy checks on each manifest (17 original + 5 extended)
    3. Secrets detection (if security_scan=True)
    4. Scoring (includes new checks automatically)
    5. External tools (kube-score, KubeLinter, Polaris) if not skipped
    6. AI context (extended with security findings if security_scan=True)
    7. Security grade (deterministic, if security_scan=True)
    8. Build response (includes security section + grade)
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

    # Step 2.5: Apply waivers if provided
    waivers_applied: list[dict] = []
    if request.waivers_path:
        waivers = load_waivers(request.waivers_path)
        all_results, waivers_applied = apply_waivers(all_results, waivers, manifests)

    # Step 3: Secrets detection (if security_scan enabled)
    secrets_result = None
    if request.security_scan:
        secrets_result = scan_secrets(manifests, request.values, request.environment)

    # Step 4: Scoring (includes secrets detection results)
    risk = calculate_risk(all_results, request.environment, secrets_result=secrets_result)

    # Step 5: External tools (optional)
    external_findings = []
    polaris_score = None
    if not request.skip_external:
        manifests_yaml = yaml.dump_all(manifests, default_flow_style=False)
        external_findings, polaris_score = run_all_external_tools(manifests_yaml)

    # Step 6: AI context (optional, security-enhanced if security_scan)
    ai_context = None
    hardening_recs = []
    secrets_ai_data = None

    if not request.skip_ai:
        manifests_metadata = [extract_metadata(m) for m in manifests]

        if request.security_scan:
            ai_context, hardening_recs, secrets_ai_data = await get_security_ai_context(
                manifests_metadata=manifests_metadata,
                policy_results=all_results,
                secrets_result=secrets_result,
                environment=request.environment,
                external_findings=external_findings,
            )
        else:
            ai_context = await get_ai_context(
                manifests_metadata=manifests_metadata,
                policy_results=all_results,
                environment=request.environment,
                external_findings=external_findings,
            )

    # Apply AI context to secrets findings if available
    if secrets_result and secrets_ai_data:
        secrets_result.summary = secrets_ai_data.get("summary")
        ai_findings = secrets_ai_data.get("findings", [])
        all_secret_findings = secrets_result.hard_blocks + secrets_result.soft_risks
        for ai_f in ai_findings:
            for sf in all_secret_findings:
                if sf.location == ai_f.get("location"):
                    sf.ai_context = ai_f.get("ai_context")
                    sf.recommendation = ai_f.get("recommendation")
                    sf.effort = ai_f.get("effort")

    # Step 7: Security grade (if security_scan enabled)
    security_grade = None
    security_section = None

    if request.security_scan:
        extended_checks = [r for r in all_results if r.check_id in _EXTENDED_CHECK_IDS]
        security_grade = calculate_security_grade(
            secrets_result=secrets_result,
            extended_check_results=extended_checks,
            hardening_recommendations=hardening_recs,
            environment=request.environment,
        )
        security_section = SecuritySection(
            secrets_detection=secrets_result,
            extended_checks=extended_checks,
            hardening_recommendations=hardening_recs,
        )

    return AnalyzeResponse(
        risk_score=risk.score,
        risk_level=risk.level,
        blocked=risk.blocked,
        hard_blocks=risk.hard_blocks,
        policy_checks=all_results,
        external_findings=external_findings,
        polaris_score=polaris_score,
        security_grade=security_grade,
        security=security_section,
        ai_context=ai_context,
        waivers_applied=waivers_applied,
        metadata={
            "environment": request.environment,
            "chart": request.chart,
            "manifest_count": len(manifests),
        },
    )
