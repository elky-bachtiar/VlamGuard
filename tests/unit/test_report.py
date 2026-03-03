"""Tests for report generation."""

from vlamguard.models.response import (
    AIContext,
    AnalyzeResponse,
    ExternalFinding,
    ImpactItem,
    PolicyCheckResult,
    RiskLevel,
)
from vlamguard.report.generator import generate_markdown


def _make_response(
    blocked: bool = False,
    ai: bool = False,
    external: bool = False,
    polaris_score: int | None = None,
) -> AnalyzeResponse:
    checks = [
        PolicyCheckResult(
            check_id="image_tag",
            name="Image Tag Policy",
            passed=not blocked,
            severity="critical",
            message="Uses latest tag." if blocked else "All tags explicit.",
        ),
    ]
    ai_context = None
    if ai:
        ai_context = AIContext(
            summary="This change is risky.",
            impact_analysis=[
                ImpactItem(severity="high", resource="Deployment/web", description="Unpinned image.")
            ],
            recommendations=["Pin image tag."],
            rollback_suggestion="kubectl rollout undo",
        )
    external_findings = []
    if external:
        external_findings = [
            ExternalFinding(
                tool="kube-score",
                check_id="container-image-tag",
                severity="critical",
                message="Image uses latest tag",
                resource="Deployment/web",
            ),
            ExternalFinding(
                tool="kube-linter",
                check_id="no-read-only-root-fs",
                severity="warning",
                message="Container not using read-only root filesystem",
                resource="Deployment/web",
            ),
        ]
    return AnalyzeResponse(
        risk_score=100 if blocked else 0,
        risk_level=RiskLevel.CRITICAL if blocked else RiskLevel.LOW,
        blocked=blocked,
        hard_blocks=["Image Tag Policy: Uses latest tag."] if blocked else [],
        policy_checks=checks,
        external_findings=external_findings,
        polaris_score=polaris_score,
        ai_context=ai_context,
        metadata={"environment": "production", "chart": "test"},
    )


class TestMarkdownReport:
    def test_contains_risk_score(self) -> None:
        resp = _make_response(blocked=False)
        md = generate_markdown(resp)
        # The generator emits "**Risk Score:** 0/100 (LOW)" — match the visible text
        assert "0/100" in md
        assert "LOW" in md.upper()

    def test_blocked_shows_hard_blocks(self) -> None:
        resp = _make_response(blocked=True)
        md = generate_markdown(resp)
        assert "BLOCKED" in md.upper()
        assert "Image Tag Policy" in md

    def test_ai_context_included_when_present(self) -> None:
        resp = _make_response(blocked=True, ai=True)
        md = generate_markdown(resp)
        assert "AI Analysis" in md
        assert "This change is risky." in md
        assert "Pin image tag." in md

    def test_no_ai_section_when_absent(self) -> None:
        resp = _make_response(blocked=False, ai=False)
        md = generate_markdown(resp)
        assert "not available" in md.lower()

    def test_policy_checks_listed(self) -> None:
        resp = _make_response(blocked=False)
        md = generate_markdown(resp)
        assert "Image Tag Policy" in md

    def test_external_findings_section(self) -> None:
        resp = _make_response(blocked=True, external=True)
        md = generate_markdown(resp)
        assert "External Tool Findings" in md
        assert "kube-score" in md
        assert "kube-linter" in md
        assert "container-image-tag" in md
        assert "no-read-only-root-fs" in md

    def test_no_external_section_when_empty(self) -> None:
        resp = _make_response(blocked=False)
        md = generate_markdown(resp)
        assert "External Tool Findings" not in md

    def test_polaris_score_comparison(self) -> None:
        resp = _make_response(blocked=False, polaris_score=72)
        md = generate_markdown(resp)
        assert "Score Comparison" in md
        assert "Polaris" in md
        assert "72" in md

    def test_no_polaris_section_when_none(self) -> None:
        resp = _make_response(blocked=False, polaris_score=None)
        md = generate_markdown(resp)
        assert "Score Comparison" not in md
