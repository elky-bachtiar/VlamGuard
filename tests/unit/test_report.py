"""Tests for report generation."""

from vlamguard.models.response import (
    AIContext,
    AnalyzeResponse,
    ImpactItem,
    PolicyCheckResult,
    RiskLevel,
)
from vlamguard.report.generator import generate_markdown


def _make_response(blocked: bool = False, ai: bool = False) -> AnalyzeResponse:
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
    return AnalyzeResponse(
        risk_score=100 if blocked else 0,
        risk_level=RiskLevel.CRITICAL if blocked else RiskLevel.LOW,
        blocked=blocked,
        hard_blocks=["Image Tag Policy: Uses latest tag."] if blocked else [],
        policy_checks=checks,
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
