# tests/unit/test_issue_creation.py
"""Tests for issue body generation and creation."""

import subprocess
from unittest.mock import patch

import pytest

from vlamguard.integrations import IssueCreationError
from vlamguard.integrations.issues import build_issue_body, build_issue_title, select_labels, create_issue
from vlamguard.models.report import Platform, PlatformInfo
from vlamguard.models.response import (
    AIContext,
    AnalyzeResponse,
    ImpactItem,
    PolicyCheckResult,
    Recommendation,
    RiskLevel,
    SecurityGrade,
)


def _make_platform(platform: Platform = Platform.GITHUB) -> PlatformInfo:
    if platform == Platform.GITHUB:
        return PlatformInfo(
            platform=Platform.GITHUB,
            remote_url="git@github.com:user/repo.git",
            remote_name="origin",
            cli_command="gh",
            body_flag="--body",
            term="PR",
        )
    return PlatformInfo(
        platform=Platform.GITLAB,
        remote_url="git@gitlab.com:user/repo.git",
        remote_name="gitlab",
        cli_command="glab",
        body_flag="--description",
        term="MR",
    )


def _make_response(
    failed_checks: list[PolicyCheckResult] | None = None,
    ai_context: AIContext | None = None,
    security_grade: SecurityGrade | None = None,
) -> AnalyzeResponse:
    checks = failed_checks or []
    ctx = ai_context or AIContext(
        summary="Test summary of findings.",
        impact_analysis=[ImpactItem(severity="high", resource="Deployment/web", description="Missing security context")],
        recommendations=["Add security context"],
        rollback_suggestion="Revert the deployment.",
    )
    return AnalyzeResponse(
        risk_score=65,
        risk_level=RiskLevel.HIGH,
        blocked=True,
        hard_blocks=["security_context"],
        policy_checks=checks,
        ai_context=ctx,
        security_grade=security_grade,
        metadata={"environment": "production", "manifest_count": 2},
    )


class TestSelectLabels:
    def test_security_category(self):
        checks = [
            PolicyCheckResult(check_id="x", name="x", passed=False, severity="high", message="fail", category="security"),
        ]
        assert select_labels(checks) == ["security", "policy"]

    def test_security_subcategory(self):
        checks = [
            PolicyCheckResult(check_id="x", name="x", passed=False, severity="high", message="fail", category="keda-security"),
        ]
        assert select_labels(checks) == ["security", "policy"]

    def test_non_security_category(self):
        checks = [
            PolicyCheckResult(check_id="x", name="x", passed=False, severity="medium", message="fail", category="reliability"),
        ]
        assert select_labels(checks) == ["bug"]

    def test_no_failed_checks(self):
        checks = [
            PolicyCheckResult(check_id="x", name="x", passed=True, severity="medium", message="pass", category="security"),
        ]
        assert select_labels(checks) == ["bug"]


class TestBuildIssueTitle:
    def test_security_title(self):
        checks = [
            PolicyCheckResult(check_id="x", name="x", passed=False, severity="high", message="fail", category="security"),
        ]
        title = build_issue_title(_make_response(failed_checks=checks), checks)
        assert title.startswith("[Security]: VlamGuard")
        assert "high" in title.lower()

    def test_bug_title(self):
        checks = [
            PolicyCheckResult(check_id="x", name="x", passed=False, severity="medium", message="fail", category="reliability"),
        ]
        title = build_issue_title(_make_response(failed_checks=checks), checks)
        assert title.startswith("[Bug]: VlamGuard")


class TestBuildIssueBody:
    def test_contains_summary(self):
        body = build_issue_body(_make_response())
        assert "Test summary of findings." in body

    def test_contains_risk_score(self):
        body = build_issue_body(_make_response())
        assert "65" in body
        assert "high" in body.lower()

    def test_contains_hard_blocks(self):
        body = build_issue_body(_make_response())
        assert "security_context" in body

    def test_contains_recommendations_string(self):
        body = build_issue_body(_make_response())
        assert "Add security context" in body

    def test_contains_recommendations_object(self):
        rec = Recommendation(
            action="Add runAsNonRoot",
            reason="Prevents root execution",
            resource="Deployment/web",
            yaml_snippet="securityContext:\n  runAsNonRoot: true",
        )
        ctx = AIContext(
            summary="Summary",
            impact_analysis=[],
            recommendations=[rec],
            rollback_suggestion="Rollback.",
        )
        body = build_issue_body(_make_response(ai_context=ctx))
        assert "Add runAsNonRoot" in body
        assert "runAsNonRoot: true" in body
        assert "Deployment/web" in body

    def test_contains_failed_checks_table(self):
        checks = [
            PolicyCheckResult(check_id="sc", name="Security Context", passed=False, severity="critical", message="Missing", category="security"),
        ]
        body = build_issue_body(_make_response(failed_checks=checks))
        assert "sc" in body
        assert "Security Context" in body

    def test_contains_grade_when_present(self):
        body = build_issue_body(_make_response(security_grade=SecurityGrade.D))
        assert "D" in body

    def test_contains_footer(self):
        body = build_issue_body(_make_response())
        assert "VlamGuard" in body


class TestCreateIssue:
    @patch("vlamguard.integrations.issues.run_cmd")
    def test_github_create(self, mock_run):
        mock_run.return_value = "https://github.com/user/repo/issues/42"
        url = create_issue(_make_response(), _make_platform())
        assert url == "https://github.com/user/repo/issues/42"
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "gh"
        assert "issue" in call_args
        assert "create" in call_args

    @patch("vlamguard.integrations.issues.run_cmd")
    def test_gitlab_create(self, mock_run):
        mock_run.return_value = "https://gitlab.com/user/repo/-/issues/42"
        url = create_issue(_make_response(), _make_platform(Platform.GITLAB))
        assert url == "https://gitlab.com/user/repo/-/issues/42"
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "glab"

    def test_missing_ai_context_raises(self):
        response = AnalyzeResponse(
            risk_score=50,
            risk_level=RiskLevel.MEDIUM,
            blocked=False,
            hard_blocks=[],
            policy_checks=[],
            ai_context=None,
            metadata={"environment": "dev", "manifest_count": 1},
        )
        with pytest.raises(IssueCreationError, match="AI analysis required"):
            create_issue(response, _make_platform())

    @patch("vlamguard.integrations.issues.run_cmd")
    def test_cli_failure_raises(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, "gh", stderr="auth required")
        with pytest.raises(IssueCreationError):
            create_issue(_make_response(), _make_platform())
