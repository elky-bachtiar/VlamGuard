"""Tests for report models: Platform, PlatformInfo, FixApplied, ReportResponse."""

import pytest
from pydantic import ValidationError

from vlamguard.models.report import FixApplied, Platform, PlatformInfo, ReportResponse
from vlamguard.models.response import (
    AnalyzeResponse,
    PolicyCheckResult,
    RiskLevel,
)


def _minimal_analyze_response() -> AnalyzeResponse:
    """Return a minimal valid AnalyzeResponse for use in ReportResponse tests."""
    return AnalyzeResponse(
        risk_score=10,
        risk_level=RiskLevel.LOW,
        blocked=False,
        hard_blocks=[],
        policy_checks=[
            PolicyCheckResult(
                check_id="image_tag",
                name="Image Tag Policy",
                passed=True,
                severity="critical",
                message="All images use explicit version tags.",
            )
        ],
        ai_context=None,
        metadata={"environment": "staging", "chart": "test-chart"},
    )


class TestPlatform:
    def test_github_value(self):
        assert Platform.GITHUB == "github"

    def test_gitlab_value(self):
        assert Platform.GITLAB == "gitlab"

    def test_invalid_platform_raises(self):
        with pytest.raises(ValueError):
            Platform("bitbucket")

    def test_enum_members(self):
        members = list(Platform)
        assert len(members) == 2
        assert Platform.GITHUB in members
        assert Platform.GITLAB in members


class TestPlatformInfo:
    def test_github_platform_info(self):
        info = PlatformInfo(
            platform=Platform.GITHUB,
            remote_url="https://github.com/org/repo.git",
            remote_name="origin",
            cli_command="gh",
            body_flag="--body",
            term="PR",
        )
        assert info.platform == Platform.GITHUB
        assert info.remote_url == "https://github.com/org/repo.git"
        assert info.remote_name == "origin"
        assert info.cli_command == "gh"
        assert info.body_flag == "--body"
        assert info.term == "PR"

    def test_gitlab_platform_info(self):
        info = PlatformInfo(
            platform=Platform.GITLAB,
            remote_url="https://gitlab.com/org/repo.git",
            remote_name="upstream",
            cli_command="glab",
            body_flag="--description",
            term="MR",
        )
        assert info.platform == Platform.GITLAB
        assert info.cli_command == "glab"
        assert info.body_flag == "--description"
        assert info.term == "MR"

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            PlatformInfo(
                platform=Platform.GITHUB,
                remote_url="https://github.com/org/repo.git",
                # remote_name missing
                cli_command="gh",
                body_flag="--body",
                term="PR",
            )

    def test_platform_string_coercion(self):
        """Platform field accepts the string value due to StrEnum."""
        info = PlatformInfo(
            platform="github",
            remote_url="https://github.com/org/repo.git",
            remote_name="origin",
            cli_command="gh",
            body_flag="--body",
            term="PR",
        )
        assert info.platform == Platform.GITHUB


class TestFixApplied:
    def test_full_fields(self):
        fix = FixApplied(
            check_id="security_context",
            file_path="charts/templates/deployment.yaml",
            description="Added runAsNonRoot: true",
            before_snippet="securityContext: {}",
            after_snippet="securityContext:\n  runAsNonRoot: true",
        )
        assert fix.check_id == "security_context"
        assert fix.file_path == "charts/templates/deployment.yaml"
        assert fix.description == "Added runAsNonRoot: true"
        assert fix.before_snippet == "securityContext: {}"
        assert fix.after_snippet == "securityContext:\n  runAsNonRoot: true"

    def test_minimal_fields(self):
        fix = FixApplied(
            check_id="image_tag",
            file_path="charts/templates/deployment.yaml",
            description="Pinned image to explicit tag",
        )
        assert fix.before_snippet is None
        assert fix.after_snippet is None

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            FixApplied(
                check_id="image_tag",
                # file_path missing
                description="Pinned image to explicit tag",
            )


class TestReportResponse:
    def test_minimal_fields(self):
        analysis = _minimal_analyze_response()
        report = ReportResponse(analysis=analysis)
        assert report.analysis is analysis
        assert report.issue_url is None
        assert report.pr_url is None
        assert report.fixes_applied == []
        assert report.unfixed == []

    def test_full_fields(self):
        analysis = _minimal_analyze_response()
        fix = FixApplied(
            check_id="security_context",
            file_path="charts/templates/deployment.yaml",
            description="Added securityContext",
        )
        report = ReportResponse(
            analysis=analysis,
            issue_url="https://github.com/org/repo/issues/42",
            pr_url="https://github.com/org/repo/pull/43",
            fixes_applied=[fix],
            unfixed=["resource_limits"],
        )
        assert report.issue_url == "https://github.com/org/repo/issues/42"
        assert report.pr_url == "https://github.com/org/repo/pull/43"
        assert len(report.fixes_applied) == 1
        assert report.fixes_applied[0].check_id == "security_context"
        assert report.unfixed == ["resource_limits"]

    def test_fixes_applied_default_is_empty_list(self):
        analysis = _minimal_analyze_response()
        report = ReportResponse(analysis=analysis)
        assert isinstance(report.fixes_applied, list)
        assert len(report.fixes_applied) == 0

    def test_unfixed_default_is_empty_list(self):
        analysis = _minimal_analyze_response()
        report = ReportResponse(analysis=analysis)
        assert isinstance(report.unfixed, list)
        assert len(report.unfixed) == 0

    def test_missing_analysis_raises(self):
        with pytest.raises(ValidationError):
            ReportResponse()

    def test_multiple_fixes_applied(self):
        analysis = _minimal_analyze_response()
        fixes = [
            FixApplied(
                check_id=f"check_{i}",
                file_path=f"charts/templates/file_{i}.yaml",
                description=f"Fix for check {i}",
            )
            for i in range(3)
        ]
        report = ReportResponse(analysis=analysis, fixes_applied=fixes)
        assert len(report.fixes_applied) == 3
        assert report.fixes_applied[2].check_id == "check_2"
