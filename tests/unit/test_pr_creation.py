# tests/unit/test_pr_creation.py
"""Tests for PR/MR creation and fix application."""

import subprocess
from unittest.mock import patch, MagicMock, call

import pytest

from vlamguard.integrations import PRCreationError
from vlamguard.integrations.pull_requests import (
    build_pr_body,
    create_pull_request,
    _check_clean_tree,
    _get_current_branch,
    REMEDIATION_MAP,
)
from vlamguard.models.report import Platform, PlatformInfo, FixApplied
from vlamguard.models.response import (
    AIContext,
    AnalyzeResponse,
    ImpactItem,
    PolicyCheckResult,
    Recommendation,
    RiskLevel,
)


def _make_platform() -> PlatformInfo:
    return PlatformInfo(
        platform=Platform.GITHUB,
        remote_url="git@github.com:user/repo.git",
        remote_name="origin",
        cli_command="gh",
        body_flag="--body",
        term="PR",
    )


def _make_response(
    checks: list[PolicyCheckResult] | None = None,
    recs: list | None = None,
) -> AnalyzeResponse:
    ctx = AIContext(
        summary="Security issues found.",
        impact_analysis=[],
        recommendations=recs or ["Fix security context"],
        rollback_suggestion="Rollback.",
    )
    return AnalyzeResponse(
        risk_score=70,
        risk_level=RiskLevel.HIGH,
        blocked=True,
        hard_blocks=["security_context"],
        policy_checks=checks or [],
        ai_context=ctx,
        metadata={"environment": "production", "manifest_count": 1},
    )


class TestCheckCleanTree:
    @patch("vlamguard.integrations.pull_requests.run_cmd")
    def test_clean_tree(self, mock_run):
        mock_run.return_value = ""
        _check_clean_tree()  # Should not raise

    @patch("vlamguard.integrations.pull_requests.run_cmd")
    def test_dirty_tree_raises(self, mock_run):
        mock_run.return_value = "M values.yaml"
        with pytest.raises(PRCreationError, match="uncommitted changes"):
            _check_clean_tree()


class TestGetCurrentBranch:
    @patch("vlamguard.integrations.pull_requests.run_cmd")
    def test_returns_branch_name(self, mock_run):
        mock_run.return_value = "main"
        assert _get_current_branch() == "main"


class TestBuildPRBody:
    def test_contains_before_after(self):
        before = _make_response()
        after = AnalyzeResponse(
            risk_score=20,
            risk_level=RiskLevel.LOW,
            blocked=False,
            hard_blocks=[],
            policy_checks=[],
            ai_context=before.ai_context,
            metadata=before.metadata,
        )
        fixes = [FixApplied(check_id="security_context", file_path="values.yaml", description="Added runAsNonRoot")]
        body = build_pr_body(before, after, fixes, unfixed=[], issue_url=None)
        assert "70" in body  # before score
        assert "20" in body  # after score

    def test_contains_issue_link(self):
        before = _make_response()
        body = build_pr_body(before, before, [], [], issue_url="https://github.com/user/repo/issues/1")
        assert "https://github.com/user/repo/issues/1" in body

    def test_contains_fixes_table(self):
        before = _make_response()
        fixes = [FixApplied(check_id="sc", file_path="v.yaml", description="fix")]
        body = build_pr_body(before, before, fixes, unfixed=["rl"])
        assert "sc" in body
        assert "rl" in body


class TestRemediationMap:
    def test_has_common_checks(self):
        assert "security_context" in REMEDIATION_MAP
        assert "resource_limits" in REMEDIATION_MAP
        assert "readonly_root_fs" in REMEDIATION_MAP
        assert "image_tag" not in REMEDIATION_MAP  # Handled by AI, not static map


class TestApplyFixes:
    def test_applies_known_check(self, tmp_path):
        from vlamguard.integrations.pull_requests import _apply_fixes

        manifest = tmp_path / "values.yaml"
        manifest.write_text("replicaCount: 1\n")

        checks = [PolicyCheckResult(
            check_id="replica_count", name="Replica Count",
            passed=False, severity="medium", message="Low replicas",
            category="reliability",
        )]
        response = _make_response(checks=checks)
        fixes, unfixed, _ = _apply_fixes(response, manifest)

        assert len(fixes) == 1
        assert fixes[0].check_id == "replica_count"
        assert "replicaCount" in manifest.read_text()
        assert unfixed == []

    def test_unknown_check_goes_to_unfixed(self, tmp_path):
        from vlamguard.integrations.pull_requests import _apply_fixes

        manifest = tmp_path / "values.yaml"
        manifest.write_text("key: value\n")

        checks = [PolicyCheckResult(
            check_id="unknown_check_xyz", name="Unknown",
            passed=False, severity="medium", message="Unknown",
            category="reliability",
        )]
        response = _make_response(checks=checks)
        fixes, unfixed, _ = _apply_fixes(response, manifest)

        assert fixes == []
        assert unfixed == ["unknown_check_xyz"]

    def test_non_dict_yaml_returns_all_unfixed(self, tmp_path):
        from vlamguard.integrations.pull_requests import _apply_fixes

        manifest = tmp_path / "values.yaml"
        manifest.write_text("- item1\n- item2\n")

        checks = [PolicyCheckResult(
            check_id="security_context", name="SC",
            passed=False, severity="critical", message="Missing",
            category="security",
        )]
        response = _make_response(checks=checks)
        fixes, unfixed, _ = _apply_fixes(response, manifest)

        assert fixes == []
        assert "security_context" in unfixed

    def test_security_context_nested_fix(self, tmp_path):
        from vlamguard.integrations.pull_requests import _apply_fixes

        manifest = tmp_path / "values.yaml"
        manifest.write_text("image:\n  repository: nginx\n")

        checks = [PolicyCheckResult(
            check_id="security_context", name="SC",
            passed=False, severity="critical", message="Missing",
            category="security",
        )]
        response = _make_response(checks=checks)
        fixes, unfixed, _ = _apply_fixes(response, manifest)

        assert len(fixes) == 1
        import yaml
        data = yaml.safe_load(manifest.read_text())
        assert data["securityContext"]["runAsNonRoot"] is True


class TestCreatePullRequest:
    def test_missing_ai_context_raises(self):
        response = AnalyzeResponse(
            risk_score=50, risk_level=RiskLevel.MEDIUM, blocked=False,
            hard_blocks=[], policy_checks=[], ai_context=None,
            metadata={"environment": "dev", "manifest_count": 1},
        )
        with pytest.raises(PRCreationError, match="AI analysis required"):
            create_pull_request(response, _make_platform(), "/tmp/test.yaml")

    @patch("vlamguard.integrations.pull_requests.run_cmd")
    def test_dirty_tree_raises(self, mock_run):
        mock_run.return_value = "M dirty.yaml"  # git status --porcelain
        with pytest.raises(PRCreationError, match="uncommitted changes"):
            create_pull_request(_make_response(), _make_platform(), "/tmp/test.yaml")
