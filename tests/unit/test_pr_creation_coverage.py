# tests/unit/test_pr_creation_coverage.py
"""Extended coverage tests for pull_requests.py — targeting uncovered lines.

Covers:
  117        build_pr_body pyyaml_fallback=True
  159-261    create_pull_request full flow (GitHub and GitLab)
  277-278    _apply_fixes PyYAML fallback path
  291-292    _apply_fixes PyYAML write-back path
  310        ai_fixes mapping path
  329-332    _apply_fixes with ruamel write-back
  343-345    _set_nested intermediate dict creation
"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from vlamguard.integrations import PRCreationError
from vlamguard.integrations.pull_requests import (
    _apply_fixes,
    _set_nested,
    build_pr_body,
    create_pull_request,
    REMEDIATION_MAP,
)
from vlamguard.models.report import FixApplied, Platform, PlatformInfo
from vlamguard.models.response import (
    AIContext,
    AnalyzeResponse,
    PolicyCheckResult,
    Recommendation,
    RiskLevel,
)


def _make_github_platform() -> PlatformInfo:
    return PlatformInfo(
        platform=Platform.GITHUB,
        remote_url="git@github.com:user/repo.git",
        remote_name="origin",
        cli_command="gh",
        body_flag="--body",
        term="PR",
    )


def _make_gitlab_platform() -> PlatformInfo:
    return PlatformInfo(
        platform=Platform.GITLAB,
        remote_url="git@gitlab.com:user/repo.git",
        remote_name="origin",
        cli_command="glab",
        body_flag="--description",
        term="MR",
    )


def _make_response(
    checks: list[PolicyCheckResult] | None = None,
    recs: list | None = None,
    ai_context: AIContext | None = None,
) -> AnalyzeResponse:
    ctx = ai_context or AIContext(
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


# ---------------------------------------------------------------------------
# build_pr_body with pyyaml_fallback=True
# ---------------------------------------------------------------------------


class TestBuildPRBodyPyYAMLFallback:
    def test_pyyaml_fallback_note_in_body(self):
        before = _make_response()
        after = _make_response()
        fixes = [FixApplied(check_id="sc", file_path="v.yaml", description="fix")]
        body = build_pr_body(before, after, fixes, unfixed=[], pyyaml_fallback=True)
        assert "ruamel.yaml" in body
        assert "PyYAML" in body
        assert "Comments" in body

    def test_pyyaml_fallback_false_no_note(self):
        before = _make_response()
        after = _make_response()
        body = build_pr_body(before, after, [], unfixed=[], pyyaml_fallback=False)
        assert "ruamel.yaml" not in body


# ---------------------------------------------------------------------------
# create_pull_request — full GitHub flow
# ---------------------------------------------------------------------------


class TestCreatePullRequestGitHub:
    @patch("vlamguard.integrations.pull_requests.run_cmd")
    @patch("vlamguard.integrations.pull_requests._apply_fixes")
    def test_full_github_flow(self, mock_apply, mock_run, tmp_path):
        manifest = tmp_path / "values.yaml"
        manifest.write_text("replicaCount: 1\n")

        fix = FixApplied(check_id="security_context", file_path=str(manifest), description="fix")
        mock_apply.return_value = ([fix], [], False)

        # run_cmd returns: clean tree, branch name, then various git + gh commands
        mock_run.side_effect = [
            "",           # git status --porcelain (clean)
            "main",       # git rev-parse --abbrev-ref HEAD
            "",           # git checkout -b fix/vlamguard-...
            "",           # git add
            "",           # git commit
            "",           # git push
            "https://github.com/user/repo/pull/1",  # gh pr create
        ]

        checks = [PolicyCheckResult(
            check_id="security_context", name="SC",
            passed=False, severity="critical", message="Missing",
            category="security",
        )]
        response = _make_response(checks=checks)
        platform = _make_github_platform()

        url = create_pull_request(response, platform, str(manifest))
        assert "https://github.com/user/repo/pull/1" in url

    @patch("vlamguard.integrations.pull_requests.run_cmd")
    @patch("vlamguard.integrations.pull_requests._apply_fixes")
    def test_no_fixes_cleans_up(self, mock_apply, mock_run, tmp_path):
        manifest = tmp_path / "values.yaml"
        manifest.write_text("key: value\n")

        mock_apply.return_value = ([], ["unknown_check"], False)
        mock_run.side_effect = [
            "",           # git status --porcelain
            "main",       # git rev-parse
            "",           # git checkout -b
            "",           # git checkout original
            "",           # git branch -D
        ]

        response = _make_response()
        with pytest.raises(PRCreationError, match="No fixable checks"):
            create_pull_request(response, _make_github_platform(), str(manifest))

    @patch("vlamguard.integrations.pull_requests.run_cmd")
    @patch("vlamguard.integrations.pull_requests._apply_fixes")
    def test_manifest_not_found_raises(self, mock_apply, mock_run):
        mock_run.side_effect = [
            "",      # git status --porcelain
        ]
        response = _make_response()
        with pytest.raises(PRCreationError, match="not found"):
            create_pull_request(response, _make_github_platform(), "/nonexistent/values.yaml")

    @patch("vlamguard.integrations.pull_requests.run_cmd")
    @patch("vlamguard.integrations.pull_requests._apply_fixes")
    def test_subprocess_error_cleanup(self, mock_apply, mock_run, tmp_path):
        manifest = tmp_path / "values.yaml"
        manifest.write_text("key: value\n")

        fix = FixApplied(check_id="sc", file_path=str(manifest), description="fix")
        mock_apply.return_value = ([fix], [], False)

        mock_run.side_effect = [
            "",           # git status --porcelain
            "main",       # git rev-parse
            "",           # git checkout -b
            "",           # git add
            "",           # git commit
            subprocess.CalledProcessError(1, "git push", stderr="auth failed"),  # git push fails
            "",           # cleanup: git checkout -- file
            "",           # cleanup: git checkout original
            "",           # cleanup: git branch -D
        ]

        response = _make_response()
        with pytest.raises(PRCreationError, match="Failed to create PR"):
            create_pull_request(response, _make_github_platform(), str(manifest))

    @patch("vlamguard.integrations.pull_requests.run_cmd")
    @patch("vlamguard.integrations.pull_requests._apply_fixes")
    def test_generic_error_cleanup(self, mock_apply, mock_run, tmp_path):
        manifest = tmp_path / "values.yaml"
        manifest.write_text("key: value\n")

        fix = FixApplied(check_id="sc", file_path=str(manifest), description="fix")
        mock_apply.return_value = ([fix], [], False)

        mock_run.side_effect = [
            "",           # git status --porcelain
            "main",       # git rev-parse
            "",           # git checkout -b
            "",           # git add
            "",           # git commit
            RuntimeError("unexpected"),  # git push raises generic error
            "",           # cleanup: git checkout -- file
            "",           # cleanup: git checkout original
            "",           # cleanup: git branch -D
        ]

        response = _make_response()
        with pytest.raises(PRCreationError, match="Failed to create PR"):
            create_pull_request(response, _make_github_platform(), str(manifest))

    @patch("vlamguard.integrations.pull_requests.run_cmd")
    @patch("vlamguard.integrations.pull_requests._apply_fixes")
    def test_cleanup_failure_logged(self, mock_apply, mock_run, tmp_path):
        """When cleanup itself fails, we still raise PRCreationError."""
        manifest = tmp_path / "values.yaml"
        manifest.write_text("key: value\n")

        fix = FixApplied(check_id="sc", file_path=str(manifest), description="fix")
        mock_apply.return_value = ([fix], [], False)

        mock_run.side_effect = [
            "",           # git status --porcelain
            "main",       # git rev-parse
            "",           # git checkout -b
            "",           # git add
            "",           # git commit
            RuntimeError("push failed"),  # git push
            Exception("cleanup fail"),    # cleanup also fails
        ]

        response = _make_response()
        with pytest.raises(PRCreationError, match="Failed to create PR"):
            create_pull_request(response, _make_github_platform(), str(manifest))


# ---------------------------------------------------------------------------
# create_pull_request — GitLab flow
# ---------------------------------------------------------------------------


class TestCreatePullRequestGitLab:
    @patch("vlamguard.integrations.pull_requests.run_cmd")
    @patch("vlamguard.integrations.pull_requests._apply_fixes")
    def test_full_gitlab_flow(self, mock_apply, mock_run, tmp_path):
        manifest = tmp_path / "values.yaml"
        manifest.write_text("replicaCount: 1\n")

        fix = FixApplied(check_id="security_context", file_path=str(manifest), description="fix")
        mock_apply.return_value = ([fix], [], False)

        mock_run.side_effect = [
            "",           # git status --porcelain
            "main",       # git rev-parse
            "",           # git checkout -b
            "",           # git add
            "",           # git commit
            "",           # git push
            "https://gitlab.com/user/repo/-/merge_requests/1",  # glab mr create
        ]

        checks = [PolicyCheckResult(
            check_id="security_context", name="SC",
            passed=False, severity="critical", message="Missing",
            category="security",
        )]
        response = _make_response(checks=checks)
        platform = _make_gitlab_platform()

        url = create_pull_request(response, platform, str(manifest))
        assert "gitlab.com" in url

        # Verify GitLab uses --description and --target-branch
        last_call = mock_run.call_args_list[-1]
        cmd = last_call[0][0]
        assert "glab" in cmd
        assert "--target-branch" in cmd

    @patch("vlamguard.integrations.pull_requests.run_cmd")
    @patch("vlamguard.integrations.pull_requests._apply_fixes")
    def test_subprocess_error_cleanup_gitlab(self, mock_apply, mock_run, tmp_path):
        """CalledProcessError with stderr on GitLab path."""
        manifest = tmp_path / "values.yaml"
        manifest.write_text("key: value\n")

        fix = FixApplied(check_id="sc", file_path=str(manifest), description="fix")
        mock_apply.return_value = ([fix], [], False)

        err = subprocess.CalledProcessError(1, "git push", stderr="auth failed")
        mock_run.side_effect = [
            "",           # git status --porcelain
            "main",       # git rev-parse
            "",           # git checkout -b
            "",           # git add
            "",           # git commit
            err,          # git push fails
            "",           # cleanup: git checkout -- file
            "",           # cleanup: git checkout original
            "",           # cleanup: git branch -D
        ]

        response = _make_response()
        with pytest.raises(PRCreationError, match="stderr: auth failed"):
            create_pull_request(response, _make_gitlab_platform(), str(manifest))


# ---------------------------------------------------------------------------
# _apply_fixes — PyYAML fallback
# ---------------------------------------------------------------------------


class TestApplyFixesPyYAMLFallback:
    def test_pyyaml_fallback_when_ruamel_missing(self, tmp_path):
        """When ruamel.yaml import fails, _apply_fixes falls back to PyYAML."""
        manifest = tmp_path / "values.yaml"
        manifest.write_text("replicaCount: 1\n")

        checks = [PolicyCheckResult(
            check_id="replica_count", name="Replica Count",
            passed=False, severity="medium", message="Low replicas",
            category="reliability",
        )]
        response = _make_response(checks=checks)

        # Patch the import inside _apply_fixes to fail on ruamel.yaml
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if "ruamel" in name:
                raise ImportError(f"No module named '{name}'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            fixes, unfixed, pyyaml_fallback = _apply_fixes(response, manifest)

        assert pyyaml_fallback is True
        assert len(fixes) == 1
        # Verify content was written
        import yaml
        data = yaml.safe_load(manifest.read_text())
        assert data["replicaCount"] == 2


# ---------------------------------------------------------------------------
# _set_nested
# ---------------------------------------------------------------------------


class TestSetNested:
    def test_creates_intermediate_dicts(self):
        data = {}
        _set_nested(data, ["a", "b", "c"], 42)
        assert data == {"a": {"b": {"c": 42}}}

    def test_overwrites_non_dict_intermediate(self):
        data = {"a": "string_value"}
        _set_nested(data, ["a", "b"], 1)
        assert data == {"a": {"b": 1}}

    def test_preserves_existing_siblings(self):
        data = {"a": {"x": 1}}
        _set_nested(data, ["a", "b"], 2)
        assert data == {"a": {"x": 1, "b": 2}}
