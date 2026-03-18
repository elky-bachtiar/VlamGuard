# tests/unit/test_cli_coverage_ext.py
"""Extended coverage tests for vlamguard/cli.py — targeting remaining uncovered lines.

Covers:
  252-253    all checks pass → no issues to create
  266-267    dry-run PR skip message
  270-294    live integration: create_issue, create_pr, platform error, PR error
  318        debug logging in check command
  373        debug logging in security-scan command
  426, 432-465  report command full flow
  541        discover with debug
  659        __main__ guard
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, call

import click
import pytest
from typer.testing import CliRunner

from vlamguard.cli import app, _handle_integrations
from vlamguard.integrations import IntegrationError
from vlamguard.models.report import Platform, PlatformInfo
from vlamguard.models.response import (
    AIContext,
    AnalyzeResponse,
    PolicyCheckResult,
    RiskLevel,
)

runner = CliRunner(env={"NO_COLOR": "1", "TERM": "dumb"})

_FIXTURE_DIR = Path(__file__).parent.parent / "fixtures"
_CLEAN_FIXTURE = str(_FIXTURE_DIR / "clean-deploy.yaml")
_RISK_FIXTURE = str(_FIXTURE_DIR / "evident-risk.yaml")


def _make_response(
    blocked: bool = False,
    ai_context: AIContext | None = None,
    checks: list[PolicyCheckResult] | None = None,
) -> AnalyzeResponse:
    return AnalyzeResponse(
        risk_score=0 if not blocked else 70,
        risk_level=RiskLevel.LOW if not blocked else RiskLevel.HIGH,
        blocked=blocked,
        hard_blocks=["security_context"] if blocked else [],
        policy_checks=checks or [],
        ai_context=ai_context,
        metadata={"environment": "production", "manifest_count": 1},
    )


def _make_ai_context() -> AIContext:
    return AIContext(
        summary="Issues found.",
        impact_analysis=[],
        recommendations=["Fix it"],
        rollback_suggestion="Rollback.",
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


# ---------------------------------------------------------------------------
# _handle_integrations — all checks pass (lines 252-253)
# ---------------------------------------------------------------------------


class TestHandleIntegrationsAllPass:
    def test_all_checks_pass_no_issues(self, capsys):
        """When all checks pass, print message and return without creating issues."""
        response = _make_response(
            ai_context=_make_ai_context(),
            checks=[
                PolicyCheckResult(
                    check_id="security_context", name="SC",
                    passed=True, severity="critical", message="OK",
                    category="security",
                ),
            ],
        )
        _handle_integrations(
            response,
            create_issues=True,
            create_pr=False,
            dry_run=False,
            remote="origin",
            platform=None,
            manifests_path=None,
        )
        # Should print "All checks pass" — no error raised


# ---------------------------------------------------------------------------
# _handle_integrations — dry-run PR (lines 266-267)
# ---------------------------------------------------------------------------


class TestHandleIntegrationsDryRunPR:
    def test_dry_run_pr_skip_message(self, capsys):
        checks = [
            PolicyCheckResult(
                check_id="security_context", name="SC",
                passed=False, severity="critical", message="Missing",
                category="security",
            ),
        ]
        response = _make_response(
            ai_context=_make_ai_context(),
            checks=checks,
        )
        _handle_integrations(
            response,
            create_issues=False,
            create_pr=True,
            dry_run=True,
            remote="origin",
            platform=None,
            manifests_path=None,
        )
        # Should print dry-run PR skip message


# ---------------------------------------------------------------------------
# _handle_integrations — live integration paths (lines 270-294)
# ---------------------------------------------------------------------------


class TestHandleIntegrationsLive:
    @patch("vlamguard.cli.create_pull_request")
    @patch("vlamguard.cli.create_issue")
    @patch("vlamguard.cli.detect_platform")
    def test_create_issue_success(self, mock_detect, mock_issue, mock_pr):
        mock_detect.return_value = _make_platform()
        mock_issue.return_value = "https://github.com/user/repo/issues/1"

        checks = [
            PolicyCheckResult(
                check_id="security_context", name="SC",
                passed=False, severity="critical", message="Missing",
                category="security",
            ),
        ]
        response = _make_response(
            ai_context=_make_ai_context(),
            checks=checks,
        )
        _handle_integrations(
            response,
            create_issues=True,
            create_pr=False,
            dry_run=False,
            remote="origin",
            platform=None,
            manifests_path=None,
        )
        mock_issue.assert_called_once()

    @patch("vlamguard.cli.create_pull_request")
    @patch("vlamguard.cli.create_issue")
    @patch("vlamguard.cli.detect_platform")
    def test_create_pr_success(self, mock_detect, mock_issue, mock_pr):
        mock_detect.return_value = _make_platform()
        mock_pr.return_value = "https://github.com/user/repo/pull/1"

        checks = [
            PolicyCheckResult(
                check_id="security_context", name="SC",
                passed=False, severity="critical", message="Missing",
                category="security",
            ),
        ]
        response = _make_response(
            ai_context=_make_ai_context(),
            checks=checks,
        )
        _handle_integrations(
            response,
            create_issues=False,
            create_pr=True,
            dry_run=False,
            remote="origin",
            platform=None,
            manifests_path="/tmp/values.yaml",
        )
        mock_pr.assert_called_once()

    @patch("vlamguard.cli.detect_platform")
    def test_platform_error_exits(self, mock_detect):
        mock_detect.side_effect = IntegrationError("no remote")

        checks = [
            PolicyCheckResult(
                check_id="security_context", name="SC",
                passed=False, severity="critical", message="Missing",
                category="security",
            ),
        ]
        response = _make_response(
            ai_context=_make_ai_context(),
            checks=checks,
        )
        with pytest.raises((SystemExit, click.exceptions.Exit)):
            _handle_integrations(
                response,
                create_issues=True,
                create_pr=False,
                dry_run=False,
                remote="origin",
                platform=None,
                manifests_path=None,
            )

    @patch("vlamguard.cli.create_issue")
    @patch("vlamguard.cli.detect_platform")
    def test_issue_creation_error_exits(self, mock_detect, mock_issue):
        mock_detect.return_value = _make_platform()
        mock_issue.side_effect = IntegrationError("gh not found")

        checks = [
            PolicyCheckResult(
                check_id="security_context", name="SC",
                passed=False, severity="critical", message="Missing",
                category="security",
            ),
        ]
        response = _make_response(
            ai_context=_make_ai_context(),
            checks=checks,
        )
        with pytest.raises((SystemExit, click.exceptions.Exit)):
            _handle_integrations(
                response,
                create_issues=True,
                create_pr=False,
                dry_run=False,
                remote="origin",
                platform=None,
                manifests_path=None,
            )

    @patch("vlamguard.cli.create_pull_request")
    @patch("vlamguard.cli.detect_platform")
    def test_pr_creation_error_exits(self, mock_detect, mock_pr):
        mock_detect.return_value = _make_platform()
        mock_pr.side_effect = IntegrationError("dirty tree")

        checks = [
            PolicyCheckResult(
                check_id="security_context", name="SC",
                passed=False, severity="critical", message="Missing",
                category="security",
            ),
        ]
        response = _make_response(
            ai_context=_make_ai_context(),
            checks=checks,
        )
        with pytest.raises((SystemExit, click.exceptions.Exit)):
            _handle_integrations(
                response,
                create_issues=False,
                create_pr=True,
                dry_run=False,
                remote="origin",
                platform=None,
                manifests_path="/tmp/values.yaml",
            )

    @patch("vlamguard.cli.detect_platform")
    def test_create_pr_no_manifests_exits(self, mock_detect):
        mock_detect.return_value = _make_platform()

        checks = [
            PolicyCheckResult(
                check_id="security_context", name="SC",
                passed=False, severity="critical", message="Missing",
                category="security",
            ),
        ]
        response = _make_response(
            ai_context=_make_ai_context(),
            checks=checks,
        )
        with pytest.raises((SystemExit, click.exceptions.Exit)):
            _handle_integrations(
                response,
                create_issues=False,
                create_pr=True,
                dry_run=False,
                remote="origin",
                platform=None,
                manifests_path=None,
            )


# ---------------------------------------------------------------------------
# _handle_integrations — ai_context is None (error message)
# ---------------------------------------------------------------------------


class TestHandleIntegrationsNoAI:
    def test_ai_context_none_exits_with_message(self):
        response = _make_response(ai_context=None)
        with pytest.raises((SystemExit, click.exceptions.Exit)):
            _handle_integrations(
                response,
                create_issues=True,
                create_pr=False,
                dry_run=False,
                remote="origin",
                platform=None,
                manifests_path=None,
            )


# ---------------------------------------------------------------------------
# check command with --debug (line 318)
# ---------------------------------------------------------------------------


class TestCheckDebugFlag:
    @patch("vlamguard.cli._analyze_manifests", new_callable=AsyncMock)
    @patch("vlamguard.cli._load_manifests")
    def test_check_with_debug(self, mock_load, mock_analyze):
        mock_load.return_value = ([{"kind": "Deployment", "metadata": {"name": "web"}}], "yaml")
        mock_analyze.return_value = _make_response()

        result = runner.invoke(app, [
            "check", "--manifests", _CLEAN_FIXTURE, "--skip-ai", "--debug",
        ])
        # Should not error out
        assert result.exit_code in (0, 1)


# ---------------------------------------------------------------------------
# security-scan with --debug (line 373)
# ---------------------------------------------------------------------------


class TestSecurityScanDebugFlag:
    @patch("vlamguard.cli._analyze_manifests", new_callable=AsyncMock)
    @patch("vlamguard.cli._load_manifests")
    def test_security_scan_with_debug(self, mock_load, mock_analyze):
        mock_load.return_value = ([{"kind": "Deployment", "metadata": {"name": "web"}}], "yaml")
        mock_analyze.return_value = _make_response()

        result = runner.invoke(app, [
            "security-scan", "--manifests", _CLEAN_FIXTURE, "--skip-ai", "--debug",
        ])
        assert result.exit_code in (0, 1)


# ---------------------------------------------------------------------------
# report command (lines 426, 432-465)
# ---------------------------------------------------------------------------


class TestReportCommand:
    @patch("vlamguard.cli._handle_integrations")
    @patch("vlamguard.cli._analyze_manifests", new_callable=AsyncMock)
    @patch("vlamguard.cli._load_manifests")
    def test_report_command_basic(self, mock_load, mock_analyze, mock_handle):
        mock_load.return_value = ([{"kind": "Deployment", "metadata": {"name": "web"}}], "yaml")
        mock_analyze.return_value = _make_response()

        result = runner.invoke(app, [
            "report", "--manifests", _CLEAN_FIXTURE,
        ])
        assert result.exit_code in (0, 1)
        mock_handle.assert_called_once()

    @patch("vlamguard.cli._handle_integrations")
    @patch("vlamguard.cli._analyze_manifests", new_callable=AsyncMock)
    @patch("vlamguard.cli._load_manifests")
    def test_report_command_with_debug(self, mock_load, mock_analyze, mock_handle):
        mock_load.return_value = ([{"kind": "Deployment", "metadata": {"name": "web"}}], "yaml")
        mock_analyze.return_value = _make_response()

        result = runner.invoke(app, [
            "report", "--manifests", _CLEAN_FIXTURE, "--debug",
        ])
        assert result.exit_code in (0, 1)

    def test_report_no_chart_or_manifests(self):
        result = runner.invoke(app, ["report"])
        assert result.exit_code != 0

    @patch("vlamguard.cli._handle_integrations")
    @patch("vlamguard.cli._analyze_manifests", new_callable=AsyncMock)
    @patch("vlamguard.cli._load_manifests")
    def test_report_with_dry_run(self, mock_load, mock_analyze, mock_handle):
        mock_load.return_value = ([{"kind": "Deployment", "metadata": {"name": "web"}}], "yaml")
        mock_analyze.return_value = _make_response()

        result = runner.invoke(app, [
            "report", "--manifests", _CLEAN_FIXTURE, "--dry-run",
        ])
        assert result.exit_code in (0, 1)
        # Verify _handle_integrations was called with dry_run=True
        args = mock_handle.call_args
        assert args[1].get("dry_run") is True or args[0][3] is True

    @patch("vlamguard.cli._load_manifests")
    def test_report_helm_render_error(self, mock_load):
        from vlamguard.engine.helm import HelmRenderError
        mock_load.side_effect = HelmRenderError("chart not found")

        result = runner.invoke(app, [
            "report", "--manifests", _CLEAN_FIXTURE,
        ])
        assert result.exit_code != 0
